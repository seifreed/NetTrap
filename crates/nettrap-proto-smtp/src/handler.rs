use async_trait::async_trait;
use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::prelude::*;

pub struct SmtpHandler {
    domain: String,
    /// CRAM challenge token for the current session
    cram_challenge: String,
}

impl SmtpHandler {
    pub fn new() -> Self {
        let challenge = Self::generate_cram_challenge();
        Self {
            domain: "nettrap.local".to_string(),
            cram_challenge: challenge,
        }
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn get_welcome_banner(&self) -> String {
        format!("{} ESMTP NetTrap Ready\r\n", self.domain)
    }

    fn generate_cram_challenge() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        let random_part: u64 = rng.random();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("<{}.{}@nettrap.local>", random_part, timestamp)
    }

    /// Decode AUTH PLAIN credentials from base64
    fn decode_auth_plain(data: &str) -> Option<(String, String)> {
        let decoded = BASE64.decode(data.trim()).ok()?;
        // PLAIN format: \0authzid\0authcid\0passwd  or  authzid\0authcid\0passwd
        let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
        if parts.len() >= 3 {
            let user = String::from_utf8_lossy(parts[1]).to_string();
            let pass = String::from_utf8_lossy(parts[2]).to_string();
            Some((user, pass))
        } else if parts.len() == 2 {
            let user = String::from_utf8_lossy(parts[0]).to_string();
            let pass = String::from_utf8_lossy(parts[1]).to_string();
            Some((user, pass))
        } else {
            None
        }
    }

    /// Decode AUTH LOGIN credentials (base64 encoded username or password)
    fn decode_auth_login(data: &str) -> Option<String> {
        let decoded = BASE64.decode(data.trim()).ok()?;
        Some(String::from_utf8_lossy(&decoded).to_string())
    }

    /// Handle CRAM-MD5/CRAM-SHA1 response: base64(<user> <digest>)
    fn decode_cram_response(data: &str) -> Option<(String, String)> {
        let decoded = BASE64.decode(data.trim()).ok()?;
        let text = String::from_utf8_lossy(&decoded);
        let mut parts = text.splitn(2, ' ');
        let user = parts.next()?.to_string();
        let digest = parts.next().unwrap_or("").to_string();
        Some((user, digest))
    }
}

impl Default for SmtpHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait SmtpHandlerTrait: Send + Sync {
    async fn handle(&self, command: &str) -> Result<SmtpResponse>;
    fn name(&self) -> &'static str;
}

#[async_trait]
impl SmtpHandlerTrait for SmtpHandler {
    async fn handle(&self, command: &str) -> Result<SmtpResponse> {
        let upper = command.to_uppercase();
        let trimmed = command.trim();

        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            // Advertise AUTH mechanisms in EHLO response
            if upper.starts_with("EHLO") {
                Ok(SmtpResponse::message(format!(
                    "250-{} Hello\r\n250-AUTH PLAIN LOGIN CRAM-MD5 CRAM-SHA1\r\n250-SIZE 10485760\r\n250-8BITMIME\r\n250 OK",
                    self.domain
                )))
            } else {
                Ok(SmtpResponse::ok())
            }
        } else if upper.starts_with("MAIL FROM")
            || upper.starts_with("RCPT TO")
            || upper.starts_with("RSET")
            || upper.starts_with("NOOP")
            || upper.starts_with("VRFY")
        {
            Ok(SmtpResponse::ok())
        } else if upper.starts_with("DATA") {
            Ok(SmtpResponse::start_data())
        } else if upper.starts_with("QUIT") {
            Ok(SmtpResponse::bye())
        } else if upper.starts_with("HELP") {
            Ok(SmtpResponse::message("250-This is NetTrap SMTP honeypot\r\n250-Commands: EHLO HELO MAIL RCPT DATA RSET NOOP QUIT AUTH"))
        } else if upper.starts_with("STARTTLS") {
            Ok(SmtpResponse::message("220 Ready to start TLS"))
        } else if upper.starts_with("AUTH") {
            // ── AUTH credential capture ──────────────────────────────────
            let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
            let mechanism = parts.get(1).map(|s| s.to_uppercase()).unwrap_or_default();

            match mechanism.as_str() {
                "PLAIN" => {
                    // AUTH PLAIN <base64> (inline) or AUTH PLAIN (then client sends base64)
                    if let Some(data) = parts.get(2) {
                        if let Some((user, pass)) = Self::decode_auth_plain(data) {
                            tracing::info!("SMTP AUTH PLAIN captured — user: {} pass: {}", user, pass);
                        } else {
                            tracing::info!("SMTP AUTH PLAIN captured (decode failed): {}", data);
                        }
                        Ok(SmtpResponse::new(235, "2.7.0 Authentication successful"))
                    } else {
                        // Send continuation, client will send base64 on next line
                        // We return 334 to prompt; the next input will be handled as a
                        // continuation. For simplicity in stateless handler, accept immediately.
                        Ok(SmtpResponse::new(334, ""))
                    }
                }
                "LOGIN" => {
                    // AUTH LOGIN — send 334 VXNlcm5hbWU6 (Username:)
                    // Stateless handler: prompt for username
                    Ok(SmtpResponse::new(334, "VXNlcm5hbWU6"))
                }
                "CRAM-MD5" => {
                    // Send challenge as base64
                    let challenge_b64 = BASE64.encode(self.cram_challenge.as_bytes());
                    tracing::debug!("SMTP CRAM-MD5 challenge: {}", self.cram_challenge);
                    Ok(SmtpResponse::new(334, challenge_b64))
                }
                "CRAM-SHA1" => {
                    let challenge_b64 = BASE64.encode(self.cram_challenge.as_bytes());
                    tracing::debug!("SMTP CRAM-SHA1 challenge: {}", self.cram_challenge);
                    Ok(SmtpResponse::new(334, challenge_b64))
                }
                _ => {
                    // Unknown AUTH mechanism — could be a continuation response
                    // (base64 blob from LOGIN/CRAM). Try to decode and accept.
                    if let Some(data) = parts.get(1) {
                        // Could be AUTH LOGIN continuation or CRAM response
                        if let Some((user, digest)) = Self::decode_cram_response(data) {
                            tracing::info!("SMTP AUTH response captured — user: {} digest: {}", user, digest);
                        } else if let Some(decoded) = Self::decode_auth_login(data) {
                            tracing::info!("SMTP AUTH continuation captured: {}", decoded);
                        } else {
                            tracing::info!("SMTP AUTH data captured: {}", data);
                        }
                    }
                    Ok(SmtpResponse::new(235, "2.7.0 Authentication successful"))
                }
            }
        } else if upper.starts_with("X-EXPS") || upper.starts_with("X-EXCH50") || upper.starts_with("X-LINK2STATE") {
            Ok(SmtpResponse::ok())
        } else {
            // Check if this is a continuation line (base64 for AUTH LOGIN / CRAM)
            // These arrive as bare base64 strings after a 334 challenge.
            // Require: no spaces, valid base64 chars, and successful base64 decode.
            if trimmed.len() >= 8
                && !trimmed.contains(' ')
                && trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
                && BASE64.decode(trimmed.as_bytes()).is_ok()
            {
                // Likely a base64 AUTH continuation
                if let Some((user, digest)) = Self::decode_cram_response(trimmed) {
                    tracing::info!("SMTP AUTH continuation — user: {} digest: {}", user, digest);
                } else if let Some(decoded) = Self::decode_auth_login(trimmed) {
                    tracing::info!("SMTP AUTH continuation — decoded: {}", decoded);
                } else {
                    tracing::info!("SMTP AUTH continuation — raw: {}", trimmed);
                }
                // After capturing, always accept
                Ok(SmtpResponse::new(235, "2.7.0 Authentication successful"))
            } else {
                Ok(SmtpResponse::error("500 Command not recognized"))
            }
        }
    }

    fn name(&self) -> &'static str {
        "smtp"
    }
}