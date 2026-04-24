use async_trait::async_trait;
use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::prelude::*;

/// Tracks multi-line AUTH state between handler calls.
/// This is per-connection state, NOT global state.
#[derive(Debug, Clone, Default)]
pub enum SmtpAuthState {
    #[default]
    None,
    /// Waiting for base64-encoded username (AUTH LOGIN step 1)
    LoginUsername,
    /// Waiting for base64-encoded password (AUTH LOGIN step 2)
    LoginPassword(String),
    /// Waiting for CRAM-MD5/CRAM-SHA1 response
    CramResponse(String),
    /// Waiting for PLAIN continuation (AUTH PLAIN without inline data)
    PlainContinuation,
}

/// SMTP handler (stateless - AUTH state is passed per-call).
pub struct SmtpHandler {
    domain: String,
    /// Whether to log credentials in plaintext (default: true for honeypot use)
    log_credentials: bool,
}

impl SmtpHandler {
    pub fn new() -> Self {
        Self {
            domain: "nettrap.local".to_string(),
            log_credentials: true,
        }
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    /// Set whether to log credentials in plaintext.
    /// When false, passwords are shown as "***REDACTED***".
    pub fn with_log_credentials(mut self, log: bool) -> Self {
        self.log_credentials = log;
        self
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn get_welcome_banner(&self) -> String {
        format!("220 {} ESMTP NetTrap Ready\r\n", self.domain)
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

    /// Handle a command with optional AUTH state.
    /// Returns (response, new_auth_state).
    /// The caller is responsible for maintaining auth_state across calls.
    pub fn handle_with_state(
        &self,
        command: &str,
        auth_state: SmtpAuthState,
    ) -> (SmtpResponse, SmtpAuthState) {
        let upper = command.to_uppercase();
        let trimmed = command.trim();

        // ── Check if client is aborting AUTH with RSET or QUIT ─────────────────
        // RFC 4954: "*" cancels AUTH, RSET/QUIT also reset state
        if trimmed == "*" || upper.starts_with("RSET") || upper.starts_with("QUIT") {
            if trimmed == "*" {
                return (
                    SmtpResponse::new(501, "5.5.2 Authentication exchange cancelled"),
                    SmtpAuthState::None,
                );
            }
            // Let RSET/QUIT fall through to normal handling but reset AUTH state
            let (result, _) = self.handle_command(command);
            return (result, SmtpAuthState::None);
        }

        // ── Check for pending AUTH state ──────────────────────────────────
        // Only treat input as credential data if it's NOT a known SMTP command
        let is_smtp_command = upper.starts_with("EHLO")
            || upper.starts_with("HELO")
            || upper.starts_with("MAIL")
            || upper.starts_with("RCPT")
            || upper.starts_with("DATA")
            || upper.starts_with("RSET")
            || upper.starts_with("NOOP")
            || upper.starts_with("VRFY")
            || upper.starts_with("QUIT")
            || upper.starts_with("HELP")
            || upper.starts_with("AUTH")
            || upper.starts_with("STARTTLS")
            || upper.starts_with("X-EXPS")
            || upper.starts_with("X-EXCH50")
            || upper.starts_with("X-LINK2STATE");

        match auth_state {
            SmtpAuthState::PlainContinuation => {
                if is_smtp_command {
                    tracing::info!("SMTP AUTH PLAIN aborted by command: {}", trimmed);
                    return (
                        SmtpResponse::new(501, "5.5.2 Authentication exchange cancelled"),
                        SmtpAuthState::None,
                    );
                }
                // Client sending base64 PLAIN data after 334
                if let Some((user, pass)) = Self::decode_auth_plain(trimmed) {
                    if self.log_credentials {
                        tracing::info!("SMTP AUTH PLAIN captured — user: {} pass: {}", user, pass);
                    } else {
                        tracing::info!(
                            "SMTP AUTH PLAIN captured — user: {} pass: ***REDACTED***",
                            user
                        );
                    }
                } else {
                    tracing::info!("SMTP AUTH PLAIN captured (decode failed): {}", trimmed);
                }
                (
                    SmtpResponse::new(235, "2.7.0 Authentication successful"),
                    SmtpAuthState::None,
                )
            }
            SmtpAuthState::LoginUsername => {
                if is_smtp_command {
                    tracing::info!("SMTP AUTH LOGIN aborted by command: {}", trimmed);
                    return (
                        SmtpResponse::new(501, "5.5.2 Authentication exchange cancelled"),
                        SmtpAuthState::None,
                    );
                }
                // Client sending base64-encoded username
                let username =
                    Self::decode_auth_login(trimmed).unwrap_or_else(|| trimmed.to_string());
                tracing::info!("SMTP AUTH LOGIN username: {}", username);
                (
                    SmtpResponse::new(334, "UGFzc3dvcmQ6"),
                    SmtpAuthState::LoginPassword(username),
                )
            }
            SmtpAuthState::LoginPassword(username) => {
                if is_smtp_command {
                    tracing::info!("SMTP AUTH LOGIN aborted by command: {}", trimmed);
                    return (
                        SmtpResponse::new(501, "5.5.2 Authentication exchange cancelled"),
                        SmtpAuthState::None,
                    );
                }
                // Client sending base64-encoded password
                let password =
                    Self::decode_auth_login(trimmed).unwrap_or_else(|| trimmed.to_string());
                if self.log_credentials {
                    tracing::info!(
                        "SMTP AUTH LOGIN captured — user: {} pass: {}",
                        username,
                        password
                    );
                } else {
                    tracing::info!(
                        "SMTP AUTH LOGIN captured — user: {} pass: ***REDACTED***",
                        username
                    );
                }
                (
                    SmtpResponse::new(235, "2.7.0 Authentication successful"),
                    SmtpAuthState::None,
                )
            }
            SmtpAuthState::CramResponse(mechanism) => {
                if is_smtp_command {
                    tracing::info!("SMTP AUTH {} aborted by command: {}", mechanism, trimmed);
                    return (
                        SmtpResponse::new(501, "5.5.2 Authentication exchange cancelled"),
                        SmtpAuthState::None,
                    );
                }
                // Client sending CRAM-MD5/SHA1 response
                if let Some((user, digest)) = Self::decode_cram_response(trimmed) {
                    tracing::info!(
                        "SMTP AUTH {} captured — user: {} digest: {}",
                        mechanism,
                        user,
                        digest
                    );
                } else {
                    tracing::info!(
                        "SMTP AUTH {} response captured (raw): {}",
                        mechanism,
                        trimmed
                    );
                }
                (
                    SmtpResponse::new(235, "2.7.0 Authentication successful"),
                    SmtpAuthState::None,
                )
            }
            SmtpAuthState::None => {
                // No pending state, handle as normal command
                self.handle_command(command)
            }
        }
    }

    fn handle_command(&self, command: &str) -> (SmtpResponse, SmtpAuthState) {
        let upper = command.to_uppercase();
        let trimmed = command.trim();

        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            let resp = if upper.starts_with("EHLO") {
                SmtpResponse::raw(format!(
                    "250-{} Hello\r\n250-AUTH PLAIN LOGIN CRAM-MD5 CRAM-SHA1\r\n250-SIZE 10485760\r\n250-8BITMIME\r\n250 OK",
                    self.domain
                ))
            } else {
                SmtpResponse::ok()
            };
            (resp, SmtpAuthState::None)
        } else if upper.starts_with("MAIL FROM")
            || upper.starts_with("RCPT TO")
            || upper.starts_with("RSET")
            || upper.starts_with("NOOP")
            || upper.starts_with("VRFY")
        {
            (SmtpResponse::ok(), SmtpAuthState::None)
        } else if upper.starts_with("DATA") {
            (SmtpResponse::start_data(), SmtpAuthState::None)
        } else if upper.starts_with("QUIT") {
            (SmtpResponse::bye(), SmtpAuthState::None)
        } else if upper.starts_with("HELP") {
            (
                SmtpResponse::raw(
                    "250-This is NetTrap SMTP honeypot\r\n250 Commands: EHLO HELO MAIL RCPT DATA RSET NOOP QUIT AUTH",
                ),
                SmtpAuthState::None,
            )
        } else if upper.starts_with("STARTTLS") {
            (
                SmtpResponse::new(220, "Ready to start TLS"),
                SmtpAuthState::None,
            )
        } else if upper.starts_with("AUTH") {
            // ── AUTH credential capture ──────────────────────────────────
            let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
            let mechanism = parts.get(1).map(|s| s.to_uppercase()).unwrap_or_default();

            match mechanism.as_str() {
                "PLAIN" => {
                    if let Some(data) = parts.get(2) {
                        if let Some((user, pass)) = Self::decode_auth_plain(data) {
                            if self.log_credentials {
                                tracing::info!(
                                    "SMTP AUTH PLAIN captured — user: {} pass: {}",
                                    user,
                                    pass
                                );
                            } else {
                                tracing::info!(
                                    "SMTP AUTH PLAIN captured — user: {} pass: ***REDACTED***",
                                    user
                                );
                            }
                        } else {
                            tracing::info!("SMTP AUTH PLAIN captured (decode failed): {}", data);
                        }
                        (
                            SmtpResponse::new(235, "2.7.0 Authentication successful"),
                            SmtpAuthState::None,
                        )
                    } else {
                        (SmtpResponse::new(334, ""), SmtpAuthState::PlainContinuation)
                    }
                }
                "LOGIN" => (
                    SmtpResponse::new(334, "VXNlcm5hbWU6"),
                    SmtpAuthState::LoginUsername,
                ),
                "CRAM-MD5" => {
                    let fresh_challenge = Self::generate_cram_challenge();
                    let challenge_b64 = BASE64.encode(fresh_challenge.as_bytes());
                    tracing::debug!("SMTP CRAM-MD5 challenge: {}", fresh_challenge);
                    (
                        SmtpResponse::new(334, challenge_b64),
                        SmtpAuthState::CramResponse("CRAM-MD5".to_string()),
                    )
                }
                "CRAM-SHA1" => {
                    let fresh_challenge = Self::generate_cram_challenge();
                    let challenge_b64 = BASE64.encode(fresh_challenge.as_bytes());
                    tracing::debug!("SMTP CRAM-SHA1 challenge: {}", fresh_challenge);
                    (
                        SmtpResponse::new(334, challenge_b64),
                        SmtpAuthState::CramResponse("CRAM-SHA1".to_string()),
                    )
                }
                _ => {
                    tracing::info!("SMTP AUTH unknown mechanism: {}", mechanism);
                    (
                        SmtpResponse::new(504, "5.5.4 Unrecognized authentication type"),
                        SmtpAuthState::None,
                    )
                }
            }
        } else if upper.starts_with("X-EXPS")
            || upper.starts_with("X-EXCH50")
            || upper.starts_with("X-LINK2STATE")
        {
            (SmtpResponse::ok(), SmtpAuthState::None)
        } else {
            (
                SmtpResponse::error("Command not recognized"),
                SmtpAuthState::None,
            )
        }
    }
}

impl Default for SmtpHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Response from SMTP handler indicating what AUTH state to transition to.
#[derive(Debug, Clone)]
pub struct SmtpAuthResult {
    pub response: SmtpResponse,
    pub new_state: SmtpAuthState,
}

impl SmtpAuthResult {
    pub fn new(response: SmtpResponse, new_state: SmtpAuthState) -> Self {
        Self {
            response,
            new_state,
        }
    }
}

/// Backward-compatible trait for async context.
/// Note: The stateful version requires the caller to maintain auth_state.
#[async_trait]
pub trait SmtpHandlerTrait: Send + Sync {
    /// Handle command without AUTH state tracking (stateless mode).
    /// Use handle_with_state() for proper AUTH state management.
    async fn handle(&self, command: &str) -> Result<SmtpResponse>;
    fn name(&self) -> &'static str;
}

#[async_trait]
impl SmtpHandlerTrait for SmtpHandler {
    async fn handle(&self, command: &str) -> Result<SmtpResponse> {
        // Stateless mode - AUTH won't work correctly across multi-line exchanges
        // Use handle_with_state() in callers that need AUTH support
        let (response, _) = self.handle_with_state(command, SmtpAuthState::None);
        Ok(response)
    }

    fn name(&self) -> &'static str {
        "smtp"
    }
}
