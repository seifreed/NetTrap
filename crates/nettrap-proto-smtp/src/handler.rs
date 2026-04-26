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
        // PLAIN format: [authzid]\0authcid\0passwd. Accept the legacy two-field
        // form used by some clients, but reject extra NUL-separated fields.
        let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
        let (user, pass) = if parts.len() == 3 {
            (parts[1], parts[2])
        } else if parts.len() == 2 {
            (parts[0], parts[1])
        } else {
            return None;
        };
        let user = String::from_utf8_lossy(user).to_string();
        let pass = String::from_utf8_lossy(pass).to_string();
        (!user.is_empty() && !pass.is_empty()).then_some((user, pass))
    }

    /// Decode AUTH LOGIN credentials (base64 encoded username or password)
    fn decode_auth_login(data: &str) -> Option<String> {
        let decoded = BASE64.decode(data.trim()).ok()?;
        if decoded.is_empty() {
            return None;
        }
        Some(String::from_utf8_lossy(&decoded).to_string())
    }

    /// Handle CRAM-MD5/CRAM-SHA1 response: base64(<user> <digest>)
    fn decode_cram_response(data: &str) -> Option<(String, String)> {
        let decoded = BASE64.decode(data.trim()).ok()?;
        let text = String::from_utf8_lossy(&decoded);
        let mut parts = text.splitn(2, ' ');
        let user = parts.next()?.trim();
        let digest = parts.next()?.trim();
        if user.is_empty() || digest.is_empty() {
            return None;
        }
        let user = user.to_string();
        let digest = digest.to_string();
        Some((user, digest))
    }

    fn verb_and_rest(command: &str) -> (&str, &str) {
        let trimmed = command.trim();
        match trimmed.find(char::is_whitespace) {
            Some(separator) => (&trimmed[..separator], trimmed[separator..].trim_start()),
            None => (trimmed, ""),
        }
    }

    fn command_verb(command: &str) -> String {
        let (verb, _) = Self::verb_and_rest(command);
        verb.to_ascii_uppercase()
    }

    fn has_strict_path_argument(rest: &str, keyword: &str) -> bool {
        let Some((head, path)) = rest.split_once(':') else {
            return false;
        };
        if !head.eq_ignore_ascii_case(keyword) || !path.starts_with('<') || !path.ends_with('>') {
            return false;
        }
        let address = &path[1..path.len() - 1];
        !address.trim().is_empty()
    }

    fn invalid_auth_response() -> SmtpResponse {
        SmtpResponse::new(535, "5.7.8 Authentication credentials invalid")
    }

    fn is_known_smtp_command(command: &str) -> bool {
        matches!(
            Self::command_verb(command).as_str(),
            "EHLO"
                | "HELO"
                | "MAIL"
                | "RCPT"
                | "DATA"
                | "RSET"
                | "NOOP"
                | "VRFY"
                | "QUIT"
                | "HELP"
                | "AUTH"
                | "STARTTLS"
                | "X-EXPS"
                | "X-EXCH50"
                | "X-LINK2STATE"
        )
    }

    /// Handle a command with optional AUTH state.
    /// Returns (response, new_auth_state).
    /// The caller is responsible for maintaining auth_state across calls.
    pub fn handle_with_state(
        &self,
        command: &str,
        auth_state: SmtpAuthState,
    ) -> (SmtpResponse, SmtpAuthState) {
        let trimmed = command.trim();
        let verb = Self::command_verb(trimmed);

        // ── Check if client is aborting AUTH with RSET or QUIT ─────────────────
        // RFC 4954: "*" cancels AUTH, RSET/QUIT also reset state
        if trimmed == "*" || verb == "RSET" || verb == "QUIT" {
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
        let is_smtp_command = Self::is_known_smtp_command(trimmed);

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
                    (
                        SmtpResponse::new(235, "2.7.0 Authentication successful"),
                        SmtpAuthState::None,
                    )
                } else {
                    tracing::info!("SMTP AUTH PLAIN captured (decode failed): {}", trimmed);
                    (Self::invalid_auth_response(), SmtpAuthState::None)
                }
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
                let Some(username) = Self::decode_auth_login(trimmed) else {
                    return (Self::invalid_auth_response(), SmtpAuthState::None);
                };
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
                let Some(password) = Self::decode_auth_login(trimmed) else {
                    return (Self::invalid_auth_response(), SmtpAuthState::None);
                };
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
                    (
                        SmtpResponse::new(235, "2.7.0 Authentication successful"),
                        SmtpAuthState::None,
                    )
                } else {
                    tracing::info!(
                        "SMTP AUTH {} response captured (raw): {}",
                        mechanism,
                        trimmed
                    );
                    (Self::invalid_auth_response(), SmtpAuthState::None)
                }
            }
            SmtpAuthState::None => {
                // No pending state, handle as normal command
                self.handle_command(command)
            }
        }
    }

    fn handle_command(&self, command: &str) -> (SmtpResponse, SmtpAuthState) {
        let trimmed = command.trim();
        let (verb_raw, rest) = Self::verb_and_rest(trimmed);
        let verb = verb_raw.to_ascii_uppercase();

        if verb == "EHLO" || verb == "HELO" {
            if rest.is_empty() {
                return (
                    SmtpResponse::new(501, "5.5.4 Domain required"),
                    SmtpAuthState::None,
                );
            }
            let resp = if verb == "EHLO" {
                SmtpResponse::raw(format!(
                    "250-{} Hello\r\n250-AUTH PLAIN LOGIN CRAM-MD5 CRAM-SHA1\r\n250-SIZE 10485760\r\n250-8BITMIME\r\n250 OK",
                    self.domain
                ))
            } else {
                SmtpResponse::ok()
            };
            (resp, SmtpAuthState::None)
        } else if verb == "MAIL" {
            if Self::has_strict_path_argument(rest, "FROM") {
                (SmtpResponse::ok(), SmtpAuthState::None)
            } else {
                (
                    SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                    SmtpAuthState::None,
                )
            }
        } else if verb == "RCPT" {
            if Self::has_strict_path_argument(rest, "TO") {
                (SmtpResponse::ok(), SmtpAuthState::None)
            } else {
                (
                    SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                    SmtpAuthState::None,
                )
            }
        } else if verb == "RSET" || verb == "NOOP" {
            (SmtpResponse::ok(), SmtpAuthState::None)
        } else if verb == "VRFY" {
            if rest.is_empty() {
                (
                    SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                    SmtpAuthState::None,
                )
            } else {
                (SmtpResponse::ok(), SmtpAuthState::None)
            }
        } else if verb == "DATA" {
            if !rest.is_empty() {
                return (
                    SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                    SmtpAuthState::None,
                );
            }
            (SmtpResponse::start_data(), SmtpAuthState::None)
        } else if verb == "QUIT" {
            (SmtpResponse::bye(), SmtpAuthState::None)
        } else if verb == "HELP" {
            (
                SmtpResponse::raw(
                    "250-This is NetTrap SMTP honeypot\r\n250 Commands: EHLO HELO MAIL RCPT DATA RSET NOOP QUIT AUTH",
                ),
                SmtpAuthState::None,
            )
        } else if verb == "STARTTLS" {
            (
                SmtpResponse::new(454, "4.7.0 TLS not available"),
                SmtpAuthState::None,
            )
        } else if verb == "AUTH" {
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
                            (
                                SmtpResponse::new(235, "2.7.0 Authentication successful"),
                                SmtpAuthState::None,
                            )
                        } else {
                            tracing::info!("SMTP AUTH PLAIN captured (decode failed): {}", data);
                            (
                                SmtpResponse::new(535, "5.7.8 Authentication credentials invalid"),
                                SmtpAuthState::None,
                            )
                        }
                    } else {
                        (SmtpResponse::new(334, ""), SmtpAuthState::PlainContinuation)
                    }
                }
                "LOGIN" => {
                    if let Some(initial_response) = parts.get(2).filter(|data| !data.is_empty()) {
                        let Some(username) = Self::decode_auth_login(initial_response) else {
                            return (
                                SmtpResponse::new(535, "5.7.8 Authentication credentials invalid"),
                                SmtpAuthState::None,
                            );
                        };
                        tracing::info!("SMTP AUTH LOGIN username: {}", username);
                        (
                            SmtpResponse::new(334, "UGFzc3dvcmQ6"),
                            SmtpAuthState::LoginPassword(username),
                        )
                    } else {
                        (
                            SmtpResponse::new(334, "VXNlcm5hbWU6"),
                            SmtpAuthState::LoginUsername,
                        )
                    }
                }
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
        } else if matches!(verb.as_str(), "X-EXPS" | "X-EXCH50" | "X-LINK2STATE") {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixed_smtp_verbs_are_rejected() {
        let handler = SmtpHandler::new();

        let (response, state) =
            handler.handle_with_state("EHLOXYZ example.test", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"500 Command not recognized\r\n");

        let (response, state) =
            handler.handle_with_state("MAILBOX FROM:<a@example.test>", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"500 Command not recognized\r\n");
    }

    #[test]
    fn exact_mail_and_ehlo_commands_still_work() {
        let handler = SmtpHandler::new();

        let (response, state) =
            handler.handle_with_state("MAIL FROM:<a@example.test>", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"250 OK\r\n");

        let (response, state) = handler.handle_with_state("EHLO example.test", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        let bytes = response.to_bytes();
        assert!(bytes.starts_with(b"250-nettrap.local Hello\r\n"));
    }

    #[test]
    fn helo_and_ehlo_require_domain_argument() {
        let handler = SmtpHandler::new();

        let (response, state) = handler.handle_with_state("EHLO", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"501 5.5.4 Domain required\r\n");

        let (response, state) = handler.handle_with_state("HELO   ", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"501 5.5.4 Domain required\r\n");
    }

    #[test]
    fn data_rejects_extra_arguments() {
        let handler = SmtpHandler::new();

        let (response, state) = handler.handle_with_state("DATA now", SmtpAuthState::None);

        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"501 5.5.4 Syntax error in parameters\r\n"
        );
    }

    #[test]
    fn mail_and_rcpt_require_strict_path_syntax() {
        let handler = SmtpHandler::new();

        let (response, state) =
            handler.handle_with_state("MAIL FROM:<a@example.test>", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"250 OK\r\n");

        for command in [
            "MAIL FROM",
            "MAIL FROM:",
            "MAIL FROM <a@example.test>",
            "RCPT TO",
            "RCPT TO:",
            "RCPT TO <b@example.test>",
        ] {
            let (response, state) = handler.handle_with_state(command, SmtpAuthState::None);
            assert!(matches!(state, SmtpAuthState::None));
            assert_eq!(
                response.to_bytes(),
                b"501 5.5.4 Syntax error in parameters\r\n",
                "{command}"
            );
        }

        let (response, state) =
            handler.handle_with_state("RCPT TO:<b@example.test>", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"250 OK\r\n");
    }

    #[test]
    fn vrfy_requires_argument() {
        let handler = SmtpHandler::new();

        let (response, state) = handler.handle_with_state("VRFY", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"501 5.5.4 Syntax error in parameters\r\n"
        );

        let (response, state) = handler.handle_with_state("VRFY root", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"250 OK\r\n");
    }

    #[test]
    fn auth_plain_invalid_base64_does_not_authenticate() {
        let handler = SmtpHandler::new();

        let (response, state) = handler.handle_with_state("AUTH PLAIN !!!", SmtpAuthState::None);

        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"535 5.7.8 Authentication credentials invalid\r\n"
        );
    }

    #[test]
    fn auth_plain_rejects_extra_nul_fields() {
        let handler = SmtpHandler::new();
        let invalid = BASE64.encode(b"\0user\0pass\0extra");

        let (response, state) =
            handler.handle_with_state(&format!("AUTH PLAIN {invalid}"), SmtpAuthState::None);

        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"535 5.7.8 Authentication credentials invalid\r\n"
        );
    }

    #[test]
    fn auth_plain_continuation_rejects_invalid_or_incomplete_credentials() {
        let handler = SmtpHandler::new();

        let (response, state) = handler.handle_with_state("AUTH PLAIN", SmtpAuthState::None);
        assert_eq!(response.to_bytes(), b"334 \r\n");
        assert!(matches!(state, SmtpAuthState::PlainContinuation));

        let (response, state) = handler.handle_with_state("!!!", state);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"535 5.7.8 Authentication credentials invalid\r\n"
        );

        let (_, state) = handler.handle_with_state("AUTH PLAIN", SmtpAuthState::None);
        let (response, state) = handler.handle_with_state("dXNlcg==", state);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"535 5.7.8 Authentication credentials invalid\r\n"
        );
    }

    #[test]
    fn auth_login_inline_username_moves_to_password_challenge() {
        let handler = SmtpHandler::new();

        let (response, state) =
            handler.handle_with_state("AUTH LOGIN dXNlcg==", SmtpAuthState::None);

        assert_eq!(response.to_bytes(), b"334 UGFzc3dvcmQ6\r\n");
        assert!(matches!(state, SmtpAuthState::LoginPassword(username) if username == "user"));
    }

    #[test]
    fn auth_login_continuation_rejects_invalid_base64() {
        let handler = SmtpHandler::new();

        let (response, state) = handler.handle_with_state("AUTH LOGIN", SmtpAuthState::None);
        assert_eq!(response.to_bytes(), b"334 VXNlcm5hbWU6\r\n");
        assert!(matches!(state, SmtpAuthState::LoginUsername));

        let (response, state) = handler.handle_with_state("!!!", state);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"535 5.7.8 Authentication credentials invalid\r\n"
        );

        let (response, state) =
            handler.handle_with_state("AUTH LOGIN dXNlcg==", SmtpAuthState::None);
        assert_eq!(response.to_bytes(), b"334 UGFzc3dvcmQ6\r\n");
        assert!(matches!(state, SmtpAuthState::LoginPassword(ref username) if username == "user"));

        let (response, state) = handler.handle_with_state("!!!", state);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"535 5.7.8 Authentication credentials invalid\r\n"
        );
    }

    #[test]
    fn cram_auth_requires_user_and_digest_response() {
        let handler = SmtpHandler::new();

        let (response, state) = handler.handle_with_state("AUTH CRAM-MD5", SmtpAuthState::None);
        assert_eq!(response.code, 334);
        assert!(
            matches!(state, SmtpAuthState::CramResponse(ref mechanism) if mechanism == "CRAM-MD5")
        );

        let (response, state) = handler.handle_with_state("dXNlcg==", state);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"535 5.7.8 Authentication credentials invalid\r\n"
        );

        let valid = BASE64.encode(b"user abcdef");
        let (_, state) = handler.handle_with_state("AUTH CRAM-SHA1", SmtpAuthState::None);
        let (response, state) = handler.handle_with_state(&valid, state);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"235 2.7.0 Authentication successful\r\n"
        );
    }
}
