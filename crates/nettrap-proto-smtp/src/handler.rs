use async_trait::async_trait;
use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::prelude::*;

mod commands;
use commands::*;

const LOG_AUTH_PREVIEW_CHARS: usize = 240;
const MAX_AUTH_DATA_LEN: usize = 8192;
const MAX_SMTP_COMMAND_LINE_BYTES: usize = 1000;
const REDACTED_AUTH_FIELD: &str = "***REDACTED***";

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
    /// Whether to log credentials in plaintext at debug level.
    log_credentials: bool,
    now: fn() -> chrono::DateTime<chrono::Utc>,
}

impl SmtpHandler {
    const DEFAULT_DOMAIN: &'static str = "nettrap.local";

    pub fn new() -> Self {
        Self {
            domain: Self::DEFAULT_DOMAIN.to_string(),
            log_credentials: true,
            now: chrono::Utc::now,
        }
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Result<Self> {
        self.domain = validate_smtp_domain(&domain.into())?;
        Ok(self)
    }

    pub fn with_now(mut self, now: fn() -> chrono::DateTime<chrono::Utc>) -> Self {
        self.now = now;
        self
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn get_welcome_banner(&self) -> String {
        format!("220 {} ESMTP NetTrap Ready\r\n", self.domain)
    }

    /// Handle a command with optional AUTH state.
    /// Returns (response, new_auth_state).
    /// The caller is responsible for maintaining auth_state across calls.
    pub fn handle_with_state(
        &self,
        command: &str,
        auth_state: SmtpAuthState,
    ) -> (SmtpResponse, SmtpAuthState) {
        let Some(trimmed) = smtp_command_line(command) else {
            return match auth_state {
                SmtpAuthState::None => {
                    (SmtpResponse::new(500, "Command not recognized"), auth_state)
                }
                _ => (invalid_auth_response(), SmtpAuthState::None),
            };
        };
        if trimmed.chars().next().is_some_and(char::is_whitespace)
            || trimmed.chars().last().is_some_and(char::is_whitespace)
        {
            return match auth_state {
                SmtpAuthState::None => {
                    (SmtpResponse::new(500, "Command not recognized"), auth_state)
                }
                _ => (invalid_auth_response(), SmtpAuthState::None),
            };
        }
        let verb = command_verb(trimmed);

        // RFC 4954: "*" cancels AUTH, RSET/QUIT also reset state
        if trimmed == "*" || verb == "RSET" || verb == "QUIT" {
            if trimmed == "*" {
                return (
                    SmtpResponse::new(501, "5.5.2 Authentication exchange cancelled"),
                    SmtpAuthState::None,
                );
            }
            // Let RSET/QUIT fall through to normal handling but reset AUTH state
            let (result, _) = self.handle_command(trimmed);
            return (result, SmtpAuthState::None);
        }

        // Only treat input as credential data if it's NOT a known SMTP command
        let is_smtp_command = is_known_smtp_command(trimmed);

        match auth_state {
            SmtpAuthState::PlainContinuation => {
                if is_smtp_command {
                    tracing::info!(
                        "SMTP AUTH PLAIN aborted by command: {}",
                        safe_auth_log_text(trimmed)
                    );
                    return (
                        SmtpResponse::new(501, "5.5.2 Authentication exchange cancelled"),
                        SmtpAuthState::None,
                    );
                }
                if let Some((user, pass)) = decode_auth_plain(trimmed) {
                    if self.log_credentials {
                        tracing::debug!(
                            "SMTP AUTH PLAIN captured — user: {} pass: {}",
                            safe_auth_log_text(&user),
                            safe_auth_log_text(&pass)
                        );
                    }
                    tracing::info!(
                        "SMTP AUTH PLAIN captured — user: {} pass: {}",
                        REDACTED_AUTH_FIELD,
                        REDACTED_AUTH_FIELD
                    );
                    (
                        SmtpResponse::new(235, "2.7.0 Authentication successful"),
                        SmtpAuthState::None,
                    )
                } else {
                    if self.log_credentials {
                        tracing::debug!(
                            "SMTP AUTH PLAIN captured (decode failed): {}",
                            safe_auth_log_text(trimmed)
                        );
                    }
                    tracing::info!(
                        "SMTP AUTH PLAIN captured (decode failed): {}",
                        REDACTED_AUTH_FIELD
                    );
                    (invalid_auth_response(), SmtpAuthState::None)
                }
            }
            SmtpAuthState::LoginUsername => {
                if is_smtp_command {
                    tracing::info!(
                        "SMTP AUTH LOGIN aborted by command: {}",
                        safe_auth_log_text(trimmed)
                    );
                    return (
                        SmtpResponse::new(501, "5.5.2 Authentication exchange cancelled"),
                        SmtpAuthState::None,
                    );
                }
                let Some(username) = decode_auth_login(trimmed) else {
                    return (invalid_auth_response(), SmtpAuthState::None);
                };
                if self.log_credentials {
                    tracing::debug!(
                        "SMTP AUTH LOGIN username: {}",
                        safe_auth_log_text(&username)
                    );
                }
                tracing::info!("SMTP AUTH LOGIN username: {}", REDACTED_AUTH_FIELD);
                (
                    SmtpResponse::new(334, "UGFzc3dvcmQ6"),
                    SmtpAuthState::LoginPassword(username),
                )
            }
            SmtpAuthState::LoginPassword(username) => {
                if is_smtp_command {
                    tracing::info!(
                        "SMTP AUTH LOGIN aborted by command: {}",
                        safe_auth_log_text(trimmed)
                    );
                    return (
                        SmtpResponse::new(501, "5.5.2 Authentication exchange cancelled"),
                        SmtpAuthState::None,
                    );
                }
                // Client sending base64-encoded password
                let Some(password) = decode_auth_login(trimmed) else {
                    return (invalid_auth_response(), SmtpAuthState::None);
                };
                if self.log_credentials {
                    tracing::debug!(
                        "SMTP AUTH LOGIN captured — user: {} pass: {}",
                        safe_auth_log_text(&username),
                        safe_auth_log_text(&password)
                    );
                }
                tracing::info!(
                    "SMTP AUTH LOGIN captured — user: {} pass: {}",
                    REDACTED_AUTH_FIELD,
                    REDACTED_AUTH_FIELD
                );
                (
                    SmtpResponse::new(235, "2.7.0 Authentication successful"),
                    SmtpAuthState::None,
                )
            }
            SmtpAuthState::CramResponse(mechanism) => {
                if is_smtp_command {
                    tracing::info!(
                        "SMTP AUTH {} aborted by command: {}",
                        safe_auth_log_text(&mechanism),
                        safe_auth_log_text(trimmed)
                    );
                    return (
                        SmtpResponse::new(501, "5.5.2 Authentication exchange cancelled"),
                        SmtpAuthState::None,
                    );
                }
                if let Some((user, digest)) = decode_cram_response(trimmed) {
                    if self.log_credentials {
                        tracing::debug!(
                            "SMTP AUTH {} captured — user: {} digest: {}",
                            safe_auth_log_text(&mechanism),
                            safe_auth_log_text(&user),
                            safe_auth_log_text(&digest)
                        );
                    }
                    tracing::info!(
                        "SMTP AUTH {} captured — user: {} digest: {}",
                        safe_auth_log_text(&mechanism),
                        REDACTED_AUTH_FIELD,
                        REDACTED_AUTH_FIELD
                    );
                    (
                        SmtpResponse::new(235, "2.7.0 Authentication successful"),
                        SmtpAuthState::None,
                    )
                } else {
                    if self.log_credentials {
                        tracing::debug!(
                            "SMTP AUTH {} response captured (raw): {}",
                            safe_auth_log_text(&mechanism),
                            safe_auth_log_text(trimmed)
                        );
                    }
                    tracing::info!(
                        "SMTP AUTH {} response captured (raw): {}",
                        safe_auth_log_text(&mechanism),
                        REDACTED_AUTH_FIELD
                    );
                    (invalid_auth_response(), SmtpAuthState::None)
                }
            }
            SmtpAuthState::None => self.handle_command(trimmed),
        }
    }

    fn handle_command(&self, command: &str) -> (SmtpResponse, SmtpAuthState) {
        let trimmed = command.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty()
            || trimmed.chars().next().is_some_and(char::is_whitespace)
            || trimmed.chars().last().is_some_and(char::is_whitespace)
        {
            return (
                SmtpResponse::error("Command not recognized"),
                SmtpAuthState::None,
            );
        }
        let (verb_raw, rest) = verb_and_rest(trimmed);
        let verb = verb_raw.to_ascii_uppercase();

        match verb.as_str() {
            "EHLO" | "HELO" => {
                if rest.is_empty()
                    || rest.split(' ').nth(1).is_some()
                    || validate_smtp_domain(rest).is_err()
                {
                    return (
                        SmtpResponse::new(501, "5.5.4 Domain required"),
                        SmtpAuthState::None,
                    );
                }
                let resp = if verb == "EHLO" {
                    SmtpResponse::raw(format!(
                        "250-{} Hello\r\n250-AUTH PLAIN LOGIN CRAM-MD5 CRAM-SHA1\r\n250-SIZE 10485760\r\n250-8BITMIME\r\n250 OK\r\n",
                        self.domain
                    ))
                } else {
                    SmtpResponse::ok()
                };
                (resp, SmtpAuthState::None)
            }
            "MAIL" => {
                if has_strict_path_argument(rest, "FROM") {
                    (SmtpResponse::ok(), SmtpAuthState::None)
                } else {
                    (
                        SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                        SmtpAuthState::None,
                    )
                }
            }
            "RCPT" => {
                if has_strict_path_argument(rest, "TO") {
                    (SmtpResponse::ok(), SmtpAuthState::None)
                } else {
                    (
                        SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                        SmtpAuthState::None,
                    )
                }
            }
            "RSET" | "NOOP" => {
                if rest.is_empty() {
                    (SmtpResponse::ok(), SmtpAuthState::None)
                } else {
                    (
                        SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                        SmtpAuthState::None,
                    )
                }
            }
            "VRFY" => {
                let has_extra_args = rest.split(' ').nth(1).is_some();
                if rest.is_empty() || has_extra_args {
                    (
                        SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                        SmtpAuthState::None,
                    )
                } else {
                    (SmtpResponse::ok(), SmtpAuthState::None)
                }
            }
            "DATA" => {
                if !rest.is_empty() {
                    return (
                        SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                        SmtpAuthState::None,
                    );
                }
                (SmtpResponse::start_data(), SmtpAuthState::None)
            }
            "QUIT" => {
                if rest.is_empty() {
                    (SmtpResponse::bye(), SmtpAuthState::None)
                } else {
                    (
                        SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                        SmtpAuthState::None,
                    )
                }
            }
            "HELP" => {
                if rest.is_empty() {
                    (
                        SmtpResponse::raw(
                            "250-This is NetTrap SMTP honeypot\r\n250 Commands: EHLO HELO MAIL RCPT DATA RSET NOOP QUIT HELP STARTTLS VRFY AUTH X-EXPS X-EXCH50 X-LINK2STATE\r\n",
                        ),
                        SmtpAuthState::None,
                    )
                } else {
                    (
                        SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                        SmtpAuthState::None,
                    )
                }
            }
            "STARTTLS" => {
                if rest.is_empty() {
                    (
                        SmtpResponse::new(454, "4.7.0 TLS not available"),
                        SmtpAuthState::None,
                    )
                } else {
                    (
                        SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                        SmtpAuthState::None,
                    )
                }
            }
            "AUTH" => self.handle_auth(trimmed),
            "X-EXPS" | "X-EXCH50" | "X-LINK2STATE" => {
                if rest.is_empty() {
                    (SmtpResponse::ok(), SmtpAuthState::None)
                } else {
                    (
                        SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                        SmtpAuthState::None,
                    )
                }
            }
            _ => (
                SmtpResponse::error("Command not recognized"),
                SmtpAuthState::None,
            ),
        }
    }

    fn handle_auth(&self, trimmed: &str) -> (SmtpResponse, SmtpAuthState) {
        let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
        let Some(mechanism) = parts.get(1).filter(|value| !value.is_empty()) else {
            return (
                SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                SmtpAuthState::None,
            );
        };
        let mechanism = mechanism.to_uppercase();

        match mechanism.as_str() {
            "PLAIN" => {
                if let Some(data) = parts.get(2) {
                    if let Some((user, pass)) = decode_auth_plain(data) {
                        if self.log_credentials {
                            tracing::debug!(
                                "SMTP AUTH PLAIN captured — user: {} pass: {}",
                                safe_auth_log_text(&user),
                                safe_auth_log_text(&pass)
                            );
                        }
                        tracing::info!(
                            "SMTP AUTH PLAIN captured — user: {} pass: {}",
                            REDACTED_AUTH_FIELD,
                            REDACTED_AUTH_FIELD
                        );
                        (
                            SmtpResponse::new(235, "2.7.0 Authentication successful"),
                            SmtpAuthState::None,
                        )
                    } else {
                        if self.log_credentials {
                            tracing::debug!(
                                "SMTP AUTH PLAIN captured (decode failed): {}",
                                safe_auth_log_text(data)
                            );
                        }
                        tracing::info!(
                            "SMTP AUTH PLAIN captured (decode failed): {}",
                            REDACTED_AUTH_FIELD
                        );
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
                    let Some(username) = decode_auth_login(initial_response) else {
                        return (
                            SmtpResponse::new(535, "5.7.8 Authentication credentials invalid"),
                            SmtpAuthState::None,
                        );
                    };
                    if self.log_credentials {
                        tracing::debug!(
                            "SMTP AUTH LOGIN username: {}",
                            safe_auth_log_text(&username)
                        );
                    }
                    tracing::info!("SMTP AUTH LOGIN username: {}", REDACTED_AUTH_FIELD);
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
                if parts.get(2).is_some_and(|data| !data.is_empty()) {
                    return (
                        SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                        SmtpAuthState::None,
                    );
                }
                let fresh_challenge = generate_cram_challenge((self.now)());
                let challenge_b64 = BASE64.encode(fresh_challenge.as_bytes());
                tracing::debug!("SMTP CRAM-MD5 challenge: {}", fresh_challenge);
                (
                    SmtpResponse::new(334, challenge_b64),
                    SmtpAuthState::CramResponse("CRAM-MD5".to_string()),
                )
            }
            "CRAM-SHA1" => {
                if parts.get(2).is_some_and(|data| !data.is_empty()) {
                    return (
                        SmtpResponse::new(501, "5.5.4 Syntax error in parameters"),
                        SmtpAuthState::None,
                    );
                }
                let fresh_challenge = generate_cram_challenge((self.now)());
                let challenge_b64 = BASE64.encode(fresh_challenge.as_bytes());
                tracing::debug!("SMTP CRAM-SHA1 challenge: {}", fresh_challenge);
                (
                    SmtpResponse::new(334, challenge_b64),
                    SmtpAuthState::CramResponse("CRAM-SHA1".to_string()),
                )
            }
            _ => {
                tracing::info!(
                    "SMTP AUTH unknown mechanism: {}",
                    safe_auth_log_text(&mechanism)
                );
                (
                    SmtpResponse::new(504, "5.5.4 Unrecognized authentication type"),
                    SmtpAuthState::None,
                )
            }
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
            handler.handle_with_state(" EHLO example.test", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"500 Command not recognized\r\n");

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
        assert!(bytes.ends_with(b"\r\n"));
    }

    #[test]
    fn help_lists_supported_commands() {
        let handler = SmtpHandler::new();

        let (response, state) = handler.handle_with_state("HELP", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        let text = String::from_utf8(response.to_bytes()).expect("HELP response should be utf-8");

        assert!(text.contains("STARTTLS"));
        assert!(text.contains("VRFY"));
        assert!(text.contains("X-EXPS"));
    }

    #[test]
    fn argument_commands_accept_normal_crlf_termination() {
        let handler = SmtpHandler::new();

        let (response, state) =
            handler.handle_with_state("MAIL FROM:<a@example.test>\r\n", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"250 OK\r\n");

        let (response, state) =
            handler.handle_with_state("EHLO example.test\r\n", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        let bytes = response.to_bytes();
        assert!(bytes.starts_with(b"250-nettrap.local Hello\r\n"));
        assert!(bytes.ends_with(b"\r\n"));
    }

    #[test]
    fn raw_multiline_replies_are_crlf_terminated() {
        let handler = SmtpHandler::new();

        for command in ["EHLO example.test", "HELP"] {
            let (response, state) = handler.handle_with_state(command, SmtpAuthState::None);
            assert!(matches!(state, SmtpAuthState::None), "{command}");
            let bytes = response.to_bytes();

            assert!(bytes.ends_with(b"\r\n"), "{command}");
            assert!(!bytes.ends_with(b"\r\n\r\n"), "{command}");
        }
    }

    #[test]
    fn configured_domain_cannot_inject_response_lines() {
        assert!(
            SmtpHandler::new()
                .with_domain("mail.example\r\n250 injected")
                .is_err()
        );
    }

    #[test]
    fn configured_domain_rejects_unicode_line_separators() {
        assert!(
            SmtpHandler::new()
                .with_domain("mail.example\u{2028}250 injected")
                .is_err()
        );
    }

    #[test]
    fn configured_domain_rejects_invalid_punctuation() {
        assert!(
            SmtpHandler::new()
                .with_domain("mail.example><injected")
                .is_err()
        );
    }

    #[test]
    fn configured_domain_rejects_leading_whitespace() {
        assert!(SmtpHandler::new().with_domain(" mail.example").is_err());
    }

    #[test]
    fn helo_and_ehlo_require_domain_argument() {
        let handler = SmtpHandler::new();

        let (response, state) = handler.handle_with_state("EHLO", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"501 5.5.4 Domain required\r\n");

        let (response, state) = handler.handle_with_state("HELO", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"501 5.5.4 Domain required\r\n");

        let (response, state) = handler.handle_with_state("HELO   ", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"500 Command not recognized\r\n");

        let (response, state) =
            handler.handle_with_state("EHLO example.test extra", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"501 5.5.4 Domain required\r\n");
    }

    #[test]
    fn helo_and_ehlo_reject_invalid_domain_argument_bytes() {
        let handler = SmtpHandler::new();

        for command in ["EHLO example.test\tjunk", "HELO example.test\x1b"] {
            let (response, state) = handler.handle_with_state(command, SmtpAuthState::None);

            assert!(matches!(state, SmtpAuthState::None), "{command:?}");
            assert_eq!(
                response.to_bytes(),
                b"501 5.5.4 Domain required\r\n",
                "{command:?}"
            );
        }
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
    fn tab_separated_commands_are_rejected() {
        let handler = SmtpHandler::new();

        let (response, state) =
            handler.handle_with_state("EHLO\texample.test", SmtpAuthState::None);

        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"500 Command not recognized\r\n");
    }

    #[test]
    fn commands_reject_trailing_whitespace() {
        let handler = SmtpHandler::new();

        let (response, state) =
            handler.handle_with_state("MAIL FROM:<a@example.test> ", SmtpAuthState::None);

        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"500 Command not recognized\r\n");
    }

    #[test]
    fn commands_reject_oversized_lines() {
        let handler = SmtpHandler::new();
        let command = format!("EHLO {}", "a".repeat(MAX_SMTP_COMMAND_LINE_BYTES));

        let (response, state) = handler.handle_with_state(&command, SmtpAuthState::None);

        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"500 Command not recognized\r\n");
    }

    #[test]
    fn zero_arg_commands_accept_normal_crlf_termination() {
        let handler = SmtpHandler::new();

        for command in ["NOOP\r\n", "RSET\r\n"] {
            let (response, state) = handler.handle_with_state(command, SmtpAuthState::None);
            assert!(matches!(state, SmtpAuthState::None), "{command:?}");
            assert_eq!(response.to_bytes(), b"250 OK\r\n", "{command:?}");
        }
    }

    #[test]
    fn zero_arg_commands_reject_extra_arguments() {
        let handler = SmtpHandler::new();

        for command in [
            "NOOP now",
            "RSET now",
            "QUIT now",
            "HELP now",
            "X-EXPS now",
            "X-EXCH50 now",
            "X-LINK2STATE now",
        ] {
            let (response, state) = handler.handle_with_state(command, SmtpAuthState::None);
            assert!(matches!(state, SmtpAuthState::None), "{command:?}");
            assert_eq!(
                response.to_bytes(),
                b"501 5.5.4 Syntax error in parameters\r\n",
                "{command:?}"
            );
        }
    }

    #[test]
    fn zero_arg_commands_reject_trailing_tabs() {
        let handler = SmtpHandler::new();

        for command in ["QUIT\t", "NOOP\t", "RSET\t", "QUIT\n", "QUIT "] {
            let (response, state) = handler.handle_with_state(command, SmtpAuthState::None);
            assert!(matches!(state, SmtpAuthState::None), "{command}");
            assert_eq!(
                response.to_bytes(),
                b"500 Command not recognized\r\n",
                "{command}"
            );
        }
    }

    #[test]
    fn cram_md5_challenge_uses_the_injected_clock_for_timestamp() {
        use base64::Engine as _;

        fn fixed_now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant")
        }

        let handler = SmtpHandler::new().with_now(fixed_now);
        let (response, state) = handler.handle_with_state("AUTH CRAM-MD5", SmtpAuthState::None);
        let response = String::from_utf8(response.to_bytes()).expect("response is utf-8");

        assert!(matches!(state, SmtpAuthState::CramResponse(_)));
        let challenge_b64 = response
            .strip_prefix("334 ")
            .and_then(|text| text.strip_suffix("\r\n"))
            .expect("CRAM response should contain a base64 challenge");
        let challenge = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(challenge_b64)
                .expect("challenge should decode"),
        )
        .expect("challenge should be utf-8");

        assert!(challenge.ends_with(".1704067200@nettrap.local>"));
    }

    #[test]
    fn cram_md5_challenge_preserves_pre_epoch_timestamps() {
        fn fixed_now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(-1, 0).expect("valid instant")
        }

        let challenge = crate::handler::commands::generate_cram_challenge(fixed_now());

        assert!(challenge.ends_with(".-1@nettrap.local>"));
    }

    #[test]
    fn commands_reject_trailing_tab_arguments() {
        let handler = SmtpHandler::new();

        let (response, state) =
            handler.handle_with_state("HELO example.test\t", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"500 Command not recognized\r\n");

        let (response, state) =
            handler.handle_with_state("AUTH PLAIN dXNlcgBzZWNyZXQ=\t", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"500 Command not recognized\r\n");
    }

    #[test]
    fn commands_reject_embedded_nul_bytes() {
        let handler = SmtpHandler::new();

        let (response, state) =
            handler.handle_with_state("HELO example.test\0bad", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"500 Command not recognized\r\n");
    }

    #[test]
    fn starttls_rejects_extra_arguments_before_tls_policy() {
        let handler = SmtpHandler::new();

        let (response, state) = handler.handle_with_state("STARTTLS now", SmtpAuthState::None);

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
    fn mail_accepts_empty_reverse_path_but_rcpt_requires_forward_path() {
        let handler = SmtpHandler::new();

        let (response, state) = handler.handle_with_state("MAIL FROM:<>", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"250 OK\r\n");

        let (response, state) = handler.handle_with_state("RCPT TO:<>", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"501 5.5.4 Syntax error in parameters\r\n"
        );
    }

    #[test]
    fn mail_and_rcpt_reject_whitespace_after_colon() {
        let handler = SmtpHandler::new();

        for command in ["MAIL FROM: <a@example.test>", "RCPT TO: <b@example.test>"] {
            let (response, state) = handler.handle_with_state(command, SmtpAuthState::None);
            assert!(matches!(state, SmtpAuthState::None), "{command}");
            assert_eq!(
                response.to_bytes(),
                b"501 5.5.4 Syntax error in parameters\r\n",
                "{command}"
            );
        }
    }

    #[test]
    fn mail_and_rcpt_reject_unicode_whitespace_after_path() {
        let handler = SmtpHandler::new();

        for command in [
            "MAIL FROM:<a@example.test>\u{00a0}SIZE=1000",
            "RCPT TO:<b@example.test>\u{2003}NOTIFY=SUCCESS",
        ] {
            let (response, state) = handler.handle_with_state(command, SmtpAuthState::None);
            assert!(matches!(state, SmtpAuthState::None), "{command}");
            assert_eq!(
                response.to_bytes(),
                b"501 5.5.4 Syntax error in parameters\r\n",
                "{command}"
            );
        }
    }

    #[test]
    fn mail_and_rcpt_reject_unicode_whitespace_inside_path() {
        let handler = SmtpHandler::new();

        for command in [
            "MAIL FROM:<a@\u{00a0}example.test>",
            "RCPT TO:<b@example.test\u{00a0}>",
        ] {
            let (response, state) = handler.handle_with_state(command, SmtpAuthState::None);
            assert!(matches!(state, SmtpAuthState::None), "{command}");
            assert_eq!(
                response.to_bytes(),
                b"501 5.5.4 Syntax error in parameters\r\n",
                "{command}"
            );
        }
    }

    #[test]
    fn mail_and_rcpt_accept_advertised_esmtp_parameters() {
        // EHLO advertises SIZE (RFC 1870), so clients legitimately append
        // ESMTP parameters after the path; these must not be rejected as a
        // syntax error.
        let handler = SmtpHandler::new();

        for command in [
            "MAIL FROM:<a@example.test> SIZE=1000",
            "MAIL FROM:<a@example.test> SIZE=1000 BODY=8BITMIME",
            "RCPT TO:<b@example.test> NOTIFY=SUCCESS",
        ] {
            let (response, _state) = handler.handle_with_state(command, SmtpAuthState::None);
            assert_eq!(response.to_bytes(), b"250 OK\r\n", "{command}");
        }
    }

    #[test]
    fn mail_and_rcpt_reject_compressed_esmtp_separators() {
        let handler = SmtpHandler::new();

        for command in [
            "MAIL FROM:<a@example.test>  SIZE=1000",
            "RCPT TO:<b@example.test>  NOTIFY=SUCCESS",
        ] {
            let (response, state) = handler.handle_with_state(command, SmtpAuthState::None);
            assert!(matches!(state, SmtpAuthState::None), "{command}");
            assert_eq!(
                response.to_bytes(),
                b"501 5.5.4 Syntax error in parameters\r\n",
                "{command}"
            );
        }
    }

    #[test]
    fn mail_and_rcpt_reject_trailing_non_parameter_tokens() {
        let handler = SmtpHandler::new();

        for command in [
            "MAIL FROM:<a@example.test> extra",
            "RCPT TO:<b@example.test> extra",
        ] {
            let (response, state) = handler.handle_with_state(command, SmtpAuthState::None);
            assert!(matches!(state, SmtpAuthState::None), "{command}");
            assert_eq!(
                response.to_bytes(),
                b"501 5.5.4 Syntax error in parameters\r\n",
                "{command}"
            );
        }
    }

    #[test]
    fn mail_and_rcpt_reject_malformed_esmtp_parameters() {
        let handler = SmtpHandler::new();

        for command in [
            "MAIL FROM:<a@example.test> =",
            "MAIL FROM:<a@example.test> SIZE=",
            "RCPT TO:<b@example.test> @=1",
        ] {
            let (response, state) = handler.handle_with_state(command, SmtpAuthState::None);
            assert!(matches!(state, SmtpAuthState::None), "{command}");
            assert_eq!(
                response.to_bytes(),
                b"501 5.5.4 Syntax error in parameters\r\n",
                "{command}"
            );
        }
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

        let (response, state) = handler.handle_with_state("VRFY root extra", SmtpAuthState::None);
        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"501 5.5.4 Syntax error in parameters\r\n"
        );
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
    fn auth_without_mechanism_returns_syntax_error() {
        let handler = SmtpHandler::new();

        let (response, state) = handler.handle_with_state("AUTH", SmtpAuthState::None);

        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"501 5.5.4 Syntax error in parameters\r\n"
        );
    }

    #[test]
    fn auth_plain_rejects_leading_whitespace_base64() {
        let handler = SmtpHandler::new();

        let (response, state) =
            handler.handle_with_state("AUTH PLAIN  dXNlcgBzZWNyZXQ=", SmtpAuthState::None);

        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"535 5.7.8 Authentication credentials invalid\r\n"
        );
    }

    #[test]
    fn commands_reject_leading_whitespace() {
        let handler = SmtpHandler::new();

        let (response, state) =
            handler.handle_with_state(" EHLO example.test", SmtpAuthState::None);

        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(response.to_bytes(), b"500 Command not recognized\r\n");
    }

    #[test]
    fn commands_reject_compressed_ascii_separators() {
        let handler = SmtpHandler::new();

        for command in ["EHLO  example.test", "AUTH  LOGIN"] {
            let (response, state) = handler.handle_with_state(command, SmtpAuthState::None);

            assert!(matches!(state, SmtpAuthState::None), "{command}");
            assert_eq!(
                response.to_bytes(),
                b"500 Command not recognized\r\n",
                "{command}"
            );
        }
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
    fn auth_plain_rejects_invalid_utf8_credentials() {
        let handler = SmtpHandler::new();
        let invalid = BASE64.encode(b"\0user\0pa\xffss");

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
    fn auth_plain_continuation_aborts_on_expn_command() {
        let handler = SmtpHandler::new();

        let (_, state) = handler.handle_with_state("AUTH PLAIN", SmtpAuthState::None);
        let (response, state) = handler.handle_with_state("EXPN root", state);

        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"501 5.5.2 Authentication exchange cancelled\r\n"
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
    fn auth_login_rejects_invalid_utf8_username() {
        let handler = SmtpHandler::new();
        let invalid = BASE64.encode(b"user\xff");

        let (response, state) =
            handler.handle_with_state(&format!("AUTH LOGIN {invalid}"), SmtpAuthState::None);

        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"535 5.7.8 Authentication credentials invalid\r\n"
        );
    }

    #[test]
    fn auth_decoders_reject_control_bytes_in_credentials() {
        let plain = BASE64.encode(b"\0ali\r\nce\0pa\x1bss");
        assert!(decode_auth_plain(&plain).is_none());

        let login = BASE64.encode(b"user\r\nname\x1b");
        assert!(decode_auth_login(&login).is_none());

        let cram = BASE64.encode(b"alice dig\r\nest");
        assert!(decode_cram_response(&cram).is_none());

        let printable_plain = BASE64.encode(b"\0alice\0password");
        let (user, pass) = decode_auth_plain(&printable_plain).expect("AUTH PLAIN credentials");

        assert_eq!(user, "alice");
        assert_eq!(pass, "password");
        assert!(!user.chars().any(char::is_control));

        let printable_login = BASE64.encode(b"username");
        let username = decode_auth_login(&printable_login).expect("AUTH LOGIN username");

        assert_eq!(username, "username");
        assert!(!username.chars().any(char::is_control));

        let cram = BASE64.encode(b"alice digest");
        let (user, digest) = decode_cram_response(&cram).expect("CRAM response");

        assert_eq!(user, "alice");
        assert_eq!(digest, "digest");
        assert!(!digest.chars().any(char::is_control));
    }

    #[test]
    fn auth_decoders_reject_oversized_base64_input() {
        let oversized = "A".repeat(MAX_AUTH_DATA_LEN + 1);

        assert!(decode_auth_plain(&oversized).is_none());
        assert!(decode_auth_login(&oversized).is_none());
        assert!(decode_cram_response(&oversized).is_none());
    }

    #[test]
    fn cram_response_rejects_surrounding_whitespace() {
        let cram = BASE64.encode(b" user digest");

        assert!(decode_cram_response(&cram).is_none());
    }

    #[test]
    fn cram_response_rejects_internal_whitespace_in_digest() {
        let cram = BASE64.encode(b"user dig est");

        assert!(decode_cram_response(&cram).is_none());
    }

    #[test]
    fn raw_auth_log_fields_are_single_line() {
        let command = safe_auth_log_text("AUTH PLAIN\r\nQUIT\x1b");
        let mechanism = safe_auth_log_text("XOAUTH\x1b2");

        assert_eq!(command, "AUTH PLAIN  QUIT ");
        assert_eq!(mechanism, "XOAUTH 2");
        assert!(!command.chars().any(char::is_control));
        assert!(!mechanism.chars().any(char::is_control));

        let long = "a".repeat(LOG_AUTH_PREVIEW_CHARS + 1);
        assert_eq!(safe_auth_log_text(&long).len(), LOG_AUTH_PREVIEW_CHARS);
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

    #[test]
    fn cram_auth_rejects_initial_response_arguments() {
        let handler = SmtpHandler::new();

        for command in ["AUTH CRAM-MD5 ignored", "AUTH CRAM-SHA1 ignored"] {
            let (response, state) = handler.handle_with_state(command, SmtpAuthState::None);

            assert!(matches!(state, SmtpAuthState::None), "{command}");
            assert_eq!(
                response.to_bytes(),
                b"501 5.5.4 Syntax error in parameters\r\n",
                "{command}"
            );
        }
    }

    #[test]
    fn cram_auth_rejects_invalid_utf8_response() {
        let handler = SmtpHandler::new();

        let (response, state) = handler.handle_with_state("AUTH CRAM-MD5", SmtpAuthState::None);
        assert_eq!(response.code, 334);
        assert!(
            matches!(state, SmtpAuthState::CramResponse(ref mechanism) if mechanism == "CRAM-MD5")
        );

        let invalid = BASE64.encode(b"user \xffdigest");
        let (response, state) = handler.handle_with_state(&invalid, state);

        assert!(matches!(state, SmtpAuthState::None));
        assert_eq!(
            response.to_bytes(),
            b"535 5.7.8 Authentication credentials invalid\r\n"
        );
    }
}
