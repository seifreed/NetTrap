use crate::prelude::*;
use async_trait::async_trait;
#[cfg(test)]
use base64::Engine as Base64Engine;
#[cfg(test)]
use base64::engine::general_purpose::STANDARD as BASE64;
use std::sync::Mutex;

const MAX_AUTH_DATA_LEN: usize = 8192;
const MAX_POP3_COMMAND_LINE_BYTES: usize = 512;
const LOG_AUTH_PREVIEW_CHARS: usize = 240;
const REDACTED_AUTH_FIELD: &str = "***REDACTED***";

mod helpers;
pub(crate) use helpers::*;

pub struct Pop3Handler {
    domain: String,
    emails: Vec<Pop3Email>,
    auth_state: Mutex<Pop3AuthState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Pop3AuthState {
    #[default]
    None,
    AuthPlain,
    AuthLoginUsername,
    AuthLoginPassword {
        username: String,
    },
}

struct Pop3Email {
    body: String,
    size: usize,
}

impl Pop3Handler {
    const DEFAULT_DOMAIN: &'static str = "nettrap.local";

    pub fn new() -> Self {
        Self::from_now(chrono::Utc::now())
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Result<Self> {
        self.domain = validate_pop3_domain(&domain.into())?;
        Ok(self)
    }

    /// Seed the default welcome mail with an explicit instant so FakeTime mode
    /// can reach POP3 RETR/LIST output, including pre-epoch offsets.
    pub fn with_now(mut self, now: fn() -> chrono::DateTime<chrono::Utc>) -> Self {
        self.emails = Self::default_maildrop(now());
        self
    }

    pub fn get_welcome_banner(&self) -> String {
        format!("+OK {} NetTrap POP3 server ready\r\n", self.domain)
    }

    fn from_now(now: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            domain: Self::DEFAULT_DOMAIN.to_string(),
            emails: Self::default_maildrop(now),
            auth_state: Mutex::new(Pop3AuthState::None),
        }
    }

    fn default_maildrop(now: chrono::DateTime<chrono::Utc>) -> Vec<Pop3Email> {
        let body = pop3_welcome_email_body(now);
        let size = body.len();
        vec![Pop3Email { body, size }]
    }

    fn handle_with_auth_state(&self, command: &str) -> Result<Pop3Response> {
        let Some(command) = pop3_command_line(command) else {
            return Ok(Pop3Response::err("Invalid argument"));
        };
        if command.chars().last().is_some_and(char::is_whitespace) {
            return Ok(Pop3Response::err("Invalid argument"));
        }

        let current_state = {
            let mut state = self
                .auth_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *state)
        };

        if current_state != Pop3AuthState::None && command == "*" {
            return Ok(Pop3Response::err("Authentication exchange cancelled"));
        }

        let (response, next_state) = match current_state {
            Pop3AuthState::None => self.handle_stateless_command(command)?,
            Pop3AuthState::AuthPlain => (handle_auth_plain_data(command), Pop3AuthState::None),
            Pop3AuthState::AuthLoginUsername => match decode_auth_field(command) {
                Ok(username) => (
                    Pop3Response::raw("+ UGFzc3dvcmQ6\r\n"),
                    Pop3AuthState::AuthLoginPassword { username },
                ),
                Err(response) => (response, Pop3AuthState::None),
            },
            Pop3AuthState::AuthLoginPassword { username } => {
                let response = match decode_auth_field(command) {
                    Ok(password) => {
                        tracing::debug!(
                            "POP3 AUTH LOGIN — user: {} pass: {}",
                            safe_auth_log_text(&username),
                            safe_auth_log_text(&password)
                        );
                        tracing::info!(
                            "POP3 AUTH LOGIN — user: {} pass: {}",
                            REDACTED_AUTH_FIELD,
                            REDACTED_AUTH_FIELD
                        );
                        Pop3Response::ok("Authentication successful")
                    }
                    Err(response) => response,
                };
                (response, Pop3AuthState::None)
            }
        };

        let mut state = self
            .auth_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *state = next_state;
        Ok(response)
    }

    fn handle_stateless_command(&self, command: &str) -> Result<(Pop3Response, Pop3AuthState)> {
        if command.chars().next().is_some_and(char::is_whitespace) {
            return Ok((Pop3Response::err("Unknown command"), Pop3AuthState::None));
        }

        let parts: Vec<&str> = command.split(' ').collect();
        if parts.iter().skip(1).any(|part| part.is_empty()) {
            return Ok((Pop3Response::err("Invalid argument"), Pop3AuthState::None));
        }
        let verb = parts
            .first()
            .map(|part| part.to_ascii_uppercase())
            .unwrap_or_default();

        let response = match verb.as_str() {
            "USER" => {
                if parts.len() == 2 && is_strict_single_token(parts[1]) {
                    Pop3Response::ok("User accepted")
                } else if parts.len() == 1 {
                    Pop3Response::err("Missing argument")
                } else {
                    Pop3Response::err("Invalid argument")
                }
            }
            "PASS" => {
                if parts.len() == 2 && is_strict_single_token(parts[1]) {
                    Pop3Response::ok("Mailbox locked and ready")
                } else if parts.len() == 1 {
                    Pop3Response::err("Missing argument")
                } else {
                    Pop3Response::err("Invalid argument")
                }
            }
            "STAT" => {
                if let Err(response) = Self::require_no_extra_args(&parts) {
                    return Ok((response, Pop3AuthState::None));
                }
                let total_size = total_maildrop_size(&self.emails);
                Pop3Response::ok(format!("{} {}", self.emails.len(), total_size))
            }
            "LIST" => self.handle_list_command(&parts),
            "RETR" => self.handle_retr_command(&parts),
            "DELE" => match self.parse_existing_message_index(&parts) {
                Ok(_) if parts.len() == 2 => Pop3Response::ok("Message deleted"),
                Ok(_) => Pop3Response::err("Invalid argument"),
                Err(response) => response,
            },
            "NOOP" => match Self::require_no_extra_args(&parts) {
                Ok(()) => Pop3Response::ok(""),
                Err(response) => response,
            },
            "RSET" => match Self::require_no_extra_args(&parts) {
                Ok(()) => Pop3Response::ok("Maildrop has been reset"),
                Err(response) => response,
            },
            "TOP" => {
                if parts.len() < 3 {
                    Pop3Response::err("Missing argument")
                } else if parts.len() > 3 {
                    Pop3Response::err("Invalid argument")
                } else {
                    match self.parse_existing_message_index(&parts) {
                        Ok(idx) => match parts
                            .get(2)
                            .and_then(|part| parse_unsigned_decimal::<usize>(part))
                        {
                            Some(lines) => {
                                let Some(email) = self.emails.get(idx - 1) else {
                                    return Ok((
                                        Pop3Response::err("No such message"),
                                        Pop3AuthState::None,
                                    ));
                                };
                                let mut response = "+OK\r\n".to_string();
                                append_top_message(&mut response, &email.body, lines);
                                response.push_str(".\r\n");
                                Pop3Response::raw(response)
                            }
                            None => Pop3Response::err("Invalid argument"),
                        },
                        Err(response) => response,
                    }
                }
            }
            "UIDL" => self.handle_uidl_command(&parts),
            "AUTH" => {
                return self.handle_auth_command(&parts);
            }
            "APOP" => {
                if parts.len() > 3 {
                    return Ok((Pop3Response::err("Invalid argument"), Pop3AuthState::None));
                }
                let Some(user) = parts.get(1).filter(|value| !value.is_empty()) else {
                    return Ok((Pop3Response::err("Missing argument"), Pop3AuthState::None));
                };
                let Some(digest) = parts.get(2).filter(|value| !value.is_empty()) else {
                    return Ok((Pop3Response::err("Missing argument"), Pop3AuthState::None));
                };
                if !is_strict_single_token(user) || !is_strict_single_token(digest) {
                    return Ok((Pop3Response::err("Invalid argument"), Pop3AuthState::None));
                }
                tracing::debug!(
                    "POP3 APOP — user: {} digest: {}",
                    safe_auth_log_text(user),
                    safe_auth_log_text(digest)
                );
                tracing::info!(
                    "POP3 APOP — user: {} digest: {}",
                    REDACTED_AUTH_FIELD,
                    REDACTED_AUTH_FIELD
                );
                Pop3Response::ok("Authentication successful")
            }
            "CAPA" => match Self::require_no_extra_args(&parts) {
                Ok(()) => Pop3Response::raw(
                    "+OK Capability list follows\r\nUSER\r\nTOP\r\nUIDL\r\nAPOP\r\nSASL PLAIN LOGIN\r\n.\r\n",
                ),
                Err(response) => response,
            },
            "STLS" => match Self::require_no_extra_args(&parts) {
                Ok(()) => Pop3Response::err("TLS not available"),
                Err(response) => response,
            },
            "QUIT" => match Self::require_no_extra_args(&parts) {
                Ok(()) => Pop3Response::ok("Goodbye"),
                Err(response) => response,
            },
            _ => Pop3Response::err("Unknown command"),
        };

        Ok((response, Pop3AuthState::None))
    }

    fn handle_list_command(&self, parts: &[&str]) -> Pop3Response {
        if parts.len() > 1 {
            if parts.len() > 2 {
                Pop3Response::err("Invalid argument")
            } else if let Some(idx) = parts
                .get(1)
                .and_then(|part| parse_unsigned_decimal::<usize>(part))
            {
                if idx > 0 && idx <= self.emails.len() {
                    if let Some(email) = self.emails.get(idx - 1) {
                        Pop3Response::ok(format!("{} {}", idx, email.size))
                    } else {
                        Pop3Response::err("No such message")
                    }
                } else {
                    Pop3Response::err("No such message")
                }
            } else {
                Pop3Response::err("Invalid argument")
            }
        } else {
            let mut response = format!("+OK {} messages\r\n", self.emails.len());
            for (i, email) in self.emails.iter().enumerate() {
                response.push_str(&format!("{} {}\r\n", i + 1, email.size));
            }
            response.push_str(".\r\n");
            Pop3Response::raw(response)
        }
    }

    fn handle_retr_command(&self, parts: &[&str]) -> Pop3Response {
        tracing::info!("POP3 RETR command received (stateless handler)");
        if parts.len() > 1 {
            if parts.len() > 2 {
                Pop3Response::err("Invalid argument")
            } else if let Some(idx) = parts
                .get(1)
                .and_then(|part| parse_unsigned_decimal::<usize>(part))
            {
                if idx > 0 && idx <= self.emails.len() {
                    let Some(email) = self.emails.get(idx - 1) else {
                        return Pop3Response::err("No such message");
                    };
                    let mut response = format!("+OK {} octets\r\n", email.size);
                    append_dot_stuffed_body(&mut response, &email.body);
                    response.push_str(".\r\n");
                    Pop3Response::raw(response)
                } else {
                    Pop3Response::err("No such message")
                }
            } else {
                Pop3Response::err("Invalid argument")
            }
        } else {
            Pop3Response::err("Missing argument")
        }
    }

    fn handle_uidl_command(&self, parts: &[&str]) -> Pop3Response {
        if parts.len() > 1 {
            if parts.len() > 2 {
                Pop3Response::err("Invalid argument")
            } else if let Some(idx) = parts
                .get(1)
                .and_then(|part| parse_unsigned_decimal::<usize>(part))
            {
                if idx > 0 && idx <= self.emails.len() {
                    Pop3Response::ok(format!("{} nettrap-msg-{}", idx, idx))
                } else {
                    Pop3Response::err("No such message")
                }
            } else {
                Pop3Response::err("Invalid argument")
            }
        } else {
            let mut response = "+OK\r\n".to_string();
            for i in 0..self.emails.len() {
                response.push_str(&format!("{} nettrap-msg-{}\r\n", i + 1, i + 1));
            }
            response.push_str(".\r\n");
            Pop3Response::raw(response)
        }
    }

    fn parse_existing_message_index(
        &self,
        parts: &[&str],
    ) -> std::result::Result<usize, Pop3Response> {
        let Some(raw_index) = parts.get(1) else {
            return Err(Pop3Response::err("Missing argument"));
        };

        let index = parse_unsigned_decimal::<usize>(raw_index)
            .ok_or_else(|| Pop3Response::err("Invalid argument"))?;
        if index == 0 || index > self.emails.len() {
            return Err(Pop3Response::err("No such message"));
        }

        Ok(index)
    }

    fn require_no_extra_args(parts: &[&str]) -> std::result::Result<(), Pop3Response> {
        if parts.len() == 1 {
            Ok(())
        } else {
            Err(Pop3Response::err("Invalid argument"))
        }
    }

    fn handle_auth_command(&self, parts: &[&str]) -> Result<(Pop3Response, Pop3AuthState)> {
        if parts.len() <= 1 {
            return Ok((
                Pop3Response::raw("+OK\r\nPLAIN\r\nLOGIN\r\n.\r\n"),
                Pop3AuthState::None,
            ));
        }
        if parts.iter().skip(1).any(|part| part.is_empty()) {
            return Ok((Pop3Response::err("Invalid argument"), Pop3AuthState::None));
        }

        let Some(mechanism) = parts.get(1) else {
            return Ok((Pop3Response::err("Invalid argument"), Pop3AuthState::None));
        };
        let mechanism = mechanism.to_ascii_uppercase();
        match mechanism.as_str() {
            "PLAIN" => {
                if parts.len() > 3 {
                    return Ok((Pop3Response::err("Invalid argument"), Pop3AuthState::None));
                }
                if let Some(data) = parts.get(2) {
                    Ok((handle_auth_plain_data(data), Pop3AuthState::None))
                } else {
                    Ok((Pop3Response::raw("+\r\n"), Pop3AuthState::AuthPlain))
                }
            }
            "LOGIN" => {
                if parts.len() > 2 {
                    return Ok((Pop3Response::err("Invalid argument"), Pop3AuthState::None));
                }
                Ok((
                    Pop3Response::raw("+ VXNlcm5hbWU6\r\n"),
                    Pop3AuthState::AuthLoginUsername,
                ))
            }
            _ => {
                tracing::info!("POP3 AUTH {} attempted", safe_auth_log_text(&mechanism));
                Ok((
                    Pop3Response::err("Unsupported authentication mechanism"),
                    Pop3AuthState::None,
                ))
            }
        }
    }
}

fn append_dot_stuffed_body(response: &mut String, body: &str) {
    append_dot_stuffed_body_lines(response, body.split_terminator("\r\n"));
}

fn append_top_message(response: &mut String, message: &str, body_lines: usize) {
    let Some((headers, body)) = message.split_once("\r\n\r\n") else {
        append_dot_stuffed_body_lines(response, message.split_terminator("\r\n"));
        return;
    };

    append_dot_stuffed_body_lines(response, headers.split_terminator("\r\n"));
    response.push_str("\r\n");
    append_dot_stuffed_body_lines(response, body.split_terminator("\r\n").take(body_lines));
}

fn append_dot_stuffed_body_lines<'a, I>(response: &mut String, lines: I)
where
    I: IntoIterator<Item = &'a str>,
{
    for line in lines {
        if line.starts_with('.') {
            response.push('.');
        }
        response.push_str(line);
        response.push_str("\r\n");
    }
}

fn is_strict_single_token(value: &str) -> bool {
    !value.is_empty()
        && !value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
}

fn pop3_command_line(command: &str) -> Option<&str> {
    if command.chars().any(|ch| ch == '\0') {
        return None;
    }
    if nettrap_core::sanitize::contains_unicode_line_separator(command) {
        return None;
    }
    if let Some(line) = command.strip_suffix("\r\n") {
        if line.chars().any(|ch| matches!(ch, '\r' | '\n')) {
            return None;
        }
        if line.len() > MAX_POP3_COMMAND_LINE_BYTES {
            return None;
        }
        return Some(line);
    }
    if command.ends_with(['\r', '\n']) {
        return None;
    }
    if command.chars().any(|ch| matches!(ch, '\r' | '\n')) {
        return None;
    }
    if command.len() > MAX_POP3_COMMAND_LINE_BYTES {
        return None;
    }
    Some(command)
}

fn pop3_welcome_email_body(now: chrono::DateTime<chrono::Utc>) -> String {
    let date = pop3_rfc2822_date(now);
    format!(
        "From: admin@nettrap.local\r\nTo: user@nettrap.local\r\nSubject: Welcome to NetTrap\r\nDate: {date}\r\nContent-Type: text/plain\r\n\r\nWelcome to NetTrap POP3 honeypot.\r\n"
    )
}

fn total_maildrop_size(emails: &[Pop3Email]) -> usize {
    emails
        .iter()
        .fold(0usize, |total, email| total.saturating_add(email.size))
}

fn pop3_rfc2822_date(now: chrono::DateTime<chrono::Utc>) -> String {
    now.to_rfc2822()
}

impl Default for Pop3Handler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait Pop3HandlerTrait: Send + Sync {
    async fn handle(&self, command: &str) -> Result<Pop3Response>;
    fn name(&self) -> &'static str;
}

#[async_trait]
impl Pop3HandlerTrait for Pop3Handler {
    async fn handle(&self, command: &str) -> Result<Pop3Response> {
        self.handle_with_auth_state(command)
    }

    fn name(&self) -> &'static str {
        "pop3"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut cx = Context::from_waker(Waker::noop());
        let mut future = Pin::from(Box::new(future));
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn capa_does_not_advertise_stls_without_tls_upgrade() {
        let response = block_on(Pop3Handler::new().handle("CAPA")).expect("CAPA response");

        assert!(response.positive);
        assert!(!response.message.contains("\r\nSTLS\r\n"));
        assert!(response.message.contains("\r\nAPOP\r\n"));
        assert!(response.message.contains("\r\nSASL PLAIN LOGIN\r\n"));
        assert_eq!(
            response.to_bytes(),
            b"+OK Capability list follows\r\nUSER\r\nTOP\r\nUIDL\r\nAPOP\r\nSASL PLAIN LOGIN\r\n.\r\n"
        );
    }

    #[test]
    fn raw_multiline_responses_do_not_get_duplicate_ok_prefix() {
        let handler = Pop3Handler::new();

        let list = block_on(handler.handle("LIST")).expect("LIST response");
        assert!(list.to_bytes().starts_with(b"+OK 1 messages\r\n"));
        assert!(!list.to_bytes().starts_with(b"+OK +OK"));

        let retr = block_on(handler.handle("RETR 1")).expect("RETR response");
        assert!(retr.to_bytes().starts_with(b"+OK "));
        assert!(retr.to_bytes().ends_with(b"\r\n.\r\n"));
        assert!(!retr.to_bytes().starts_with(b"+OK +OK"));
    }

    #[test]
    fn welcome_message_date_uses_supplied_instant() {
        let now = chrono::DateTime::from_timestamp(1_704_067_200, 0)
            .expect("timestamp should be representable");
        let body = pop3_welcome_email_body(now);

        assert!(body.contains("Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n"));
    }

    #[test]
    fn welcome_message_retr_uses_injected_instant() {
        fn fixed_now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(1_704_067_200, 0)
                .expect("timestamp should be representable")
        }

        let handler = Pop3Handler::new().with_now(fixed_now);
        let retr = block_on(handler.handle("RETR 1")).expect("RETR response");
        let retr_bytes = retr.to_bytes();
        let text = String::from_utf8_lossy(&retr_bytes);

        assert!(text.contains("Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n"));
    }

    #[test]
    fn welcome_message_uses_pre_epoch_instant_without_flattening() {
        let now = chrono::DateTime::from_timestamp(-1, 0)
            .expect("pre-epoch timestamp should be representable");
        let body = pop3_welcome_email_body(now);

        assert!(body.contains("Date: Wed, 31 Dec 1969 23:59:59 +0000\r\n"));
    }

    #[test]
    fn generated_welcome_message_size_matches_body_length() {
        let now = chrono::DateTime::from_timestamp(1_704_067_200, 0)
            .expect("timestamp should be representable");
        let body = pop3_welcome_email_body(now);
        let email = Pop3Email {
            size: body.len(),
            body,
        };

        assert_eq!(email.size, email.body.len());
    }

    #[test]
    fn stat_saturates_maildrop_size_on_overflow() {
        let mut handler = Pop3Handler::new();
        handler.emails = vec![
            Pop3Email {
                body: String::new(),
                size: usize::MAX,
            },
            Pop3Email {
                body: String::new(),
                size: 1,
            },
        ];

        let response = block_on(handler.handle("STAT")).expect("STAT response");

        assert!(response.positive);
        assert_eq!(response.message, format!("2 {}", usize::MAX));
    }

    #[test]
    fn retr_and_top_dot_stuff_message_lines_that_start_with_dot() {
        let mut handler = Pop3Handler::new();
        handler.emails = vec![Pop3Email {
            body: "Header: value\r\n.line one\r\n..line two\r\n".to_string(),
            size: 39,
        }];

        let retr = block_on(handler.handle("RETR 1")).expect("RETR response");
        let retr_bytes = retr.to_bytes();
        let retr_text = std::str::from_utf8(&retr_bytes).expect("RETR utf-8");
        assert!(retr_text.contains("\r\n..line one\r\n"));
        assert!(retr_text.contains("\r\n...line two\r\n"));
        assert_eq!(retr_text.matches("\r\n.\r\n").count(), 1);

        let top = block_on(handler.handle("TOP 1 3")).expect("TOP response");
        let top_bytes = top.to_bytes();
        let top_text = std::str::from_utf8(&top_bytes).expect("TOP utf-8");
        assert!(top_text.contains("\r\n..line one\r\n"));
        assert!(top_text.contains("\r\n...line two\r\n"));
        assert_eq!(top_text.matches("\r\n.\r\n").count(), 1);
    }

    #[test]
    fn configured_domain_cannot_inject_banner_lines() {
        assert!(
            Pop3Handler::new()
                .with_domain("mail.example\r\n+OK injected")
                .is_err()
        );
    }

    #[test]
    fn configured_domain_rejects_unicode_line_separators() {
        assert!(
            Pop3Handler::new()
                .with_domain("mail.example\u{2028}+OK injected")
                .is_err()
        );
    }

    #[test]
    fn configured_domain_rejects_invalid_punctuation() {
        assert!(
            Pop3Handler::new()
                .with_domain("mail.example><injected")
                .is_err()
        );
    }

    #[test]
    fn configured_domain_rejects_leading_whitespace() {
        assert!(Pop3Handler::new().with_domain(" mail.example").is_err());
    }

    #[test]
    fn configured_domain_rejects_unicode_whitespace() {
        assert!(
            Pop3Handler::new()
                .with_domain("mail\u{00a0}example")
                .is_err()
        );
    }

    #[test]
    fn configured_domain_rejects_empty_labels() {
        assert!(Pop3Handler::new().with_domain(".example").is_err());
    }

    #[test]
    fn configured_domain_rejects_dashed_label_edges() {
        assert!(Pop3Handler::new().with_domain("bad-.example").is_err());
    }

    #[test]
    fn auth_plain_without_inline_data_sends_exact_continuation_prompt() {
        let handler = Pop3Handler::new();
        let response = block_on(handler.handle("AUTH PLAIN")).expect("AUTH PLAIN response");

        assert_eq!(response.to_bytes(), b"+\r\n");

        let response = block_on(handler.handle("AHVzZXIAcGFzcw==")).expect("AUTH PLAIN data");
        assert_eq!(response.to_bytes(), b"+OK Authentication successful\r\n");
    }

    #[test]
    fn auth_plain_rejects_extra_nul_fields() {
        let handler = Pop3Handler::new();
        let invalid = BASE64.encode(b"\0user\0pass\0extra");

        let response = block_on(handler.handle(&format!("AUTH PLAIN {invalid}")))
            .expect("AUTH PLAIN extra field response");
        assert_eq!(response.to_bytes(), b"-ERR Invalid authentication data\r\n");

        let response = block_on(handler.handle("AUTH PLAIN")).expect("AUTH PLAIN response");
        assert_eq!(response.to_bytes(), b"+\r\n");
        let response = block_on(handler.handle(&invalid)).expect("AUTH PLAIN continuation");
        assert_eq!(response.to_bytes(), b"-ERR Invalid authentication data\r\n");
    }

    #[test]
    fn auth_plain_requires_authzid_user_and_password_fields() {
        let handler = Pop3Handler::new();
        let invalid = BASE64.encode(b"user\0pass");

        let response = block_on(handler.handle(&format!("AUTH PLAIN {invalid}")))
            .expect("AUTH PLAIN two-field response");
        assert_eq!(response.to_bytes(), b"-ERR Invalid authentication data\r\n");

        let response = block_on(handler.handle("AUTH PLAIN")).expect("AUTH PLAIN response");
        assert_eq!(response.to_bytes(), b"+\r\n");
        let response = block_on(handler.handle(&invalid)).expect("AUTH PLAIN continuation");
        assert_eq!(response.to_bytes(), b"-ERR Invalid authentication data\r\n");
    }

    #[test]
    fn auth_plain_rejects_invalid_utf8_credentials() {
        let handler = Pop3Handler::new();
        let invalid = BASE64.encode(b"\0us\xffr\0pa\xfer");

        let response = block_on(handler.handle(&format!("AUTH PLAIN {invalid}")))
            .expect("AUTH PLAIN invalid utf8 response");
        assert_eq!(response.to_bytes(), b"-ERR Invalid authentication data\r\n");

        let response = block_on(handler.handle("AUTH PLAIN")).expect("AUTH PLAIN response");
        assert_eq!(response.to_bytes(), b"+\r\n");
        let response = block_on(handler.handle(&invalid)).expect("AUTH PLAIN continuation");
        assert_eq!(response.to_bytes(), b"-ERR Invalid authentication data\r\n");
    }

    #[test]
    fn auth_plain_rejects_whitespace_only_credentials() {
        let handler = Pop3Handler::new();
        let invalid = BASE64.encode(b"\0 \t \0\t");

        let response = block_on(handler.handle(&format!("AUTH PLAIN {invalid}")))
            .expect("AUTH PLAIN whitespace-only response");
        assert_eq!(response.to_bytes(), b"-ERR Invalid authentication data\r\n");
    }

    #[test]
    fn auth_login_rejects_empty_continuation_fields() {
        let handler = Pop3Handler::new();

        let response = block_on(handler.handle("AUTH LOGIN")).expect("AUTH LOGIN response");
        assert_eq!(response.to_bytes(), b"+ VXNlcm5hbWU6\r\n");
        let response = block_on(handler.handle("")).expect("empty username response");
        assert_eq!(response.to_bytes(), b"-ERR Invalid authentication data\r\n");

        let response = block_on(handler.handle("AUTH LOGIN")).expect("AUTH LOGIN response");
        assert_eq!(response.to_bytes(), b"+ VXNlcm5hbWU6\r\n");
        let response = block_on(handler.handle("dXNlcg==")).expect("AUTH LOGIN username");
        assert_eq!(response.to_bytes(), b"+ UGFzc3dvcmQ6\r\n");
        let response = block_on(handler.handle("")).expect("empty password response");
        assert_eq!(response.to_bytes(), b"-ERR Invalid authentication data\r\n");
    }

    #[test]
    fn auth_continuation_can_be_cancelled_with_asterisk() {
        let plain = Pop3Handler::new();
        let response = block_on(plain.handle("AUTH PLAIN")).expect("AUTH PLAIN response");
        assert_eq!(response.to_bytes(), b"+\r\n");
        let response = block_on(plain.handle("*")).expect("AUTH PLAIN cancellation");
        assert_eq!(
            response.to_bytes(),
            b"-ERR Authentication exchange cancelled\r\n"
        );
        let response = block_on(plain.handle("STAT")).expect("STAT after cancellation");
        assert!(response.to_bytes().starts_with(b"+OK 1 "));

        let login = Pop3Handler::new();
        let response = block_on(login.handle("AUTH LOGIN")).expect("AUTH LOGIN response");
        assert_eq!(response.to_bytes(), b"+ VXNlcm5hbWU6\r\n");
        let response = block_on(login.handle("*")).expect("AUTH LOGIN cancellation");
        assert_eq!(
            response.to_bytes(),
            b"-ERR Authentication exchange cancelled\r\n"
        );
        let response = block_on(login.handle("STAT")).expect("STAT after cancellation");
        assert!(response.to_bytes().starts_with(b"+OK 1 "));
    }

    #[test]
    fn auth_login_rejects_invalid_utf8_username_and_password() {
        let handler = Pop3Handler::new();

        let response = block_on(handler.handle("AUTH LOGIN")).expect("AUTH LOGIN response");
        assert_eq!(response.to_bytes(), b"+ VXNlcm5hbWU6\r\n");
        let response = block_on(handler.handle(&BASE64.encode(b"us\xffr")))
            .expect("AUTH LOGIN invalid username");
        assert_eq!(response.to_bytes(), b"-ERR Invalid authentication data\r\n");

        let response = block_on(handler.handle("AUTH LOGIN")).expect("AUTH LOGIN response");
        assert_eq!(response.to_bytes(), b"+ VXNlcm5hbWU6\r\n");
        let response = block_on(handler.handle("dXNlcg==")).expect("AUTH LOGIN username");
        assert_eq!(response.to_bytes(), b"+ UGFzc3dvcmQ6\r\n");
        let response = block_on(handler.handle(&BASE64.encode(b"pa\xffer")))
            .expect("AUTH LOGIN invalid password");
        assert_eq!(response.to_bytes(), b"-ERR Invalid authentication data\r\n");
    }

    #[test]
    fn auth_login_rejects_whitespace_only_continuation_fields() {
        let handler = Pop3Handler::new();

        let response = block_on(handler.handle("AUTH LOGIN")).expect("AUTH LOGIN response");
        assert_eq!(response.to_bytes(), b"+ VXNlcm5hbWU6\r\n");
        let response = block_on(handler.handle(&BASE64.encode(b" \t ")))
            .expect("AUTH LOGIN whitespace username");
        assert_eq!(response.to_bytes(), b"-ERR Invalid authentication data\r\n");

        let response = block_on(handler.handle("AUTH LOGIN")).expect("AUTH LOGIN response");
        assert_eq!(response.to_bytes(), b"+ VXNlcm5hbWU6\r\n");
        let response = block_on(handler.handle("dXNlcg==")).expect("AUTH LOGIN username");
        assert_eq!(response.to_bytes(), b"+ UGFzc3dvcmQ6\r\n");
        let response = block_on(handler.handle(&BASE64.encode(b" \t ")))
            .expect("AUTH LOGIN whitespace password");
        assert_eq!(response.to_bytes(), b"-ERR Invalid authentication data\r\n");
    }

    #[test]
    fn auth_login_continuation_captures_username_and_password() {
        let handler = Pop3Handler::new();

        let response = block_on(handler.handle("AUTH LOGIN")).expect("AUTH LOGIN response");
        assert_eq!(response.to_bytes(), b"+ VXNlcm5hbWU6\r\n");

        let response = block_on(handler.handle("dXNlcg==")).expect("AUTH LOGIN username");
        assert_eq!(response.to_bytes(), b"+ UGFzc3dvcmQ6\r\n");

        let response = block_on(handler.handle("c2VjcmV0")).expect("AUTH LOGIN password");
        assert_eq!(response.to_bytes(), b"+OK Authentication successful\r\n");
    }

    #[test]
    fn auth_decoders_reject_control_bytes_in_credentials() {
        let plain = BASE64.encode(b"\0ali\r\nce\0pa\x1bss");
        assert!(decode_auth_plain_credentials(&plain).is_err());

        let login = BASE64.encode(b"user\r\nname\x1b");
        assert!(decode_auth_field(&login).is_err());

        let printable_plain = BASE64.encode(b"\0alice\0password");
        let (user, pass) = match decode_auth_plain_credentials(&printable_plain) {
            Ok(credentials) => credentials,
            Err(_) => panic!("printable AUTH PLAIN credentials"),
        };
        assert_eq!(safe_auth_log_text(&user), "alice");
        assert_eq!(safe_auth_log_text(&pass), "password");
    }

    #[test]
    fn unsupported_auth_mechanism_does_not_fall_through_to_success() {
        let response = block_on(Pop3Handler::new().handle("AUTH CRAM-MD5"))
            .expect("unsupported AUTH response");

        assert_eq!(
            response.to_bytes(),
            b"-ERR Unsupported authentication mechanism\r\n"
        );
    }

    #[test]
    fn auth_mechanisms_reject_extra_initial_arguments() {
        let login = Pop3Handler::new();
        let response =
            block_on(login.handle("AUTH LOGIN ignored")).expect("AUTH LOGIN extra arg response");
        assert_eq!(response.to_bytes(), b"-ERR Invalid argument\r\n");

        let next = block_on(login.handle("dXNlcg==")).expect("state should not enter LOGIN");
        assert_eq!(next.to_bytes(), b"-ERR Unknown command\r\n");

        let plain = Pop3Handler::new();
        let response =
            block_on(plain.handle("AUTH PLAIN a b")).expect("AUTH PLAIN extra arg response");
        assert_eq!(response.to_bytes(), b"-ERR Invalid argument\r\n");
    }

    #[test]
    fn pop3_command_line_rejects_embedded_crlf_injection() {
        assert_eq!(pop3_command_line("STAT\r\nUSER test"), None);
        assert_eq!(pop3_command_line("STAT\r\n"), Some("STAT"));
    }

    #[test]
    fn apop_and_mechanism_log_fields_are_single_line() {
        let user = safe_auth_log_text("ali\x1bce");
        let digest = safe_auth_log_text("di\r\ngest");
        let mechanism = safe_auth_log_text("XOAUTH\x1b2");

        assert_eq!(user, "ali ce");
        assert_eq!(digest, "di  gest");
        assert_eq!(mechanism, "XOAUTH 2");
        assert!(!user.chars().any(char::is_control));
        assert!(!digest.chars().any(char::is_control));
        assert!(!mechanism.chars().any(char::is_control));

        let long = "a".repeat(LOG_AUTH_PREVIEW_CHARS + 1);
        assert_eq!(safe_auth_log_text(&long).len(), LOG_AUTH_PREVIEW_CHARS);
    }

    #[test]
    fn auth_log_fields_reject_unicode_whitespace() {
        let logged = safe_auth_log_text("user\u{2028}name");

        assert_eq!(logged, "user name");
        assert!(!logged.chars().any(char::is_control));
    }

    #[test]
    fn retr_preserves_unicode_separators_inside_message_body() {
        let handler = Pop3Handler {
            domain: Pop3Handler::DEFAULT_DOMAIN.to_string(),
            emails: vec![Pop3Email {
                body: "Line 1\r\nLine\u{2028}2\r\n.Line 3\r\n".to_string(),
                size: 29,
            }],
            auth_state: Mutex::new(Pop3AuthState::None),
        };

        let response = handler
            .handle_stateless_command("RETR 1")
            .expect("RETR response")
            .0;
        let text = String::from_utf8(response.to_bytes()).expect("POP3 response should be UTF-8");

        assert!(text.contains("Line 1\r\nLine\u{2028}2\r\n..Line 3\r\n"));
        assert!(!text.contains("Line 1\r\nLine\r\n2"));
    }

    #[test]
    fn top_preserves_headers_and_unicode_body_lines() {
        let handler = Pop3Handler {
            domain: Pop3Handler::DEFAULT_DOMAIN.to_string(),
            emails: vec![Pop3Email {
                body: concat!(
                    "From: admin@nettrap.local\r\n",
                    "To: user@nettrap.local\r\n",
                    "Subject: Demo\r\n",
                    "\r\n",
                    "alpha\r\n",
                    "bravo\u{2028}charlie\r\n",
                    ".delta\r\n",
                )
                .to_string(),
                size: 0,
            }],
            auth_state: Mutex::new(Pop3AuthState::None),
        };

        let response = handler
            .handle_stateless_command("TOP 1 3")
            .expect("TOP response")
            .0;
        let text = String::from_utf8(response.to_bytes()).expect("POP3 response should be UTF-8");

        assert!(text.contains("From: admin@nettrap.local\r\n"));
        assert!(text.contains("To: user@nettrap.local\r\n"));
        assert!(text.contains("Subject: Demo\r\n\r\nalpha\r\n"));
        assert!(text.contains("bravo\u{2028}charlie\r\n"));
        assert!(text.contains("..delta\r\n.\r\n"));
        assert!(!text.contains("alpha\r\nbravo\r\ncharlie"));
    }

    #[test]
    fn prefixed_verbs_are_rejected() {
        let handler = Pop3Handler::new();

        let user = block_on(handler.handle(" USER alice")).expect("prefixed USER response");
        assert_eq!(user.to_bytes(), b"-ERR Unknown command\r\n");

        let nul = block_on(handler.handle("USER\0alice")).expect("nul response");
        assert_eq!(nul.to_bytes(), b"-ERR Invalid argument\r\n");

        let unicode = block_on(handler.handle("USER\u{2028}alice")).expect("unicode response");
        assert_eq!(unicode.to_bytes(), b"-ERR Invalid argument\r\n");

        let retr = block_on(handler.handle("RETRIEVE 1")).expect("RETRIEVE response");
        assert_eq!(retr.to_bytes(), b"-ERR Unknown command\r\n");

        let capa = block_on(handler.handle("CAPABILITY")).expect("CAPABILITY response");
        assert_eq!(capa.to_bytes(), b"-ERR Unknown command\r\n");
    }

    #[test]
    fn oversized_command_lines_are_rejected() {
        let handler = Pop3Handler::new();
        let command = format!("USER {}", "a".repeat(MAX_POP3_COMMAND_LINE_BYTES));

        let response = block_on(handler.handle(&command)).expect("oversized command response");

        assert_eq!(response.to_bytes(), b"-ERR Invalid argument\r\n");
    }

    #[test]
    fn stls_returns_negative_response_when_tls_upgrade_is_unavailable() {
        let response = block_on(Pop3Handler::new().handle("STLS")).expect("STLS response");

        assert!(!response.positive);
        assert_eq!(response.to_bytes(), b"-ERR TLS not available\r\n");
    }

    #[test]
    fn zero_argument_commands_reject_extra_arguments() {
        let handler = Pop3Handler::new();

        for command in [
            "STAT now", "NOOP now", "RSET now", "CAPA now", "STLS now", "QUIT now",
        ] {
            let response = block_on(handler.handle(command)).expect("POP3 response");
            assert_eq!(
                response.to_bytes(),
                b"-ERR Invalid argument\r\n",
                "{command}"
            );
        }
    }

    #[test]
    fn zero_argument_commands_reject_trailing_whitespace() {
        let handler = Pop3Handler::new();

        for command in ["STAT ", "NOOP ", "RSET ", "CAPA ", "STLS ", "QUIT "] {
            let response = block_on(handler.handle(command)).expect("POP3 response");
            assert_eq!(
                response.to_bytes(),
                b"-ERR Invalid argument\r\n",
                "{command}"
            );
        }
    }

    #[test]
    fn commands_accept_normal_crlf_termination() {
        let handler = Pop3Handler::new();

        let stat = block_on(handler.handle("STAT\r\n")).expect("STAT response");
        assert!(stat.to_bytes().starts_with(b"+OK 1 "));

        let user = block_on(handler.handle("USER alice\r\n")).expect("USER response");
        assert_eq!(user.to_bytes(), b"+OK User accepted\r\n");
    }

    #[test]
    fn commands_reject_bare_lf_termination() {
        let handler = Pop3Handler::new();

        let response = block_on(handler.handle("STAT\n")).expect("POP3 response");

        assert_eq!(response.to_bytes(), b"-ERR Invalid argument\r\n");
    }

    #[test]
    fn dele_validates_message_argument() {
        let handler = Pop3Handler::new();

        let valid = block_on(handler.handle("DELE 1")).expect("valid DELE response");
        assert_eq!(valid.to_bytes(), b"+OK Message deleted\r\n");

        let missing = block_on(handler.handle("DELE")).expect("missing DELE response");
        assert_eq!(missing.to_bytes(), b"-ERR Missing argument\r\n");

        let invalid = block_on(handler.handle("DELE abc")).expect("invalid DELE response");
        assert_eq!(invalid.to_bytes(), b"-ERR Invalid argument\r\n");

        let zero = block_on(handler.handle("DELE 0")).expect("zero DELE response");
        assert_eq!(zero.to_bytes(), b"-ERR No such message\r\n");

        let out_of_range = block_on(handler.handle("DELE 99")).expect("out of range DELE response");
        assert_eq!(out_of_range.to_bytes(), b"-ERR No such message\r\n");
    }

    #[test]
    fn top_requires_message_and_line_count_arguments() {
        let handler = Pop3Handler::new();

        let valid = block_on(handler.handle("TOP 1 2")).expect("valid TOP response");
        assert!(valid.to_bytes().starts_with(b"+OK\r\n"));

        let missing_line_count = block_on(handler.handle("TOP 1")).expect("missing TOP line count");
        assert_eq!(missing_line_count.to_bytes(), b"-ERR Missing argument\r\n");

        let invalid_line_count =
            block_on(handler.handle("TOP 1 nope")).expect("invalid TOP line count");
        assert_eq!(invalid_line_count.to_bytes(), b"-ERR Invalid argument\r\n");

        let extra_arg = block_on(handler.handle("TOP 1 2 extra")).expect("extra TOP arg");
        assert_eq!(extra_arg.to_bytes(), b"-ERR Invalid argument\r\n");
    }

    #[test]
    fn apop_requires_user_and_digest() {
        let handler = Pop3Handler::new();

        let valid = block_on(handler.handle("APOP user digest")).expect("valid APOP response");
        assert_eq!(valid.to_bytes(), b"+OK Authentication successful\r\n");

        let missing_all = block_on(handler.handle("APOP")).expect("missing APOP response");
        assert_eq!(missing_all.to_bytes(), b"-ERR Missing argument\r\n");

        let missing_digest =
            block_on(handler.handle("APOP user")).expect("missing digest response");
        assert_eq!(missing_digest.to_bytes(), b"-ERR Missing argument\r\n");
    }

    #[test]
    fn message_commands_and_apop_reject_extra_arguments() {
        let handler = Pop3Handler::new();

        let list = block_on(handler.handle("LIST 1 extra")).expect("LIST extra response");
        assert_eq!(list.to_bytes(), b"-ERR Invalid argument\r\n");

        let uidl = block_on(handler.handle("UIDL 1 extra")).expect("UIDL extra response");
        assert_eq!(uidl.to_bytes(), b"-ERR Invalid argument\r\n");

        let retr = block_on(handler.handle("RETR 1 extra")).expect("RETR extra response");
        assert_eq!(retr.to_bytes(), b"-ERR Invalid argument\r\n");

        let dele = block_on(handler.handle("DELE 1 extra")).expect("DELE extra response");
        assert_eq!(dele.to_bytes(), b"-ERR Invalid argument\r\n");

        let apop = block_on(handler.handle("APOP user digest extra")).expect("APOP extra response");
        assert_eq!(apop.to_bytes(), b"-ERR Invalid argument\r\n");
    }

    #[test]
    fn tab_separated_commands_are_rejected() {
        let handler = Pop3Handler::new();

        assert_eq!(
            block_on(handler.handle("USER\talice")).unwrap().to_bytes(),
            b"-ERR Unknown command\r\n"
        );
        assert_eq!(
            block_on(handler.handle("AUTH\tLOGIN")).unwrap().to_bytes(),
            b"-ERR Unknown command\r\n"
        );
    }

    #[test]
    fn message_number_commands_reject_signed_decimal_forms() {
        let handler = Pop3Handler::new();

        for command in [
            "LIST +1", "RETR +1", "UIDL +1", "DELE +1", "TOP +1 1", "TOP 1 +1",
        ] {
            let response = block_on(handler.handle(command)).expect("POP3 response");
            assert_eq!(
                response.to_bytes(),
                b"-ERR Invalid argument\r\n",
                "{command}"
            );
        }
    }

    #[test]
    fn user_and_pass_require_arguments() {
        let handler = Pop3Handler::new();

        let missing_user = block_on(handler.handle("USER")).expect("missing USER response");
        assert_eq!(missing_user.to_bytes(), b"-ERR Missing argument\r\n");

        let valid_user = block_on(handler.handle("USER alice")).expect("valid USER response");
        assert_eq!(valid_user.to_bytes(), b"+OK User accepted\r\n");

        let missing_pass = block_on(handler.handle("PASS")).expect("missing PASS response");
        assert_eq!(missing_pass.to_bytes(), b"-ERR Missing argument\r\n");

        let valid_pass = block_on(handler.handle("PASS secret")).expect("valid PASS response");
        assert_eq!(valid_pass.to_bytes(), b"+OK Mailbox locked and ready\r\n");
    }

    #[test]
    fn user_and_pass_reject_extra_tokens_and_tabbed_arguments() {
        let handler = Pop3Handler::new();

        for command in [
            "USER alice bob",
            "PASS secret extra",
            "USER alice\tbob",
            "PASS secret\tmore",
        ] {
            let response = block_on(handler.handle(command)).expect("POP3 response");
            assert_eq!(
                response.to_bytes(),
                b"-ERR Invalid argument\r\n",
                "{command}"
            );
        }
    }

    #[test]
    fn apop_rejects_tabbed_tokens() {
        let handler = Pop3Handler::new();

        for command in ["APOP user digest\tmore", "APOP user\tname digest"] {
            let response = block_on(handler.handle(command)).expect("POP3 response");
            assert_eq!(
                response.to_bytes(),
                b"-ERR Invalid argument\r\n",
                "{command}"
            );
        }
    }

    #[test]
    fn compressed_spaces_are_rejected() {
        let handler = Pop3Handler::new();

        let user = block_on(handler.handle("USER  alice")).expect("USER response");
        assert_eq!(user.to_bytes(), b"-ERR Invalid argument\r\n");

        let auth = block_on(handler.handle("AUTH  LOGIN")).expect("AUTH response");
        assert_eq!(auth.to_bytes(), b"-ERR Invalid argument\r\n");
    }
}
