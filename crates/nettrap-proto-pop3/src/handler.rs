use crate::prelude::*;
use async_trait::async_trait;
use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::sync::Mutex;

const MAX_AUTH_DATA_LEN: usize = 8192;

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

#[allow(dead_code)]
struct Pop3Email {
    from: String,
    subject: String,
    body: String,
    size: usize,
}

impl Pop3Handler {
    pub fn new() -> Self {
        let default_email = Pop3Email {
            from: "admin@nettrap.local".to_string(),
            subject: "Welcome to NetTrap".to_string(),
            body: "From: admin@nettrap.local\r\nTo: user@nettrap.local\r\nSubject: Welcome to NetTrap\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nContent-Type: text/plain\r\n\r\nWelcome to NetTrap POP3 honeypot.\r\n".to_string(),
            size: 0,
        };
        let size = default_email.body.len();
        Self {
            domain: "nettrap.local".to_string(),
            emails: vec![Pop3Email {
                size,
                ..default_email
            }],
            auth_state: Mutex::new(Pop3AuthState::None),
        }
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    pub fn get_welcome_banner(&self) -> String {
        format!("+OK {} NetTrap POP3 server ready\r\n", self.domain)
    }

    fn handle_with_auth_state(&self, command: &str) -> Result<Pop3Response> {
        let current_state = {
            let mut state = self
                .auth_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *state)
        };

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
                        tracing::info!("POP3 AUTH LOGIN — user: {} pass: {}", username, password);
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
        let parts: Vec<&str> = command.split_whitespace().collect();
        let verb = parts
            .first()
            .map(|part| part.to_ascii_uppercase())
            .unwrap_or_default();

        let response = if verb == "USER" {
            Pop3Response::ok("User accepted")
        } else if verb == "PASS" {
            Pop3Response::ok("Mailbox locked and ready")
        } else if verb == "STAT" {
            let total_size: usize = self.emails.iter().map(|e| e.size).sum();
            Pop3Response::ok(format!("{} {}", self.emails.len(), total_size))
        } else if verb == "LIST" {
            if parts.len() > 1 {
                if let Ok(idx) = parts[1].parse::<usize>() {
                    if idx > 0 && idx <= self.emails.len() {
                        Pop3Response::ok(format!("{} {}", idx, self.emails[idx - 1].size))
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
        } else if verb == "RETR" {
            tracing::info!("POP3 RETR command received (stateless handler)");
            if parts.len() > 1 {
                if let Ok(idx) = parts[1].parse::<usize>() {
                    if idx > 0 && idx <= self.emails.len() {
                        let email = &self.emails[idx - 1];
                        let mut response = format!("+OK {} octets\r\n", email.size);
                        response.push_str(&email.body);
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
        } else if verb == "DELE" {
            Pop3Response::ok("Message deleted")
        } else if verb == "NOOP" {
            Pop3Response::ok("")
        } else if verb == "RSET" {
            Pop3Response::ok("Maildrop has been reset")
        } else if verb == "TOP" {
            if parts.len() > 1 {
                if let Ok(idx) = parts[1].parse::<usize>() {
                    if idx > 0 && idx <= self.emails.len() {
                        let email = &self.emails[idx - 1];
                        let lines: usize = parts.get(2).and_then(|l| l.parse().ok()).unwrap_or(10);
                        let body_lines: Vec<&str> = email.body.lines().take(lines).collect();
                        let mut response = "+OK\r\n".to_string();
                        for line in body_lines {
                            response.push_str(line);
                            response.push_str("\r\n");
                        }
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
        } else if verb == "UIDL" {
            if parts.len() > 1 {
                if let Ok(idx) = parts[1].parse::<usize>() {
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
        } else if verb == "AUTH" {
            return self.handle_auth_command(&parts);
        } else if verb == "APOP" {
            let user = parts.get(1).unwrap_or(&"unknown");
            let digest = parts.get(2).unwrap_or(&"");
            tracing::info!("POP3 APOP — user: {} digest: {}", user, digest);
            Pop3Response::ok("Authentication successful")
        } else if verb == "CAPA" {
            Pop3Response::raw(
                "+OK Capability list follows\r\nUSER\r\nTOP\r\nUIDL\r\nSASL PLAIN LOGIN\r\n.\r\n",
            )
        } else if verb == "STLS" {
            Pop3Response::err("TLS not available")
        } else if verb == "QUIT" {
            Pop3Response::ok("Goodbye")
        } else {
            Pop3Response::err("Unknown command")
        };

        Ok((response, Pop3AuthState::None))
    }

    fn handle_auth_command(&self, parts: &[&str]) -> Result<(Pop3Response, Pop3AuthState)> {
        if parts.len() <= 1 {
            return Ok((
                Pop3Response::raw("+OK\r\nPLAIN\r\nLOGIN\r\n.\r\n"),
                Pop3AuthState::None,
            ));
        }

        let mechanism = parts[1].to_ascii_uppercase();
        match mechanism.as_str() {
            "PLAIN" => {
                if let Some(data) = parts.get(2) {
                    Ok((handle_auth_plain_data(data), Pop3AuthState::None))
                } else {
                    Ok((Pop3Response::raw("+\r\n"), Pop3AuthState::AuthPlain))
                }
            }
            "LOGIN" => Ok((
                Pop3Response::raw("+ VXNlcm5hbWU6\r\n"),
                Pop3AuthState::AuthLoginUsername,
            )),
            _ => {
                tracing::info!("POP3 AUTH {} attempted", mechanism);
                Ok((
                    Pop3Response::err("Unsupported authentication mechanism"),
                    Pop3AuthState::None,
                ))
            }
        }
    }
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

fn handle_auth_plain_data(data: &str) -> Pop3Response {
    let decoded = match decode_auth_bytes(data, "POP3 AUTH PLAIN") {
        Ok(decoded) => decoded,
        Err(response) => return response,
    };

    let cred_parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
    if cred_parts.len() >= 3 {
        let user = String::from_utf8_lossy(cred_parts[1]);
        let pass = String::from_utf8_lossy(cred_parts[2]);
        tracing::info!("POP3 AUTH PLAIN — user: {} pass: {}", user, pass);
    } else if cred_parts.len() == 2 {
        let user = String::from_utf8_lossy(cred_parts[0]);
        let pass = String::from_utf8_lossy(cred_parts[1]);
        tracing::info!("POP3 AUTH PLAIN — user: {} pass: {}", user, pass);
    }

    Pop3Response::ok("Authentication successful")
}

fn decode_auth_field(data: &str) -> std::result::Result<String, Pop3Response> {
    let decoded = decode_auth_bytes(data, "POP3 AUTH LOGIN")?;
    Ok(String::from_utf8_lossy(&decoded).to_string())
}

fn decode_auth_bytes(data: &str, context: &str) -> std::result::Result<Vec<u8>, Pop3Response> {
    if data.len() > MAX_AUTH_DATA_LEN {
        tracing::warn!(
            "{}: input too long ({} bytes), rejecting",
            context,
            data.len()
        );
        return Err(Pop3Response::err("Input too long"));
    }

    let decoded = BASE64.decode(data.as_bytes()).map_err(|_| {
        tracing::warn!("{}: invalid base64 input", context);
        Pop3Response::err("Invalid authentication data")
    })?;

    if decoded.len() > MAX_AUTH_DATA_LEN {
        tracing::warn!(
            "{}: decoded data too large ({} bytes)",
            context,
            decoded.len()
        );
        return Err(Pop3Response::err("Credential data too large"));
    }

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);
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
        assert!(response.message.contains("\r\nSASL PLAIN LOGIN\r\n"));
        assert_eq!(
            response.to_bytes(),
            b"+OK Capability list follows\r\nUSER\r\nTOP\r\nUIDL\r\nSASL PLAIN LOGIN\r\n.\r\n"
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
    fn auth_plain_without_inline_data_sends_exact_continuation_prompt() {
        let handler = Pop3Handler::new();
        let response = block_on(handler.handle("AUTH PLAIN")).expect("AUTH PLAIN response");

        assert_eq!(response.to_bytes(), b"+\r\n");

        let response = block_on(handler.handle("AHVzZXIAcGFzcw==")).expect("AUTH PLAIN data");
        assert_eq!(response.to_bytes(), b"+OK Authentication successful\r\n");
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
    fn unsupported_auth_mechanism_does_not_fall_through_to_success() {
        let response = block_on(Pop3Handler::new().handle("AUTH CRAM-MD5"))
            .expect("unsupported AUTH response");

        assert_eq!(
            response.to_bytes(),
            b"-ERR Unsupported authentication mechanism\r\n"
        );
    }

    #[test]
    fn prefixed_verbs_are_rejected() {
        let handler = Pop3Handler::new();

        let retr = block_on(handler.handle("RETRIEVE 1")).expect("RETRIEVE response");
        assert_eq!(retr.to_bytes(), b"-ERR Unknown command\r\n");

        let capa = block_on(handler.handle("CAPABILITY")).expect("CAPABILITY response");
        assert_eq!(capa.to_bytes(), b"-ERR Unknown command\r\n");
    }

    #[test]
    fn stls_returns_negative_response_when_tls_upgrade_is_unavailable() {
        let response = block_on(Pop3Handler::new().handle("STLS")).expect("STLS response");

        assert!(!response.positive);
        assert_eq!(response.to_bytes(), b"-ERR TLS not available\r\n");
    }
}
