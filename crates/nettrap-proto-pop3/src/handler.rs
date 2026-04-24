use crate::prelude::*;
use async_trait::async_trait;
use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

pub struct Pop3Handler {
    domain: String,
    emails: Vec<Pop3Email>,
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
        }
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    pub fn get_welcome_banner(&self) -> String {
        format!("+OK {} NetTrap POP3 server ready\r\n", self.domain)
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
        let upper = command.to_uppercase();
        let parts: Vec<&str> = command.split_whitespace().collect();

        if upper.starts_with("USER") {
            Ok(Pop3Response::ok("User accepted"))
        } else if upper.starts_with("PASS") {
            Ok(Pop3Response::ok("Mailbox locked and ready"))
        } else if upper.starts_with("STAT") {
            let total_size: usize = self.emails.iter().map(|e| e.size).sum();
            Ok(Pop3Response::ok(format!(
                "{} {}",
                self.emails.len(),
                total_size
            )))
        } else if upper.starts_with("LIST") {
            if parts.len() > 1 {
                if let Ok(idx) = parts[1].parse::<usize>() {
                    if idx > 0 && idx <= self.emails.len() {
                        Ok(Pop3Response::ok(format!(
                            "{} {}",
                            idx,
                            self.emails[idx - 1].size
                        )))
                    } else {
                        Ok(Pop3Response::err("No such message"))
                    }
                } else {
                    Ok(Pop3Response::err("Invalid argument"))
                }
            } else {
                let mut response = format!("+OK {} messages\r\n", self.emails.len());
                for (i, email) in self.emails.iter().enumerate() {
                    response.push_str(&format!("{} {}\r\n", i + 1, email.size));
                }
                response.push_str(".\r\n");
                Ok(Pop3Response {
                    positive: true,
                    message: response,
                })
            }
        } else if upper.starts_with("RETR") {
            // Note: accepting RETR without prior USER/PASS is intentional for honeypot
            // to maximize data capture, but log it for detection
            tracing::info!("POP3 RETR command received (stateless handler)");
            if parts.len() > 1 {
                if let Ok(idx) = parts[1].parse::<usize>() {
                    if idx > 0 && idx <= self.emails.len() {
                        let email = &self.emails[idx - 1];
                        let mut response = format!("+OK {} octets\r\n", email.size);
                        response.push_str(&email.body);
                        response.push_str(".\r\n");
                        Ok(Pop3Response {
                            positive: true,
                            message: response,
                        })
                    } else {
                        Ok(Pop3Response::err("No such message"))
                    }
                } else {
                    Ok(Pop3Response::err("Invalid argument"))
                }
            } else {
                Ok(Pop3Response::err("Missing argument"))
            }
        } else if upper.starts_with("DELE") {
            Ok(Pop3Response::ok("Message deleted"))
        } else if upper.starts_with("NOOP") {
            Ok(Pop3Response::ok(""))
        } else if upper.starts_with("RSET") {
            Ok(Pop3Response::ok("Maildrop has been reset"))
        } else if upper.starts_with("TOP") {
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
                        Ok(Pop3Response {
                            positive: true,
                            message: response,
                        })
                    } else {
                        Ok(Pop3Response::err("No such message"))
                    }
                } else {
                    Ok(Pop3Response::err("Invalid argument"))
                }
            } else {
                Ok(Pop3Response::err("Missing argument"))
            }
        } else if upper.starts_with("UIDL") {
            if parts.len() > 1 {
                if let Ok(idx) = parts[1].parse::<usize>() {
                    if idx > 0 && idx <= self.emails.len() {
                        Ok(Pop3Response::ok(format!("{} nettrap-msg-{}", idx, idx)))
                    } else {
                        Ok(Pop3Response::err("No such message"))
                    }
                } else {
                    Ok(Pop3Response::err("Invalid argument"))
                }
            } else {
                let mut response = "+OK\r\n".to_string();
                for i in 0..self.emails.len() {
                    response.push_str(&format!("{} nettrap-msg-{}\r\n", i + 1, i + 1));
                }
                response.push_str(".\r\n");
                Ok(Pop3Response {
                    positive: true,
                    message: response,
                })
            }
        } else if upper.starts_with("AUTH") {
            // AUTH command — capture credentials
            const MAX_AUTH_DATA_LEN: usize = 8192; // 8KB limit for base64 input

            if parts.len() > 1 {
                let mechanism = parts[1].to_uppercase();
                match mechanism.as_str() {
                    "PLAIN" => {
                        // AUTH PLAIN <base64> or AUTH PLAIN then continuation
                        if let Some(data) = parts.get(2) {
                            // Check size limit before decoding
                            if data.len() > MAX_AUTH_DATA_LEN {
                                tracing::warn!(
                                    "POP3 AUTH PLAIN: input too long ({} bytes), rejecting",
                                    data.len()
                                );
                                return Ok(Pop3Response::err("Input too long"));
                            }

                            if let Ok(decoded) = BASE64.decode(data.as_bytes()) {
                                // Also check decoded size
                                if decoded.len() > MAX_AUTH_DATA_LEN {
                                    tracing::warn!(
                                        "POP3 AUTH PLAIN: decoded data too large ({} bytes)",
                                        decoded.len()
                                    );
                                    return Ok(Pop3Response::err("Credential data too large"));
                                }

                                let cred_parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
                                if cred_parts.len() >= 3 {
                                    // RFC 4616: \0authcid\0passwd (with optional authzid prefix)
                                    let user = String::from_utf8_lossy(cred_parts[1]);
                                    let pass = String::from_utf8_lossy(cred_parts[2]);
                                    tracing::info!(
                                        "POP3 AUTH PLAIN — user: {} pass: {}",
                                        user,
                                        pass
                                    );
                                } else if cred_parts.len() == 2 {
                                    // 2-part format: authcid\0passwd (no authzid)
                                    let user = String::from_utf8_lossy(cred_parts[0]);
                                    let pass = String::from_utf8_lossy(cred_parts[1]);
                                    tracing::info!(
                                        "POP3 AUTH PLAIN — user: {} pass: {}",
                                        user,
                                        pass
                                    );
                                }
                            }
                            Ok(Pop3Response::ok("Authentication successful"))
                        } else {
                            // Send continuation prompt
                            Ok(Pop3Response {
                                positive: true,
                                message: "+\r\n".to_string(),
                            })
                        }
                    }
                    _ => {
                        tracing::info!("POP3 AUTH {} attempted", mechanism);
                        Ok(Pop3Response::ok("Authentication successful"))
                    }
                }
            } else {
                // AUTH with no args — list mechanisms
                let response = "+OK\r\nPLAIN\r\nLOGIN\r\n.\r\n".to_string();
                Ok(Pop3Response {
                    positive: true,
                    message: response,
                })
            }
        } else if upper.starts_with("APOP") {
            // APOP <user> <digest>
            let user = parts.get(1).unwrap_or(&"unknown");
            let digest = parts.get(2).unwrap_or(&"");
            tracing::info!("POP3 APOP — user: {} digest: {}", user, digest);
            Ok(Pop3Response::ok("Authentication successful"))
        } else if upper.starts_with("CAPA") {
            let response =
                "+OK Capability list follows\r\nUSER\r\nTOP\r\nUIDL\r\nSASL PLAIN LOGIN\r\n.\r\n"
                    .to_string();
            Ok(Pop3Response {
                positive: true,
                message: response,
            })
        } else if upper.starts_with("STLS") {
            Ok(Pop3Response::err("TLS not available"))
        } else if upper.starts_with("QUIT") {
            Ok(Pop3Response::ok("Goodbye"))
        } else {
            Ok(Pop3Response::err("Unknown command"))
        }
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
    }

    #[test]
    fn stls_returns_negative_response_when_tls_upgrade_is_unavailable() {
        let response = block_on(Pop3Handler::new().handle("STLS")).expect("STLS response");

        assert!(!response.positive);
        assert_eq!(response.to_bytes(), b"-ERR TLS not available\r\n");
    }
}
