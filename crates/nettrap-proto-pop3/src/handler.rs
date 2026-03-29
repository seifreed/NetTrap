use async_trait::async_trait;
use crate::prelude::*;

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
            emails: vec![Pop3Email { size, ..default_email }],
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
    fn default() -> Self { Self::new() }
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
            Ok(Pop3Response::ok(format!("{} {}", self.emails.len(), total_size)))
        } else if upper.starts_with("LIST") {
            if parts.len() > 1 {
                if let Ok(idx) = parts[1].parse::<usize>() {
                    if idx > 0 && idx <= self.emails.len() {
                        Ok(Pop3Response::ok(format!("{} {}", idx, self.emails[idx - 1].size)))
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
                Ok(Pop3Response { positive: true, message: response })
            }
        } else if upper.starts_with("RETR") {
            if parts.len() > 1 {
                if let Ok(idx) = parts[1].parse::<usize>() {
                    if idx > 0 && idx <= self.emails.len() {
                        let email = &self.emails[idx - 1];
                        let mut response = format!("+OK {} octets\r\n", email.size);
                        response.push_str(&email.body);
                        response.push_str(".\r\n");
                        Ok(Pop3Response { positive: true, message: response })
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
                        let mut response = format!("+OK\r\n");
                        for line in body_lines {
                            response.push_str(line);
                            response.push_str("\r\n");
                        }
                        response.push_str(".\r\n");
                        Ok(Pop3Response { positive: true, message: response })
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
                let mut response = format!("+OK\r\n");
                for i in 0..self.emails.len() {
                    response.push_str(&format!("{} nettrap-msg-{}\r\n", i + 1, i + 1));
                }
                response.push_str(".\r\n");
                Ok(Pop3Response { positive: true, message: response })
            }
        } else if upper.starts_with("CAPA") {
            let response = "+OK Capability list follows\r\nUSER\r\nTOP\r\nUIDL\r\nSTLS\r\n.\r\n".to_string();
            Ok(Pop3Response { positive: true, message: response })
        } else if upper.starts_with("STLS") {
            Ok(Pop3Response::ok("Begin TLS negotiation"))
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
