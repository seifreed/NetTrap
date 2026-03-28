use async_trait::async_trait;

use crate::prelude::*;

pub struct SmtpHandler {
    responses: SmtpResponses,
    domain: String,
}

struct SmtpResponses {
    welcome: String,
    ok: String,
    ready_for_data: String,
    goodbye: String,
}

impl SmtpResponses {
    fn new(domain: &str) -> Self {
        Self {
            welcome: format!("220 {} ESMTP NetTrap Ready", domain),
            ok: "250 OK".to_string(),
            ready_for_data: "354 End data with <CR><LF>.<CR><LF>".to_string(),
            goodbye: "221 Bye".to_string(),
        }
    }
}

impl SmtpHandler {
    pub fn new() -> Self {
        Self {
            responses: SmtpResponses::new("nettrap.local"),
            domain: "nettrap.local".to_string(),
        }
    }
    
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        let domain = domain.into();
        self.responses = SmtpResponses::new(&domain);
        self.domain = domain;
        self
    }
    
    pub fn domain(&self) -> &str {
        &self.domain
    }
    
    pub fn get_welcome_banner(&self) -> String {
        format!("{} ESMTP NetTrap Ready\r\n", self.domain)
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
        
        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            Ok(SmtpResponse::ok())
        } else if upper.starts_with("MAIL FROM") {
            Ok(SmtpResponse::ok())
        } else if upper.starts_with("RCPT TO") {
            Ok(SmtpResponse::ok())
        } else if upper.starts_with("DATA") {
            Ok(SmtpResponse::start_data())
        } else if upper.starts_with("QUIT") {
            Ok(SmtpResponse::bye())
        } else if upper.starts_with("RSET") {
            Ok(SmtpResponse::ok())
        } else if upper.starts_with("NOOP") {
            Ok(SmtpResponse::ok())
        } else if upper.starts_with("VRFY") {
            Ok(SmtpResponse::ok())
        } else if upper.starts_with("HELP") {
            Ok(SmtpResponse::message("250-This is NetTrap SMTP honeypot\r\n250-Commands: EHLO HELO MAIL RCPT DATA RSET NOOP QUIT"))
        } else if upper.starts_with("STARTTLS") {
            Ok(SmtpResponse::message("220 Ready to start TLS"))
        } else if upper.starts_with("AUTH") {
            Ok(SmtpResponse::error("530 Authentication required"))
        } else {
            Ok(SmtpResponse::error("500 Command not recognized"))
        }
    }
    
    fn name(&self) -> &'static str {
        "smtp"
    }
}