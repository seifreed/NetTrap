#[derive(Debug, Clone)]
pub struct SmtpResponse {
    pub code: u16,
    pub message: String,
}

impl SmtpResponse {
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn greeting(domain: impl Into<String>) -> Self {
        Self {
            code: 220,
            message: format!("{} NetTrap SMTP Ready", domain.into()),
        }
    }

    pub fn ok() -> Self {
        Self {
            code: 250,
            message: "OK".to_string(),
        }
    }

    pub fn queued(id: impl Into<String>) -> Self {
        Self {
            code: 250,
            message: format!("Queued as {}", id.into()),
        }
    }

    pub fn start_data() -> Self {
        Self {
            code: 354,
            message: "Start mail input; end with <CRLF>.<CRLF>".to_string(),
        }
    }

    pub fn bye() -> Self {
        Self {
            code: 221,
            message: "Closing connection".to_string(),
        }
    }

    pub fn message(msg: impl Into<String>) -> Self {
        Self {
            code: 250,
            message: msg.into(),
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            code: 500,
            message: msg.into(),
        }
    }

    /// Raw multi-line response — message already contains status codes and CRLF.
    /// `to_bytes()` emits the message directly without prepending a code.
    pub fn raw(message: impl Into<String>) -> Self {
        Self {
            code: 0,
            message: message.into(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        if self.code == 0 {
            // Raw response: message already contains codes and formatting
            format!("{}\r\n", self.message).into_bytes()
        } else {
            format!("{} {}\r\n", self.code, self.message).into_bytes()
        }
    }
}
