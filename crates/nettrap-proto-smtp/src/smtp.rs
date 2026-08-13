use nettrap_core::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct SmtpResponse {
    pub code: u16,
    pub message: String,
    raw: bool,
}

impl SmtpResponse {
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            raw: false,
        }
    }

    pub fn greeting(domain: impl Into<String>) -> Result<Self> {
        let domain = validate_single_line_field(&domain.into())?;
        Ok(Self {
            code: 220,
            message: format!("{} NetTrap SMTP Ready", domain),
            raw: false,
        })
    }

    pub fn ok() -> Self {
        Self {
            code: 250,
            message: "OK".to_string(),
            raw: false,
        }
    }

    pub fn queued(id: impl Into<String>) -> Result<Self> {
        let id = validate_single_line_field(&id.into())?;
        Ok(Self {
            code: 250,
            message: format!("Queued as {}", id),
            raw: false,
        })
    }

    pub fn start_data() -> Self {
        Self {
            code: 354,
            message: "Start mail input; end with <CRLF>.<CRLF>".to_string(),
            raw: false,
        }
    }

    pub fn bye() -> Self {
        Self {
            code: 221,
            message: "Closing connection".to_string(),
            raw: false,
        }
    }

    pub fn message(msg: impl Into<String>) -> Self {
        Self {
            code: 250,
            message: msg.into(),
            raw: false,
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            code: 500,
            message: msg.into(),
            raw: false,
        }
    }

    /// Raw multi-line response — message already contains status codes and CRLF.
    /// `to_bytes()` emits the message directly without prepending a code.
    pub fn raw(message: impl Into<String>) -> Self {
        Self {
            code: 0,
            message: message.into(),
            raw: true,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        if self.raw {
            return self.message.clone().into_bytes();
        }
        if !(100..=599).contains(&self.code) {
            return invalid_smtp_response();
        }
        let message = safe_single_line_message(&self.message);
        format!("{} {}\r\n", self.code, message).into_bytes()
    }
}

fn invalid_smtp_response() -> Vec<u8> {
    b"500 Internal server error\r\n".to_vec()
}

fn validate_single_line_field(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed != value {
        return Err(Error::Config("invalid SMTP greeting domain".to_string()));
    }
    let value = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if value.is_empty()
        || value.chars().any(|ch| ch.is_control())
        || nettrap_core::sanitize::contains_unicode_line_separator(value)
        || !is_valid_smtp_host_name(value)
    {
        Err(Error::Config("invalid SMTP greeting domain".to_string()))
    } else {
        Ok(value.to_ascii_lowercase())
    }
}

fn is_valid_smtp_host_name(value: &str) -> bool {
    let value = if let Some(value) = value.strip_suffix('.') {
        if value.is_empty() || value.ends_with('.') {
            return false;
        }
        value
    } else {
        value
    };
    if value.is_empty() || value.len() > 253 || value.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }

    !nettrap_core::sanitize::has_numeric_domain_labels(value)
        && nettrap_core::sanitize::has_valid_domain_labels(value)
}

fn safe_single_line_message(value: &str) -> String {
    nettrap_core::sanitize::single_line(value)
}

#[cfg(test)]
mod tests {
    use super::{SmtpResponse, safe_single_line_message};

    #[test]
    fn non_raw_responses_are_single_line() {
        let response = SmtpResponse::new(250, "OK\r\n550 injected").to_bytes();
        let text = std::str::from_utf8(&response).expect("response is utf-8");

        assert_eq!(text, "250 OK  550 injected\r\n");

        let long = "a".repeat(nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS + 1);
        assert_eq!(
            safe_single_line_message(&long).len(),
            nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS
        );
    }

    #[test]
    fn non_raw_invalid_codes_fail_closed() {
        assert_eq!(
            SmtpResponse::new(99, "bad").to_bytes(),
            b"500 Internal server error\r\n"
        );
        assert_eq!(
            SmtpResponse::new(600, "bad").to_bytes(),
            b"500 Internal server error\r\n"
        );
    }

    #[test]
    fn greeting_domain_cannot_inject_lines() {
        assert!(SmtpResponse::greeting("mail.example\r\n250 injected").is_err());
    }

    #[test]
    fn greeting_domain_rejects_invalid_punctuation() {
        assert!(SmtpResponse::greeting("mail.example><injected").is_err());
    }

    #[test]
    fn greeting_domain_rejects_underscores() {
        assert!(SmtpResponse::greeting("mail_example.local").is_err());
    }

    #[test]
    fn greeting_domain_rejects_surrounding_whitespace() {
        assert!(SmtpResponse::greeting(" mail.example ").is_err());
    }

    #[test]
    fn greeting_domain_rejects_c1_controls() {
        assert!(SmtpResponse::greeting("mail\u{009f}.example").is_err());
    }

    #[test]
    fn greeting_domain_rejects_unicode_line_separators() {
        assert!(SmtpResponse::greeting("mail.example\u{2028}injected").is_err());
    }

    #[test]
    fn greeting_domain_rejects_empty_labels() {
        assert!(SmtpResponse::greeting("mail..example").is_err());
    }

    #[test]
    fn greeting_domain_accepts_absolute_hostnames_with_trailing_dots() {
        let response = SmtpResponse::greeting("mail.example.")
            .expect("valid SMTP greeting domain")
            .to_bytes();
        let text = std::str::from_utf8(&response).expect("response is utf-8");

        assert_eq!(text, "220 mail.example NetTrap SMTP Ready\r\n");
    }

    #[test]
    fn greeting_domain_canonicalizes_hostname_case() {
        let upper = SmtpResponse::greeting("MAIL.EXAMPLE.")
            .expect("valid SMTP greeting domain")
            .to_bytes();
        let lower = SmtpResponse::greeting("mail.example")
            .expect("valid SMTP greeting domain")
            .to_bytes();

        assert_eq!(upper, lower);
    }

    #[test]
    fn greeting_domain_rejects_overlong_host_labels() {
        let hostname = format!("{}.example.test", "a".repeat(64));
        assert!(SmtpResponse::greeting(&hostname).is_err());
    }

    #[test]
    fn greeting_domain_rejects_multiple_trailing_dots() {
        assert!(SmtpResponse::greeting("mail.example...").is_err());
    }

    #[test]
    fn greeting_domain_rejects_overlong_absolute_hostnames() {
        let hostname = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );

        assert_eq!(hostname.len(), 255);
        assert!(SmtpResponse::greeting(&hostname).is_err());
    }

    #[test]
    fn greeting_domain_rejects_numeric_hostnames() {
        assert!(SmtpResponse::greeting("12345").is_err());
        assert!(SmtpResponse::greeting("192.0.2.10").is_err());
    }

    #[test]
    fn queued_identifier_is_sanitized() {
        assert!(SmtpResponse::queued("  queue-01\r\n550 injected  ").is_err());
    }

    #[test]
    fn queued_identifier_accepts_safe_values() {
        let response = SmtpResponse::queued("queue-01")
            .expect("valid queued identifier")
            .to_bytes();
        let text = std::str::from_utf8(&response).expect("response is utf-8");

        assert_eq!(text, "250 Queued as queue-01\r\n");
    }

    #[test]
    fn queued_identifier_rejects_unicode_line_separators() {
        assert!(SmtpResponse::queued("queue-01\u{2029}injected").is_err());
    }

    #[test]
    fn raw_responses_preserve_preformatted_bytes() {
        let response = SmtpResponse::raw("250-First line\r\n250 Second line\r\n").to_bytes();

        assert_eq!(response, b"250-First line\r\n250 Second line\r\n");
    }

    #[test]
    fn zero_code_without_raw_fails_closed() {
        let response = SmtpResponse {
            code: 0,
            message: "250-Feature list\r\n250 End".to_string(),
            raw: false,
        }
        .to_bytes();

        assert_eq!(response, b"500 Internal server error\r\n");
    }
}
