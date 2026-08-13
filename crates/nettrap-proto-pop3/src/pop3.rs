pub struct Pop3Response {
    pub positive: bool,
    pub message: String,
    pub raw: Option<String>,
}

impl Pop3Response {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            positive: true,
            message: message.into(),
            raw: None,
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            positive: false,
            message: message.into(),
            raw: None,
        }
    }

    pub fn raw(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            positive: true,
            message: message.clone(),
            raw: Some(message),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        if let Some(ref raw) = self.raw {
            return raw.clone().into_bytes();
        }

        let prefix = if self.positive { "+OK" } else { "-ERR" };
        let message = safe_single_line_message(&self.message);
        format!("{} {}\r\n", prefix, message).into_bytes()
    }
}

fn safe_single_line_message(value: &str) -> String {
    nettrap_core::sanitize::single_line(value)
}

#[cfg(test)]
mod tests {
    use super::Pop3Response;

    #[test]
    fn non_raw_responses_are_single_line() {
        let response = Pop3Response::err("Invalid\r\n+OK injected").to_bytes();
        let text = std::str::from_utf8(&response).expect("response is utf-8");

        assert_eq!(text, "-ERR Invalid  +OK injected\r\n");
    }

    #[test]
    fn raw_responses_preserve_preformatted_bytes() {
        let response = Pop3Response::raw("+OK\r\nline 1\r\nline 2\r\n.\r\n").to_bytes();

        assert_eq!(response, b"+OK\r\nline 1\r\nline 2\r\n.\r\n");
    }

    #[test]
    fn non_raw_ok_and_err_are_framed() {
        assert_eq!(Pop3Response::ok("hello").to_bytes(), b"+OK hello\r\n");
        assert_eq!(Pop3Response::err("oops").to_bytes(), b"-ERR oops\r\n");
    }

    #[test]
    fn non_raw_responses_preserve_ascii_padding() {
        let response = Pop3Response::ok("  spaced  value  ").to_bytes();
        let text = std::str::from_utf8(&response).expect("response is utf-8");

        assert_eq!(text, "+OK   spaced  value  \r\n");
    }

    #[test]
    fn non_raw_responses_reject_unicode_line_separators() {
        let response = Pop3Response::err("Invalid\u{2028}injected").to_bytes();
        let text = std::str::from_utf8(&response).expect("response is utf-8");

        assert_eq!(text, "-ERR Invalid injected\r\n");
    }
}
