use crate::prelude::*;

pub struct ProtocolDetector;

impl ProtocolDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, data: &[u8]) -> Option<ApplicationProtocol> {
        if data.is_empty() {
            return None;
        }

        if data.len() > 5 && data[0] == 0x16 && data[1] == 0x03 {
            return Some(ApplicationProtocol::Tls);
        }

        if let Ok(s) = std::str::from_utf8(data) {
            let first_line = s.lines().next().unwrap_or("").trim_end_matches('\r');

            if looks_like_http_request_line(first_line) || looks_like_http_response_line(first_line)
            {
                return Some(ApplicationProtocol::Http);
            }
            if first_line.starts_with("SSH-") {
                return Some(ApplicationProtocol::Ssh);
            }
            if looks_like_smtp_banner(first_line) || looks_like_smtp_client_command(first_line) {
                return Some(ApplicationProtocol::Smtp);
            }
            if looks_like_ftp_banner(first_line) {
                return Some(ApplicationProtocol::Ftp);
            }
        }

        None
    }

    pub fn detect_by_port(&self, port: u16, protocol: Protocol) -> ApplicationProtocol {
        ApplicationProtocol::from_port(port, protocol)
    }
}

impl Default for ProtocolDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn looks_like_http_request_line(line: &str) -> bool {
    let mut parts = line.split(' ');
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(target) = parts.next() else {
        return false;
    };
    let Some(version) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }

    matches!(
        method,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT"
    ) && !target.is_empty()
        && !target.chars().any(char::is_whitespace)
        && matches!(version, "HTTP/1.0" | "HTTP/1.1")
}

fn looks_like_http_response_line(line: &str) -> bool {
    let mut parts = line.splitn(3, ' ');
    let Some(version) = parts.next() else {
        return false;
    };
    let Some(status) = parts.next() else {
        return false;
    };

    matches!(version, "HTTP/1.0" | "HTTP/1.1")
        && status.len() == 3
        && status.bytes().all(|byte| byte.is_ascii_digit())
}

fn looks_like_smtp_banner(line: &str) -> bool {
    line.starts_with("220 ") && line.to_ascii_uppercase().contains("SMTP")
}

fn looks_like_ftp_banner(line: &str) -> bool {
    line.starts_with("220 ") && line.to_ascii_uppercase().contains("FTP")
}

fn looks_like_smtp_client_command(line: &str) -> bool {
    let Some((verb, rest)) = line.split_once(' ') else {
        return false;
    };

    match verb {
        "EHLO" | "HELO" => !rest.trim().is_empty(),
        "MAIL" => rest.trim_start().to_ascii_uppercase().starts_with("FROM:"),
        "RCPT" => rest.trim_start().to_ascii_uppercase().starts_with("TO:"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_partial_or_prefixed_protocol_markers() {
        let detector = ProtocolDetector::new();

        assert_eq!(detector.detect(b"GET "), None);
        assert_eq!(detector.detect(b"HTTP/1."), None);
        assert_eq!(detector.detect(b"EHLOXYZ example.test"), None);
        assert_eq!(detector.detect(b"EHLO "), None);
    }

    #[test]
    fn detects_well_formed_http_and_smtp_lines() {
        let detector = ProtocolDetector::new();

        assert_eq!(
            detector.detect(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
            Some(ApplicationProtocol::Http)
        );
        assert_eq!(
            detector.detect(b"HTTP/1.1 200 OK\r\n\r\n"),
            Some(ApplicationProtocol::Http)
        );
        assert_eq!(
            detector.detect(b"EHLO example.test\r\n"),
            Some(ApplicationProtocol::Smtp)
        );
        assert_eq!(
            detector.detect(b"MAIL FROM:<a@example.test>\r\n"),
            Some(ApplicationProtocol::Smtp)
        );
    }
}
