use regex::Regex;

use crate::prelude::*;

pub struct ProtocolDetector {
    patterns: Vec<(Regex, ApplicationProtocol)>,
}

impl ProtocolDetector {
    pub fn new() -> Self {
        let patterns = vec![
            (Regex::new(r"^GET ").unwrap(), ApplicationProtocol::Http),
            (Regex::new(r"^POST ").unwrap(), ApplicationProtocol::Http),
            (Regex::new(r"^PUT ").unwrap(), ApplicationProtocol::Http),
            (Regex::new(r"^DELETE ").unwrap(), ApplicationProtocol::Http),
            (Regex::new(r"^HEAD ").unwrap(), ApplicationProtocol::Http),
            (Regex::new(r"^OPTIONS ").unwrap(), ApplicationProtocol::Http),
            (Regex::new(r"^HTTP/1\.").unwrap(), ApplicationProtocol::Http),
            (Regex::new(r"^HTTP/2\.").unwrap(), ApplicationProtocol::Http),
            (Regex::new(r"^SSH-").unwrap(), ApplicationProtocol::Ssh),
            (
                Regex::new(r"^220 .*SMTP").unwrap(),
                ApplicationProtocol::Smtp,
            ),
            (Regex::new(r"^220 .*FTP").unwrap(), ApplicationProtocol::Ftp),
            (Regex::new(r"^EHLO ").unwrap(), ApplicationProtocol::Smtp),
            (Regex::new(r"^HELO ").unwrap(), ApplicationProtocol::Smtp),
            (
                Regex::new(r"^MAIL FROM:").unwrap(),
                ApplicationProtocol::Smtp,
            ),
            (Regex::new(r"^RCPT TO:").unwrap(), ApplicationProtocol::Smtp),
        ];

        Self { patterns }
    }

    pub fn detect(&self, data: &[u8]) -> Option<ApplicationProtocol> {
        if data.is_empty() {
            return None;
        }

        if data.len() > 5 && data[0] == 0x16 && data[1] <= 0x03 {
            return Some(ApplicationProtocol::Tls);
        }

        if let Ok(s) = std::str::from_utf8(data) {
            for (pattern, proto) in &self.patterns {
                if pattern.is_match(s) {
                    return Some(*proto);
                }
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
