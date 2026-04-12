use once_cell::sync::Lazy;
use regex::Regex;

use crate::prelude::*;

static DETECTION_PATTERNS: Lazy<Vec<(Regex, ApplicationProtocol)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r"^GET ").expect("invalid GET regex"),
            ApplicationProtocol::Http,
        ),
        (
            Regex::new(r"^POST ").expect("invalid POST regex"),
            ApplicationProtocol::Http,
        ),
        (
            Regex::new(r"^PUT ").expect("invalid PUT regex"),
            ApplicationProtocol::Http,
        ),
        (
            Regex::new(r"^DELETE ").expect("invalid DELETE regex"),
            ApplicationProtocol::Http,
        ),
        (
            Regex::new(r"^HEAD ").expect("invalid HEAD regex"),
            ApplicationProtocol::Http,
        ),
        (
            Regex::new(r"^OPTIONS ").expect("invalid OPTIONS regex"),
            ApplicationProtocol::Http,
        ),
        (
            Regex::new(r"^HTTP/1\.").expect("invalid HTTP/1 regex"),
            ApplicationProtocol::Http,
        ),
        (
            Regex::new(r"^HTTP/2\.").expect("invalid HTTP/2 regex"),
            ApplicationProtocol::Http,
        ),
        (
            Regex::new(r"^SSH-").expect("invalid SSH regex"),
            ApplicationProtocol::Ssh,
        ),
        (
            Regex::new(r"^220 .*SMTP").expect("invalid SMTP regex"),
            ApplicationProtocol::Smtp,
        ),
        (
            Regex::new(r"^220 .*FTP").expect("invalid FTP regex"),
            ApplicationProtocol::Ftp,
        ),
        (
            Regex::new(r"^EHLO ").expect("invalid EHLO regex"),
            ApplicationProtocol::Smtp,
        ),
        (
            Regex::new(r"^HELO ").expect("invalid HELO regex"),
            ApplicationProtocol::Smtp,
        ),
        (
            Regex::new(r"^MAIL FROM:").expect("invalid MAIL FROM regex"),
            ApplicationProtocol::Smtp,
        ),
        (
            Regex::new(r"^RCPT TO:").expect("invalid RCPT TO regex"),
            ApplicationProtocol::Smtp,
        ),
    ]
});

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
            for (pattern, proto) in DETECTION_PATTERNS.iter() {
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
