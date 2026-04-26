/// Syslog receiver handler (UDP/514, RFC 3164)
///
/// Receives and parses BSD-style syslog messages, decoding facility and severity.
pub struct SyslogRecvHandler;

const FACILITY_NAMES: &[&str] = &[
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4",
    "local5", "local6", "local7",
];

const SEVERITY_NAMES: &[&str] = &[
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

/// A parsed syslog message.
#[derive(Debug)]
pub struct SyslogMessage {
    pub facility: u8,
    pub severity: u8,
    pub facility_name: &'static str,
    pub severity_name: &'static str,
    pub message: String,
}

impl SyslogRecvHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse a raw syslog packet. Returns the decoded message.
    pub fn handle(&self, data: &[u8]) -> Option<SyslogMessage> {
        let text = std::str::from_utf8(data).ok()?;
        let text = text.trim_end_matches(['\r', '\n']);

        // Parse PRI: <N>
        if !text.starts_with('<') {
            tracing::debug!("Syslog: no PRI found, raw message: {}", text);
            return None;
        }
        let end = text.find('>')?;
        if end <= 1 {
            return None;
        }
        let pri_text = &text[1..end];
        if pri_text.len() > 3
            || !pri_text.bytes().all(|byte| byte.is_ascii_digit())
            || (pri_text.len() > 1 && pri_text.starts_with('0'))
        {
            return None;
        }
        let pri: u16 = pri_text.parse().ok()?;
        if pri > 191 {
            return None;
        }
        let facility = (pri >> 3) as u8;
        let severity = (pri & 0x07) as u8;

        let fac_name = FACILITY_NAMES
            .get(facility as usize)
            .copied()
            .unwrap_or("unknown");
        let sev_name = SEVERITY_NAMES
            .get(severity as usize)
            .copied()
            .unwrap_or("unknown");
        let message = text[end + 1..].to_string();

        tracing::info!(
            "Syslog: facility={} ({}) severity={} ({}) msg={}",
            facility,
            fac_name,
            severity,
            sev_name,
            message.chars().take(80).collect::<String>()
        );

        Some(SyslogMessage {
            facility,
            severity,
            facility_name: fac_name,
            severity_name: sev_name,
            message,
        })
    }
}

impl Default for SyslogRecvHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::SyslogRecvHandler;

    #[test]
    fn parses_valid_pri() {
        let message = SyslogRecvHandler::new()
            .handle(b"<13>Jan  1 00:00:00 host app: message")
            .expect("valid syslog message");

        assert_eq!(message.facility, 1);
        assert_eq!(message.severity, 5);
        assert_eq!(message.facility_name, "user");
        assert_eq!(message.severity_name, "notice");
    }

    #[test]
    fn rejects_pri_outside_rfc3164_range() {
        let handler = SyslogRecvHandler::new();

        assert!(handler.handle(b"<192>message").is_none());
        assert!(handler.handle(b"<255>message").is_none());
    }

    #[test]
    fn rejects_empty_or_non_numeric_pri() {
        let handler = SyslogRecvHandler::new();

        assert!(handler.handle(b"<>message").is_none());
        assert!(handler.handle(b"<abc>message").is_none());
        assert!(handler.handle(b"<013>message").is_none());
        assert!(handler.handle(b"<000>message").is_none());
        assert!(handler.handle(b"<0000>message").is_none());
    }

    #[test]
    fn rejects_messages_without_pri() {
        let handler = SyslogRecvHandler::new();

        assert!(handler.handle(b"plain message").is_none());
        assert!(handler.handle(b"<13 message").is_none());
    }

    #[test]
    fn preserves_message_spaces_but_strips_datagram_newline() {
        let message = SyslogRecvHandler::new()
            .handle(b"<13>  Jan  1 host app: message  \r\n")
            .expect("valid syslog message");

        assert_eq!(message.message, "  Jan  1 host app: message  ");
    }
}
