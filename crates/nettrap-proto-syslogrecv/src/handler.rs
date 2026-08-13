/// Syslog receiver handler (UDP/514, RFC 3164)
///
/// Receives and parses BSD-style syslog messages, decoding facility and severity.
pub struct SyslogRecvHandler;

const MAX_SYSLOG_PACKET_BYTES: usize = 1024;
const DEFAULT_SYSLOG_PRI: u16 = 13;
const REDACTED_SYSLOG_MESSAGE_FIELD: &str = "***REDACTED***";

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
        if data.len() > MAX_SYSLOG_PACKET_BYTES {
            return None;
        }
        let payload = if let Some(payload) = data.strip_suffix(b"\r\n") {
            payload
        } else if data.ends_with(b"\r") || data.ends_with(b"\n") {
            return None;
        } else {
            data
        };
        if payload
            .iter()
            .any(|&byte| matches!(byte, 0 | b'\r' | b'\n'))
        {
            return None;
        }
        if std::str::from_utf8(payload)
            .is_ok_and(nettrap_core::sanitize::contains_unicode_line_separator)
        {
            return None;
        }

        let (pri, message_start) = if !payload.starts_with(b"<") {
            let text = String::from_utf8_lossy(payload);
            tracing::debug!(
                "Syslog: no PRI found, raw message: {}",
                nettrap_core::sanitize::single_line(&text)
            );
            (DEFAULT_SYSLOG_PRI, 0usize)
        } else {
            let Some(end) = payload.iter().position(|&byte| byte == b'>') else {
                let text = String::from_utf8_lossy(payload);
                tracing::debug!(
                    "Syslog: unidentifiable PRI, raw message: {}",
                    nettrap_core::sanitize::single_line(&text)
                );
                return Some(Self::message_with_default_pri(payload));
            };
            if end <= 1 {
                return Some(Self::message_with_default_pri(payload));
            }
            let pri_text = &payload[1..end];
            if pri_text.len() > 3
                || !pri_text.iter().all(|byte| byte.is_ascii_digit())
                || (pri_text.len() > 1 && pri_text.starts_with(b"0"))
            {
                return Some(Self::message_with_default_pri(payload));
            }
            let Some(pri) = std::str::from_utf8(pri_text)
                .ok()
                .and_then(|text| text.parse().ok())
            else {
                return Some(Self::message_with_default_pri(payload));
            };
            if pri > 191 {
                return Some(Self::message_with_default_pri(payload));
            }
            (pri, end + 1)
        };
        let facility = u8::try_from(pri >> 3).ok()?;
        let severity = u8::try_from(pri & 0x07).ok()?;

        let fac_name = FACILITY_NAMES
            .get(facility as usize)
            .copied()
            .unwrap_or("unknown");
        let sev_name = SEVERITY_NAMES
            .get(severity as usize)
            .copied()
            .unwrap_or("unknown");
        let message = String::from_utf8_lossy(&payload[message_start..]).into_owned();

        tracing::debug!(
            "Syslog: facility={} ({}) severity={} ({}) msg={}",
            facility,
            fac_name,
            severity,
            sev_name,
            nettrap_core::sanitize::single_line(&message)
                .chars()
                .take(80)
                .collect::<String>()
        );
        tracing::info!(
            "Syslog: facility={} ({}) severity={} ({}) msg={}",
            facility,
            fac_name,
            severity,
            sev_name,
            REDACTED_SYSLOG_MESSAGE_FIELD
        );

        Some(SyslogMessage {
            facility,
            severity,
            facility_name: fac_name,
            severity_name: sev_name,
            message,
        })
    }

    fn message_with_default_pri(payload: &[u8]) -> SyslogMessage {
        let pri = DEFAULT_SYSLOG_PRI;
        let facility = u8::try_from(pri >> 3).unwrap_or(0);
        let severity = u8::try_from(pri & 0x07).unwrap_or(0);
        let message = String::from_utf8_lossy(payload).into_owned();

        SyslogMessage {
            facility,
            severity,
            facility_name: FACILITY_NAMES[facility as usize],
            severity_name: SEVERITY_NAMES[severity as usize],
            message,
        }
    }
}

impl Default for SyslogRecvHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_SYSLOG_PACKET_BYTES, SyslogRecvHandler};

    const LOG_FIELD_PREVIEW_CHARS: usize = 240;

    #[test]
    fn parses_valid_pri() {
        let message = SyslogRecvHandler::new()
            .handle(b"<13> Jan  1 00:00:00 host app: message")
            .expect("valid syslog message");

        assert_eq!(message.facility, 1);
        assert_eq!(message.severity, 5);
        assert_eq!(message.facility_name, "user");
        assert_eq!(message.severity_name, "notice");
    }

    #[test]
    fn accepts_pri_outside_rfc3164_range_using_default_priority() {
        let handler = SyslogRecvHandler::new();

        for packet in [b"<192>message", b"<255>message"] {
            let message = handler.handle(packet).expect("default-pri syslog message");
            assert_eq!(message.facility, 1);
            assert_eq!(message.severity, 5);
            assert_eq!(message.message, String::from_utf8_lossy(packet));
        }
    }

    #[test]
    fn accepts_unidentifiable_pri_using_default_priority() {
        let handler = SyslogRecvHandler::new();
        let packets: &[&[u8]] = &[
            b"<>message",
            b"<abc>message",
            b"<013>message",
            b"<000>message",
            b"<0000>message",
        ];

        for packet in packets {
            let message = handler.handle(packet).expect("default-pri syslog message");
            assert_eq!(message.facility, 1);
            assert_eq!(message.severity, 5);
            assert_eq!(message.message, String::from_utf8_lossy(packet));
        }
    }

    #[test]
    fn accepts_messages_without_pri_and_malformed_pri_using_default_priority() {
        let handler = SyslogRecvHandler::new();
        let packets: &[&[u8]] = &[b"<13 message", b"<13", b"<999>message"];

        let message = handler.handle(b"plain message").expect("syslog message");
        assert_eq!(message.facility, 1);
        assert_eq!(message.severity, 5);
        assert_eq!(message.message, "plain message");

        for packet in packets {
            let message = handler.handle(packet).expect("default-pri syslog message");
            assert_eq!(message.facility, 1);
            assert_eq!(message.severity, 5);
            assert_eq!(message.message, String::from_utf8_lossy(packet));
        }
    }

    #[test]
    fn preserves_message_spaces_but_strips_datagram_newline() {
        let message = SyslogRecvHandler::new()
            .handle(b"<13>  Jan  1 host app: message  \r\n")
            .expect("valid syslog message");

        assert_eq!(message.message, "  Jan  1 host app: message  ");
    }

    #[test]
    fn rejects_bare_carriage_return_or_line_feed_terminators() {
        let handler = SyslogRecvHandler::new();

        assert!(handler.handle(b"<13>message\r").is_none());
        assert!(handler.handle(b"<13>message\n").is_none());
    }

    #[test]
    fn rejects_messages_with_embedded_line_breaks() {
        let handler = SyslogRecvHandler::new();

        assert!(
            handler
                .handle(b"<13> Jan  1 host app: line 1\r\nline 2")
                .is_none()
        );
    }

    #[test]
    fn rejects_messages_with_unicode_line_separators() {
        let handler = SyslogRecvHandler::new();

        for packet in [
            "<13>line\u{0085}next",
            "<13>line\u{2028}next",
            "<13>line\u{2029}next",
        ] {
            assert!(handler.handle(packet.as_bytes()).is_none(), "{packet:?}");
        }
    }

    #[test]
    fn accepts_messages_without_pri_separator_space() {
        let handler = SyslogRecvHandler::new();

        let message = handler.handle(b"<13>message").expect("syslog message");

        assert_eq!(message.message, "message");
    }

    #[test]
    fn accepts_messages_without_pri_using_default_priority() {
        let message = SyslogRecvHandler::new()
            .handle(b"Jan  1 00:00:00 host app: message")
            .expect("syslog message");

        assert_eq!(message.facility, 1);
        assert_eq!(message.severity, 5);
        assert_eq!(message.message, "Jan  1 00:00:00 host app: message");
    }

    #[test]
    fn accepts_messages_with_invalid_utf8_payload() {
        let handler = SyslogRecvHandler::new();

        let message = handler
            .handle(b"<13> Jan  1 host app: message\xfftail")
            .expect("syslog message");

        assert!(message.message.contains('�'));
        assert!(message.message.ends_with("tail"));
    }

    #[test]
    fn rejects_oversized_syslog_packets() {
        let mut packet = b"<13> ".to_vec();
        packet.extend(std::iter::repeat_n(b'a', MAX_SYSLOG_PACKET_BYTES));

        assert!(SyslogRecvHandler::new().handle(&packet).is_none());
    }

    #[test]
    fn logged_message_preview_is_single_line() {
        let message = nettrap_core::sanitize::single_line("plain\nmessage\x1b");

        assert_eq!(message, "plain message ");
        assert!(!message.chars().any(char::is_control));

        let long = "a".repeat(LOG_FIELD_PREVIEW_CHARS + 1);
        assert_eq!(
            nettrap_core::sanitize::single_line(&long).len(),
            LOG_FIELD_PREVIEW_CHARS
        );
    }
}
