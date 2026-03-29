/// Syslog receiver handler (UDP/514, RFC 3164)
///
/// Receives and parses BSD-style syslog messages, decoding facility and severity.
pub struct SyslogRecvHandler;

const FACILITY_NAMES: &[&str] = &[
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
    "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
    "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
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
        let text = text.trim();

        // Parse PRI: <N>
        if !text.starts_with('<') {
            tracing::debug!("Syslog: no PRI found, raw message: {}", text);
            return None;
        }
        let end = text.find('>')?;
        let pri: u8 = text[1..end].parse().ok()?;
        let facility = pri >> 3;
        let severity = pri & 0x07;

        let fac_name = FACILITY_NAMES.get(facility as usize).copied().unwrap_or("unknown");
        let sev_name = SEVERITY_NAMES.get(severity as usize).copied().unwrap_or("unknown");
        let message = text[end + 1..].to_string();

        tracing::info!(
            "Syslog: facility={} ({}) severity={} ({}) msg={}",
            facility, fac_name, severity, sev_name, message.chars().take(80).collect::<String>()
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
