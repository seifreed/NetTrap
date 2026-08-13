use serde::{Deserialize, Serialize};

const IRC_MAX_MESSAGE_BYTES: usize = 512;
const IRC_LINE_TERMINATOR_BYTES: usize = 2;
const IRC_MAX_MESSAGE_CORE_BYTES: usize = IRC_MAX_MESSAGE_BYTES - IRC_LINE_TERMINATOR_BYTES;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum IrcBanner {
    #[default]
    Generic,
    DebianIrcd,
    Custom(String),
}

impl IrcBanner {
    pub fn get_banner(&self, server_name: &str) -> String {
        self.get_banner_at(server_name, chrono::Utc::now())
    }

    pub fn get_banner_at(&self, server_name: &str, now: chrono::DateTime<chrono::Utc>) -> String {
        let server_name = safe_irc_server_name(server_name);
        let server_name = server_name.as_str();
        match self {
            IrcBanner::Generic => format!(
                ":{}  NOTICE AUTH :*** Looking up your hostname...\r\n:{}  NOTICE AUTH :*** Found your hostname\r\n",
                server_name, server_name
            ),
            IrcBanner::DebianIrcd => format!(
                ":{}  NOTICE AUTH :*** Looking up your hostname...\r\n:{}  NOTICE AUTH :*** Checking Ident\r\n:{}  NOTICE AUTH :*** Found your hostname\r\n:{}  NOTICE AUTH :*** No Ident response\r\n",
                server_name, server_name, server_name, server_name
            ),
            IrcBanner::Custom(banner) => {
                let expanded = expand_banner_tokens_at(banner, server_name, now);
                format!("{}\r\n", safe_irc_custom_banner(&expanded, server_name))
            }
        }
    }
}

/// Expand banner template tokens in a custom IRC banner.
///
/// Mirrors the FTP emulator's `format_banner`: `{servername}` and `{tz}` (UTC)
/// are substituted and `strftime` `%`-specifiers are rendered against the
/// current local time, so banners reflect live values instead of frozen
/// placeholders. The result is still passed through [`safe_irc_custom_banner`],
/// so expansion cannot introduce IRC line injection; an invalid `strftime`
/// specifier leaves the text literal rather than aborting.
fn expand_banner_tokens_at(
    template: &str,
    server_name: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let mut out = template.to_string();
    if out.contains('{') {
        out = out
            .replace("{servername}", server_name)
            .replace("{tz}", "UTC");
    }
    if out.contains('%') {
        let fmt = out.clone();
        match std::panic::catch_unwind(move || {
            now.with_timezone(&chrono::Local).format(&fmt).to_string()
        }) {
            Ok(rendered) => out = rendered,
            Err(_) => {
                tracing::warn!("Invalid strftime specifier in IRC banner, leaving text literal");
            }
        }
    }
    out
}

fn safe_irc_server_name(value: &str) -> String {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty()
        || nettrap_core::sanitize::contains_line_separator(value)
        || value.chars().next().is_some_and(char::is_whitespace)
        || value.chars().last().is_some_and(char::is_whitespace)
        || value.chars().any(|ch| ch.is_control())
        || !is_valid_irc_host_name(value)
    {
        "irc.nettrap.local".to_string()
    } else {
        value.to_ascii_lowercase()
    }
}

fn is_valid_irc_host_name(value: &str) -> bool {
    let value = if let Some(value) = value.strip_suffix('.') {
        if value.is_empty() || value.ends_with('.') {
            return false;
        }
        value
    } else {
        value
    };
    !value.is_empty()
        && value.len() <= 253
        && value.parse::<std::net::IpAddr>().is_err()
        && !nettrap_core::sanitize::has_numeric_domain_labels(value)
        && nettrap_core::sanitize::has_valid_domain_labels(value)
}

fn safe_irc_custom_banner(value: &str, server_name: &str) -> String {
    let mut safe = String::new();
    for ch in value.chars() {
        if matches!(ch, '\r' | '\n') {
            break;
        }
        let ch = if ch.is_control()
            || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}')
            || (ch.is_whitespace() && ch != ' ')
        {
            ' '
        } else {
            ch
        };
        if safe.len() + ch.len_utf8() > IRC_MAX_MESSAGE_CORE_BYTES {
            break;
        }
        safe.push(ch);
    }
    if safe.trim().is_empty() {
        format!(
            ":{}  NOTICE AUTH :*** Looking up your hostname...",
            server_name
        )
    } else {
        safe
    }
}

fn is_valid_irc_message(message: &str) -> bool {
    let Some(core) = message.strip_suffix("\r\n") else {
        return false;
    };
    !core.is_empty()
        && message.len() <= IRC_MAX_MESSAGE_BYTES
        && !nettrap_core::sanitize::contains_line_separator(core)
        && !core.chars().any(|ch| ch.is_control())
}

pub struct IrcResponse {
    pub messages: Vec<String>,
}

impl Default for IrcResponse {
    fn default() -> Self {
        Self::new()
    }
}

impl IrcResponse {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    pub fn single(msg: impl Into<String>) -> Self {
        Self {
            messages: vec![msg.into()],
        }
    }

    pub fn add(&mut self, msg: impl Into<String>) {
        self.messages.push(msg.into());
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        if self
            .messages
            .iter()
            .any(|message| !is_valid_irc_message(message))
        {
            return Vec::new();
        }
        self.messages.join("").into_bytes()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{IrcBanner, IrcResponse};

    #[test]
    fn generated_banner_server_name_cannot_inject_lines() {
        let banner = IrcBanner::Generic.get_banner("irc.example\r\n:evil NOTICE AUTH :owned");

        assert!(banner.starts_with(":irc.nettrap.local  NOTICE AUTH"));
        assert!(banner.contains(":irc.nettrap.local  NOTICE AUTH"));
        assert!(!banner.contains(":evil"));
        assert_eq!(banner.matches("\r\n").count(), 2);
    }

    #[test]
    fn generated_banner_server_name_rejects_invalid_punctuation() {
        let banner = IrcBanner::Generic.get_banner("irc.example><injected");

        assert!(banner.starts_with(":irc.nettrap.local  NOTICE AUTH"));
    }

    #[test]
    fn generated_banner_server_name_rejects_empty_labels() {
        let banner = IrcBanner::Generic.get_banner("irc..example");

        assert!(banner.starts_with(":irc.nettrap.local  NOTICE AUTH"));
    }

    #[test]
    fn generated_banner_server_name_rejects_numeric_hostnames() {
        for hostname in ["12345", "192.0.2.10", "0.0.0.0"] {
            let banner = IrcBanner::Generic.get_banner(hostname);

            assert!(
                banner.starts_with(":irc.nettrap.local  NOTICE AUTH"),
                "{hostname}"
            );
        }
    }

    #[test]
    fn generated_banner_server_name_accepts_absolute_hostnames_with_trailing_dots() {
        let banner = IrcBanner::Generic.get_banner("irc.example.net.");

        assert!(banner.starts_with(":irc.example.net  NOTICE AUTH"));
    }

    #[test]
    fn generated_banner_server_name_canonicalizes_hostname_case() {
        let upper = IrcBanner::Generic.get_banner("IRC.EXAMPLE.NET.");
        let lower = IrcBanner::Generic.get_banner("irc.example.net");

        assert_eq!(upper, lower);
    }

    #[test]
    fn generated_banner_server_name_rejects_overlong_host_labels() {
        let hostname = format!("{}.example.test", "a".repeat(64));
        let banner = IrcBanner::Generic.get_banner(&hostname);

        assert!(banner.starts_with(":irc.nettrap.local  NOTICE AUTH"));
    }

    #[test]
    fn generated_banner_server_name_rejects_multiple_trailing_dots() {
        let banner = IrcBanner::Generic.get_banner("irc.example.net...");

        assert!(banner.starts_with(":irc.nettrap.local  NOTICE AUTH"));
    }

    #[test]
    fn generated_banner_server_name_rejects_overlong_absolute_hostnames() {
        let hostname = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );

        assert_eq!(hostname.len(), 255);
        let banner = IrcBanner::Generic.get_banner(&hostname);

        assert!(banner.starts_with(":irc.nettrap.local  NOTICE AUTH"));
    }

    #[test]
    fn generated_banner_server_name_rejects_c1_controls() {
        let banner = IrcBanner::Generic.get_banner("irc\u{009f}.example");

        assert!(banner.starts_with(":irc.nettrap.local  NOTICE AUTH"));
    }

    #[test]
    fn custom_banner_expands_servername_and_date_tokens() {
        let now = chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant");
        let banner = IrcBanner::Custom(":{servername} NOTICE AUTH :est %Y".into())
            .get_banner_at("irc.example.net", now);

        assert!(banner.contains(":irc.example.net NOTICE AUTH :est"));
        assert!(banner.contains("2024"), "injected year missing: {banner:?}");
        assert!(!banner.contains('%'));
        assert!(!banner.contains("{servername}"));
    }

    #[test]
    fn custom_banner_token_expansion_cannot_inject_lines() {
        // strftime / token expansion must not reopen CRLF injection.
        let banner = IrcBanner::Custom(":{servername} NOTICE :ok\r\n:evil NOTICE :owned".into())
            .get_banner("irc.example.net");

        assert!(banner.contains(":irc.example.net NOTICE :ok"));
        assert!(!banner.contains(":evil"));
        assert_eq!(banner.matches("\r\n").count(), 1);
    }

    #[test]
    fn custom_banner_cannot_inject_lines() {
        let banner =
            IrcBanner::Custom(":irc.example NOTICE AUTH :ok\r\n:evil NOTICE AUTH :owned".into())
                .get_banner("irc.nettrap.local");

        assert!(banner.contains(":irc.example NOTICE AUTH :ok"));
        assert!(!banner.contains(":evil"));
        assert_eq!(banner.matches("\r\n").count(), 1);
    }

    #[test]
    fn custom_banner_rejects_unicode_whitespace() {
        let banner = IrcBanner::Custom(":irc.example NOTICE AUTH :ok\u{2028}:evil".into())
            .get_banner("irc.nettrap.local");

        assert!(banner.contains(":irc.example NOTICE AUTH :ok :evil"));
        assert!(!banner.contains('\u{2028}'));
    }

    #[test]
    fn custom_banner_rejects_unicode_whitespace_padding() {
        let banner = IrcBanner::Custom("\u{00a0}:irc.example NOTICE AUTH :ok\u{00a0}".into())
            .get_banner("irc.nettrap.local");

        assert!(banner.contains(" :irc.example NOTICE AUTH :ok "));
    }

    #[test]
    fn custom_banner_preserves_ascii_padding() {
        let banner = IrcBanner::Custom("  :irc.example NOTICE AUTH :ok  ".into())
            .get_banner("irc.nettrap.local");

        assert!(banner.contains("  :irc.example NOTICE AUTH :ok  "));
        assert!(!banner.contains("irc.nettrap.local  NOTICE AUTH :ok"));
    }

    #[test]
    fn custom_banner_stays_within_irc_line_limit_on_utf8_boundary() {
        let banner = IrcBanner::Custom("é".repeat(300)).get_banner("irc.nettrap.local");

        assert!(banner.ends_with("\r\n"));
        assert!(banner.len() <= 512);
        assert!(std::str::from_utf8(banner.as_bytes()).is_ok());
    }

    #[test]
    fn response_serializer_rejects_mutated_message_lines() {
        let mut response = IrcResponse::single(":irc.example 001 guest :Welcome\r\n");
        response.messages[0].push_str(":evil NOTICE AUTH :owned\r\n");

        assert!(response.to_bytes().is_empty());
    }

    #[test]
    fn response_serializer_rejects_overlong_message_lines() {
        let response = IrcResponse::single(format!(":{}\r\n", "a".repeat(511)));

        assert!(response.to_bytes().is_empty());
    }
}
