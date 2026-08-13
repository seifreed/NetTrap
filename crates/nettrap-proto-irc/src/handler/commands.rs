use nettrap_core::error::{Error, Result};

const IRC_MAX_TOKEN_CHARS: usize = 64;
const IRC_MAX_NETWORK_NAME_BYTES: usize = 100;
const IRC_MAX_SERVER_NAME_BYTES: usize = 179;

pub(crate) fn is_cap_ls(args: &str) -> bool {
    let mut parts = args.split(' ');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(subcommand), None, None) => subcommand.eq_ignore_ascii_case("LS"),
        (Some(subcommand), Some(version), None) => {
            subcommand.eq_ignore_ascii_case("LS") && version == "302"
        }
        _ => false,
    }
}

pub(crate) fn first_arg(args: &str) -> Option<&str> {
    args.split(' ').find(|part| !part.is_empty())
}

pub(crate) fn privmsg_parts(args: &str) -> Option<(&str, &str)> {
    let args = args.trim_matches([' ', '\t']);
    if args.is_empty() {
        return None;
    }
    let Some((target, rest)) = args.split_once(' ') else {
        if args.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
            return None;
        }
        return Some((args, ""));
    };
    if target.is_empty()
        || rest.is_empty()
        || target
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return None;
    }
    let mut prefix_len = 0usize;
    for ch in rest.chars() {
        if ch == ' ' {
            prefix_len += ch.len_utf8();
            continue;
        }
        if ch.is_whitespace() {
            return None;
        }
        break;
    }
    let message = rest[prefix_len..].trim_start_matches(' ');
    Some((target, message.strip_prefix(':').unwrap_or(message)))
}

pub(crate) fn user_args_are_valid(args: &str) -> bool {
    if args
        .chars()
        .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return false;
    }

    let parts: Vec<&str> = args.split(' ').collect();
    if parts.len() < 4 || parts.iter().take(4).any(|part| part.is_empty()) {
        return false;
    }
    let mut parts = parts.into_iter();
    let Some(user) = parts.next() else {
        return false;
    };
    let Some(mode) = parts.next() else {
        return false;
    };
    let Some(unused) = parts.next() else {
        return false;
    };
    let Some(realname) = parts.next() else {
        return false;
    };
    let realname = std::iter::once(realname)
        .chain(parts)
        .collect::<Vec<_>>()
        .join(" ");

    !user.is_empty()
        && !mode.is_empty()
        && !unused.is_empty()
        && realname.starts_with(':')
        && realname.len() > 1
}

pub(crate) fn safe_irc_token(value: &str, fallback: &str) -> String {
    if value.is_empty()
        || nettrap_core::sanitize::contains_line_separator(value)
        || value
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
    {
        return fallback.to_string();
    }
    if value.chars().count() > IRC_MAX_TOKEN_CHARS || !value.chars().all(is_irc_token_char) {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

pub(crate) fn is_valid_irc_token(value: &str) -> bool {
    value == "*"
        || (!value.is_empty()
            && value.chars().count() <= IRC_MAX_TOKEN_CHARS
            && value.chars().all(is_irc_token_char))
}

pub(crate) fn safe_irc_channel(value: &str) -> String {
    if value.is_empty()
        || nettrap_core::sanitize::contains_line_separator(value)
        || value
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
    {
        return "#nettrap".to_string();
    }
    let safe: String = value
        .chars()
        .filter(|&ch| is_irc_channel_char(ch))
        .take(64)
        .collect();
    if safe.starts_with('#') || safe.starts_with('&') {
        safe
    } else {
        "#nettrap".to_string()
    }
}

pub(crate) fn parse_irc_channel_arg(value: &str) -> Option<String> {
    let token = first_arg(value)?;
    if token
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return None;
    }
    if !token.chars().all(is_irc_channel_char) {
        return None;
    }
    if token.chars().count() > IRC_MAX_TOKEN_CHARS {
        return None;
    }
    if token.len() > 1 && (token.starts_with('#') || token.starts_with('&')) {
        Some(token.to_string())
    } else {
        None
    }
}

pub(crate) fn validate_irc_server_name(value: &str) -> Result<String> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty()
        || value.len() > IRC_MAX_SERVER_NAME_BYTES
        || nettrap_core::sanitize::contains_line_separator(value)
        || value.chars().next().is_some_and(char::is_whitespace)
        || value.chars().last().is_some_and(char::is_whitespace)
        || value.chars().any(|ch| ch.is_control())
        || !is_valid_irc_server_name(value)
    {
        Err(Error::Config("invalid IRC server name".to_string()))
    } else {
        Ok(value.to_ascii_lowercase())
    }
}

fn is_valid_irc_server_name(value: &str) -> bool {
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

pub(crate) fn validate_irc_network_name(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > IRC_MAX_NETWORK_NAME_BYTES
        || nettrap_core::sanitize::contains_line_separator(value)
        || value.chars().next().is_some_and(char::is_whitespace)
        || value.chars().last().is_some_and(char::is_whitespace)
        || value
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, ',' | ':'))
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ' ' | '.' | '-'))
    {
        Err(Error::Config("invalid IRC network name".to_string()))
    } else {
        Ok(value.to_string())
    }
}

pub(crate) fn safe_irc_trailing(value: &str, fallback: &str) -> String {
    let safe: String = value
        .chars()
        .map(|ch| {
            if ch.is_control() || (ch.is_whitespace() && ch != ' ') {
                ' '
            } else {
                ch
            }
        })
        .take(128)
        .collect();
    if safe.trim().is_empty() {
        fallback.to_string()
    } else {
        safe
    }
}

pub(crate) fn is_irc_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
            '_' | '-' | '[' | ']' | '\\' | '`' | '^' | '{' | '}' | '|'
        )
}

pub(crate) fn is_irc_channel_char(ch: char) -> bool {
    ch.is_ascii_graphic() && !matches!(ch, ',' | ':' | '\r' | '\n')
}

#[cfg(test)]
mod tests {
    use super::{
        IRC_MAX_NETWORK_NAME_BYTES, IRC_MAX_SERVER_NAME_BYTES, safe_irc_channel, safe_irc_token,
        validate_irc_network_name, validate_irc_server_name,
    };

    #[test]
    fn server_name_accepts_absolute_hostnames_with_trailing_dots() {
        assert_eq!(
            validate_irc_server_name("irc.example.").expect("valid server name"),
            "irc.example"
        );
    }

    #[test]
    fn server_name_canonicalizes_hostname_case() {
        assert_eq!(
            validate_irc_server_name("IRC.EXAMPLE.").expect("valid server name"),
            validate_irc_server_name("irc.example").expect("valid server name")
        );
    }

    #[test]
    fn server_name_rejects_overlong_host_labels() {
        let hostname = format!("{}.example.test", "a".repeat(64));

        assert!(validate_irc_server_name(&hostname).is_err());
    }

    #[test]
    fn server_name_rejects_overlong_absolute_hostnames_without_trailing_dot() {
        let hostname = "a".repeat(254);

        assert!(validate_irc_server_name(&hostname).is_err());
    }

    #[test]
    fn server_name_rejects_single_overlong_host_label() {
        let hostname = format!("{}.", "a".repeat(255));

        assert!(validate_irc_server_name(&hostname).is_err());
    }

    #[test]
    fn server_name_rejects_multiple_trailing_dots() {
        assert!(validate_irc_server_name("irc.example...").is_err());
    }

    #[test]
    fn server_name_rejects_empty_labels() {
        assert!(validate_irc_server_name("irc..example").is_err());
    }

    #[test]
    fn server_name_rejects_numeric_hostnames() {
        for hostname in ["12345", "192.0.2.10", "0.0.0.0"] {
            assert!(validate_irc_server_name(hostname).is_err(), "{hostname}");
        }
    }

    #[test]
    fn server_name_rejects_embedded_line_separators() {
        for hostname in [
            "irc.example\r\n:evil",
            "irc.example\u{2028}:evil",
            "irc.example\u{2029}:evil",
        ] {
            assert!(validate_irc_server_name(hostname).is_err(), "{hostname:?}");
        }
    }

    #[test]
    fn server_name_rejects_c1_controls() {
        assert!(validate_irc_server_name("irc\u{009f}.example").is_err());
    }

    #[test]
    fn server_name_rejects_overlong_response_budget() {
        assert!(validate_irc_server_name(&"n".repeat(IRC_MAX_SERVER_NAME_BYTES + 1)).is_err());
    }

    #[test]
    fn network_name_rejects_embedded_line_separators() {
        for name in [
            "NetTrapNet\r\n:evil 001 owned",
            "NetTrapNet\u{2028}:evil 001 owned",
            "NetTrapNet\u{2029}:evil 001 owned",
        ] {
            assert!(validate_irc_network_name(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn network_name_rejects_c1_controls() {
        assert!(validate_irc_network_name("NetTrap\u{009f}Net").is_err());
    }

    #[test]
    fn network_name_rejects_overlong_values() {
        assert!(validate_irc_network_name(&"N".repeat(IRC_MAX_NETWORK_NAME_BYTES + 1)).is_err());
    }

    #[test]
    fn token_rejects_embedded_line_separators() {
        for token in ["guest\r\nowned", "guest\u{2028}owned", "guest\u{2029}owned"] {
            assert_eq!(safe_irc_token(token, "*"), "*", "{token:?}");
        }
    }

    #[test]
    fn channel_rejects_embedded_line_separators() {
        for channel in ["#safe\r\n:evil", "#safe\u{2028}:evil", "#safe\u{2029}:evil"] {
            assert_eq!(safe_irc_channel(channel), "#nettrap", "{channel:?}");
        }
    }
}
