use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::{LOG_AUTH_PREVIEW_CHARS, MAX_AUTH_DATA_LEN, MAX_SMTP_COMMAND_LINE_BYTES};
use crate::prelude::*;

pub(crate) fn generate_cram_challenge(now: chrono::DateTime<chrono::Utc>) -> String {
    use rand::Rng;

    let mut rng = rand::rng();
    let random_part: u64 = rng.random();
    let timestamp = now.timestamp();
    format!("<{}.{}@nettrap.local>", random_part, timestamp)
}

/// Decode AUTH PLAIN credentials from base64
pub(crate) fn decode_auth_plain(data: &str) -> Option<(String, String)> {
    if data.is_empty()
        || data.chars().next().is_some_and(char::is_whitespace)
        || data.chars().last().is_some_and(char::is_whitespace)
    {
        return None;
    }
    let decoded = decode_auth_bytes(data, "SMTP AUTH PLAIN")?;
    // PLAIN format: [authzid]\0authcid\0passwd. Accept the legacy two-field
    // form used by some clients, but reject extra NUL-separated fields.
    let mut parts = decoded.split(|&b| b == 0);
    let first = parts.next()?;
    let second = parts.next()?;
    let third = parts.next();
    let (user, pass) = match (second, third, parts.next()) {
        (u, None, None) => (first, u),
        (u, Some(p), None) => (u, p),
        _ => return None,
    };
    let user = std::str::from_utf8(user).ok()?;
    let pass = std::str::from_utf8(pass).ok()?;
    if !is_valid_auth_field(user) || !is_valid_auth_field(pass) {
        return None;
    }
    let user = safe_auth_log_text(user);
    let pass = safe_auth_log_text(pass);
    Some((user, pass))
}

/// Decode AUTH LOGIN credentials (base64 encoded username or password)
pub(crate) fn decode_auth_login(data: &str) -> Option<String> {
    if data.is_empty()
        || data.chars().next().is_some_and(char::is_whitespace)
        || data.chars().last().is_some_and(char::is_whitespace)
    {
        return None;
    }
    let decoded = decode_auth_bytes(data, "SMTP AUTH LOGIN")?;
    if decoded.is_empty() {
        return None;
    }
    let decoded = std::str::from_utf8(&decoded).ok()?;
    if !is_valid_auth_field(decoded) {
        return None;
    }
    Some(safe_auth_log_text(decoded))
}

/// Handle CRAM-MD5/CRAM-SHA1 response: base64(<user> <digest>)
pub(crate) fn decode_cram_response(data: &str) -> Option<(String, String)> {
    if data.is_empty()
        || data.chars().next().is_some_and(char::is_whitespace)
        || data.chars().last().is_some_and(char::is_whitespace)
    {
        return None;
    }
    let decoded = decode_auth_bytes(data, "SMTP AUTH CRAM")?;
    let text = std::str::from_utf8(&decoded).ok()?;
    let (user, digest) = text.split_once(' ')?;
    if user.is_empty()
        || digest.is_empty()
        || user.trim() != user
        || digest.trim() != digest
        || !is_valid_cram_field(user)
        || !is_valid_cram_field(digest)
    {
        return None;
    }
    let user = safe_auth_log_text(user);
    let digest = safe_auth_log_text(digest);
    Some((user, digest))
}

pub(crate) fn verb_and_rest(command: &str) -> (&str, &str) {
    let Some(trimmed) = smtp_command_line(command) else {
        return ("", "");
    };
    match trimmed.find(' ') {
        Some(separator) => {
            let rest = &trimmed[separator..];
            if rest.starts_with("  ") {
                return ("", "");
            }
            (&trimmed[..separator], rest.trim_start_matches(' '))
        }
        None => (trimmed, ""),
    }
}

fn decode_auth_bytes(data: &str, context: &str) -> Option<Vec<u8>> {
    if data.len() > MAX_AUTH_DATA_LEN {
        tracing::warn!(
            "{}: input too long ({} bytes), rejecting",
            context,
            data.len()
        );
        return None;
    }

    let decoded = BASE64.decode(data.as_bytes()).ok()?;
    if decoded.len() > MAX_AUTH_DATA_LEN {
        tracing::warn!(
            "{}: decoded data too large ({} bytes)",
            context,
            decoded.len()
        );
        return None;
    }

    Some(decoded)
}

pub(crate) fn smtp_command_line(command: &str) -> Option<&str> {
    if command.chars().any(|ch| ch == '\0') {
        return None;
    }
    if nettrap_core::sanitize::contains_unicode_line_separator(command) {
        return None;
    }
    if let Some(line) = command.strip_suffix("\r\n") {
        if line.chars().any(|ch| matches!(ch, '\r' | '\n')) {
            return None;
        }
        return (line.len() <= MAX_SMTP_COMMAND_LINE_BYTES).then_some(line);
    }
    if command.ends_with(['\r', '\n']) {
        return None;
    }
    if command.chars().any(|ch| matches!(ch, '\r' | '\n')) {
        return None;
    }
    (command.len() <= MAX_SMTP_COMMAND_LINE_BYTES).then_some(command)
}

pub(crate) fn command_verb(command: &str) -> String {
    let (verb, _) = verb_and_rest(command);
    verb.to_ascii_uppercase()
}

pub(crate) fn has_strict_path_argument(rest: &str, keyword: &str) -> bool {
    let Some((head, after_colon)) = rest.split_once(':') else {
        return false;
    };
    if !head.eq_ignore_ascii_case(keyword) {
        return false;
    }
    // The reverse/forward-path is the first token after the colon. Optional
    // ESMTP parameters (e.g. `SIZE=1000`, which our EHLO reply advertises via
    // RFC 1870) may follow it separated by whitespace, so validate only the
    // path token rather than requiring the whole argument to be `<...>`.
    if after_colon.starts_with(char::is_whitespace) {
        return false;
    }
    if after_colon
        .chars()
        .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return false;
    }
    let parts: Vec<&str> = after_colon.split(' ').collect();
    if parts.iter().skip(1).any(|part| part.is_empty()) {
        return false;
    }
    let Some(path) = parts.into_iter().find(|part| !part.is_empty()) else {
        return false;
    };
    if after_colon
        .split(' ')
        .filter(|part| !part.is_empty())
        .skip_while(|part| *part != path)
        .skip(1)
        .any(|part| !is_esmtp_parameter(part))
    {
        return false;
    }
    if !path.starts_with('<') || !path.ends_with('>') {
        return false;
    }
    let address = &path[1..path.len() - 1];
    if keyword.eq_ignore_ascii_case("TO") && address.is_empty() {
        return false;
    }
    address.is_empty()
        || (address.trim_matches([' ', '\t']) == address
            && !address
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control()))
}

fn is_esmtp_parameter(part: &str) -> bool {
    let (keyword, value) = match part.split_once('=') {
        Some((keyword, value)) if !value.is_empty() => (keyword, value),
        _ => return false,
    };
    !keyword.is_empty()
        && keyword
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && value.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
}

pub(crate) fn invalid_auth_response() -> SmtpResponse {
    SmtpResponse::new(535, "5.7.8 Authentication credentials invalid")
}

pub(crate) fn is_known_smtp_command(command: &str) -> bool {
    matches!(
        command_verb(command).as_str(),
        "EHLO"
            | "HELO"
            | "MAIL"
            | "RCPT"
            | "DATA"
            | "RSET"
            | "NOOP"
            | "VRFY"
            | "EXPN"
            | "QUIT"
            | "HELP"
            | "AUTH"
            | "STARTTLS"
            | "X-EXPS"
            | "X-EXCH50"
            | "X-LINK2STATE"
    )
}

pub(crate) fn validate_smtp_domain(value: &str) -> Result<String> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty()
        || nettrap_core::sanitize::contains_unicode_line_separator(value)
        || value.chars().next().is_some_and(char::is_whitespace)
        || value.chars().last().is_some_and(char::is_whitespace)
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() && ch != ' ')
        || !is_valid_smtp_host_name(value)
    {
        Err(Error::Config("invalid SMTP domain".to_string()))
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

pub(crate) fn safe_auth_log_text(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_control() || (ch.is_whitespace() && ch != ' ') {
                ' '
            } else {
                ch
            }
        })
        .take(LOG_AUTH_PREVIEW_CHARS)
        .collect()
}

fn is_effectively_blank_auth_field(value: &str) -> bool {
    value.trim().is_empty()
        || value
            .chars()
            .all(|ch| ch.is_control() || ch.is_whitespace())
}

fn is_valid_auth_field(value: &str) -> bool {
    !is_effectively_blank_auth_field(value)
        && !value
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
}

fn is_valid_cram_field(value: &str) -> bool {
    !value.is_empty()
        && !value.chars().any(|ch| {
            ch.is_whitespace()
                || ch.is_control()
                || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}')
        })
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::super::MAX_SMTP_COMMAND_LINE_BYTES;
    use super::{
        decode_auth_login, decode_auth_plain, has_strict_path_argument, safe_auth_log_text,
        smtp_command_line, validate_smtp_domain, verb_and_rest,
    };

    #[test]
    fn strict_path_argument_rejects_unicode_whitespace_separators() {
        assert!(!has_strict_path_argument(
            "FROM:<a@example.test>\u{00a0}SIZE=1000",
            "FROM"
        ));
    }

    #[test]
    fn strict_path_argument_rejects_control_whitespace_in_parameters() {
        assert!(!has_strict_path_argument(
            "FROM:<a@example.test>\tSIZE=1000",
            "FROM"
        ));
        assert!(!has_strict_path_argument(
            "TO:<b@example.test> NOTIFY=SUCCESS\tORCPT=rfc822;b@example.test",
            "TO"
        ));
    }

    #[test]
    fn strict_path_argument_allows_null_reverse_path_only_for_mail_from() {
        assert!(has_strict_path_argument("FROM:<>", "FROM"));
        assert!(!has_strict_path_argument("TO:<>", "TO"));
    }

    #[test]
    fn strict_path_argument_rejects_malformed_esmtp_parameters() {
        assert!(!has_strict_path_argument("FROM:<a@example.test> =", "FROM"));
        assert!(!has_strict_path_argument(
            "FROM:<a@example.test> SIZE=",
            "FROM"
        ));
        assert!(!has_strict_path_argument(
            "FROM:<a@example.test> @=1",
            "FROM"
        ));
        assert!(has_strict_path_argument(
            "FROM:<a@example.test> SIZE=1000 BODY=8BITMIME",
            "FROM"
        ));
    }

    #[test]
    fn smtp_domain_rejects_unicode_whitespace() {
        assert!(validate_smtp_domain("mail\u{00a0}example").is_err());
    }

    #[test]
    fn smtp_domain_rejects_c1_controls() {
        assert!(validate_smtp_domain("mail\u{009f}.example").is_err());
    }

    #[test]
    fn smtp_domain_rejects_empty_labels() {
        assert!(validate_smtp_domain(".example").is_err());
        assert!(validate_smtp_domain("mail..example").is_err());
    }

    #[test]
    fn smtp_domain_rejects_dashed_label_edges() {
        assert!(validate_smtp_domain("bad-.example").is_err());
        assert!(validate_smtp_domain("-bad.example").is_err());
    }

    #[test]
    fn smtp_domain_rejects_underscores() {
        assert!(validate_smtp_domain("mail_example.local").is_err());
    }

    #[test]
    fn smtp_domain_rejects_numeric_hostnames() {
        assert!(validate_smtp_domain("12345").is_err());
        assert!(validate_smtp_domain("192.0.2.10").is_err());
    }

    #[test]
    fn smtp_domain_accepts_absolute_hostnames_with_trailing_dots() {
        assert_eq!(
            validate_smtp_domain("mail.example.").expect("valid domain"),
            "mail.example"
        );
    }

    #[test]
    fn smtp_domain_canonicalizes_hostname_case() {
        assert_eq!(
            validate_smtp_domain("MAIL.EXAMPLE.").expect("valid domain"),
            validate_smtp_domain("mail.example").expect("valid domain")
        );
    }

    #[test]
    fn smtp_domain_rejects_overlong_host_labels() {
        let hostname = format!("{}.example.test", "a".repeat(64));

        assert!(validate_smtp_domain(&hostname).is_err());
    }

    #[test]
    fn smtp_domain_rejects_multiple_trailing_dots() {
        assert!(validate_smtp_domain("mail.example...").is_err());
    }

    #[test]
    fn smtp_domain_rejects_overlong_absolute_hostnames() {
        let hostname = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );

        assert_eq!(hostname.len(), 255);
        assert!(validate_smtp_domain(&hostname).is_err());
    }

    #[test]
    fn smtp_auth_log_text_replaces_unicode_whitespace() {
        assert_eq!(safe_auth_log_text("user\u{2028}name"), "user name");
    }

    #[test]
    fn smtp_auth_decoders_reject_whitespace_only_credentials() {
        assert!(
            decode_auth_plain(&base64::engine::general_purpose::STANDARD.encode(b"\0 \0\t"))
                .is_none()
        );
        assert!(
            decode_auth_login(&base64::engine::general_purpose::STANDARD.encode(b"\t")).is_none()
        );
    }

    #[test]
    fn smtp_auth_decoders_reject_control_only_credentials() {
        assert!(
            decode_auth_plain(&base64::engine::general_purpose::STANDARD.encode(b"\0\0")).is_none()
        );
        assert!(
            decode_auth_login(&base64::engine::general_purpose::STANDARD.encode(b"\0")).is_none()
        );
    }

    #[test]
    fn smtp_command_line_rejects_oversized_lines() {
        let exact = "A".repeat(MAX_SMTP_COMMAND_LINE_BYTES);
        let oversized = "A".repeat(MAX_SMTP_COMMAND_LINE_BYTES + 1);

        assert_eq!(smtp_command_line(&exact), Some(exact.as_str()));
        assert_eq!(
            smtp_command_line(&format!("{exact}\r\n")),
            Some(exact.as_str())
        );
        assert_eq!(smtp_command_line(&oversized), None);
        assert_eq!(smtp_command_line(&format!("{oversized}\r\n")), None);
    }

    #[test]
    fn smtp_command_line_rejects_unicode_line_separators() {
        assert_eq!(
            smtp_command_line("EHLO example.test\u{2028}MAIL FROM:<a@b>"),
            None
        );
    }

    #[test]
    fn smtp_command_line_rejects_embedded_crlf_injection() {
        assert_eq!(
            smtp_command_line("EHLO example.test\r\nMAIL FROM:<a@b>"),
            None
        );
        assert_eq!(
            smtp_command_line("EHLO example.test\r\n"),
            Some("EHLO example.test")
        );
    }

    #[test]
    fn verb_and_rest_rejects_unicode_whitespace_padding() {
        assert_eq!(
            verb_and_rest(" EHLO example.test"),
            ("", "EHLO example.test")
        );
        assert_eq!(
            verb_and_rest("EHLO\u{00a0}example.test"),
            ("EHLO\u{00a0}example.test", "")
        );
    }

    #[test]
    fn verb_and_rest_rejects_invalid_command_lines() {
        assert_eq!(
            verb_and_rest("EHLO example.test\r\nMAIL FROM:<a@b>"),
            ("", "")
        );
        assert_eq!(
            verb_and_rest("EHLO example.test\u{2028}MAIL FROM:<a@b>"),
            ("", "")
        );
    }
}
