use base64::Engine as Base64Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::prelude::*;

use super::{LOG_AUTH_PREVIEW_CHARS, MAX_AUTH_DATA_LEN, REDACTED_AUTH_FIELD};

pub(crate) use nettrap_core::parse::unsigned_decimal as parse_unsigned_decimal;

pub(crate) fn validate_pop3_domain(value: &str) -> Result<String> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty()
        || nettrap_core::sanitize::contains_line_separator(value)
        || value.chars().next().is_some_and(char::is_whitespace)
        || value.chars().last().is_some_and(char::is_whitespace)
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() && ch != ' ')
        || !is_valid_pop3_host_name(value)
    {
        Err(Error::Config("invalid POP3 domain".to_string()))
    } else {
        Ok(value.to_ascii_lowercase())
    }
}

fn is_valid_pop3_host_name(value: &str) -> bool {
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

pub(crate) fn handle_auth_plain_data(data: &str) -> Pop3Response {
    let (user, pass) = match decode_auth_plain_credentials(data) {
        Ok(credentials) => credentials,
        Err(response) => return response,
    };

    tracing::debug!(
        "POP3 AUTH PLAIN — user: {} pass: {}",
        safe_auth_log_text(&user),
        safe_auth_log_text(&pass)
    );
    tracing::info!(
        "POP3 AUTH PLAIN — user: {} pass: {}",
        REDACTED_AUTH_FIELD,
        REDACTED_AUTH_FIELD
    );
    Pop3Response::ok("Authentication successful")
}

pub(crate) fn decode_auth_plain_credentials(
    data: &str,
) -> std::result::Result<(String, String), Pop3Response> {
    let decoded = decode_auth_bytes(data, "POP3 AUTH PLAIN")?;
    let mut parts = decoded.split(|&b| b == 0);
    let _authzid = parts
        .next()
        .ok_or_else(|| Pop3Response::err("Invalid authentication data"))?;
    let second = parts
        .next()
        .ok_or_else(|| Pop3Response::err("Invalid authentication data"))?;
    let pass = parts
        .next()
        .ok_or_else(|| Pop3Response::err("Invalid authentication data"))?;
    if parts.next().is_some() {
        return Err(Pop3Response::err("Invalid authentication data"));
    }
    let user = second;

    let user = std::str::from_utf8(user)
        .map_err(|_| Pop3Response::err("Invalid authentication data"))?
        .to_string();
    let pass = std::str::from_utf8(pass)
        .map_err(|_| Pop3Response::err("Invalid authentication data"))?
        .to_string();
    if !is_valid_auth_field(&user) || !is_valid_auth_field(&pass) {
        return Err(Pop3Response::err("Invalid authentication data"));
    }

    Ok((user, pass))
}

pub(crate) fn decode_auth_field(data: &str) -> std::result::Result<String, Pop3Response> {
    let decoded = decode_auth_bytes(data, "POP3 AUTH LOGIN")?;
    if decoded.is_empty() {
        return Err(Pop3Response::err("Invalid authentication data"));
    }
    let text = std::str::from_utf8(&decoded)
        .map_err(|_| Pop3Response::err("Invalid authentication data"))
        .map(|text| text.to_string())?;
    if !is_valid_auth_field(&text) {
        return Err(Pop3Response::err("Invalid authentication data"));
    }
    Ok(text)
}

pub(crate) fn decode_auth_bytes(
    data: &str,
    context: &str,
) -> std::result::Result<Vec<u8>, Pop3Response> {
    if data.len() > MAX_AUTH_DATA_LEN {
        tracing::warn!(
            "{}: input too long ({} bytes), rejecting",
            context,
            data.len()
        );
        return Err(Pop3Response::err("Input too long"));
    }

    let decoded = BASE64.decode(data.as_bytes()).map_err(|_| {
        tracing::warn!("{}: invalid base64 input", context);
        Pop3Response::err("Invalid authentication data")
    })?;

    if decoded.len() > MAX_AUTH_DATA_LEN {
        tracing::warn!(
            "{}: decoded data too large ({} bytes)",
            context,
            decoded.len()
        );
        return Err(Pop3Response::err("Credential data too large"));
    }

    Ok(decoded)
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

#[cfg(test)]
mod tests {
    use super::validate_pop3_domain;

    #[test]
    fn pop3_domain_accepts_absolute_hostnames_with_trailing_dots() {
        assert_eq!(
            validate_pop3_domain("mail.example.").expect("valid domain"),
            "mail.example"
        );
    }

    #[test]
    fn pop3_domain_canonicalizes_hostname_case() {
        assert_eq!(
            validate_pop3_domain("MAIL.EXAMPLE.").expect("valid domain"),
            validate_pop3_domain("mail.example").expect("valid domain")
        );
    }

    #[test]
    fn pop3_domain_rejects_overlong_host_labels() {
        let hostname = format!("{}.example.test", "a".repeat(64));

        assert!(validate_pop3_domain(&hostname).is_err());
    }

    #[test]
    fn pop3_domain_rejects_overlong_absolute_hostnames() {
        let hostname = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );

        assert_eq!(hostname.len(), 254);
        assert!(validate_pop3_domain(&hostname).is_err());
    }

    #[test]
    fn pop3_domain_rejects_multiple_trailing_dots() {
        assert!(validate_pop3_domain("mail.example...").is_err());
    }

    #[test]
    fn pop3_domain_rejects_empty_labels() {
        assert!(validate_pop3_domain("mail..example").is_err());
    }

    #[test]
    fn pop3_domain_rejects_underscores() {
        assert!(validate_pop3_domain("mail_example").is_err());
    }

    #[test]
    fn pop3_domain_rejects_numeric_hostnames() {
        for host in ["12345", "192.0.2.10", "0.0.0.0"] {
            assert!(validate_pop3_domain(host).is_err(), "{host}");
        }
    }

    #[test]
    fn pop3_domain_rejects_c1_controls() {
        assert!(validate_pop3_domain("mail\u{009f}.example").is_err());
    }
}
