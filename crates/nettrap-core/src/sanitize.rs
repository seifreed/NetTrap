//! Shared text sanitization helpers for safe single-line logging.

/// Maximum characters retained when sanitizing a value for single-line logging.
pub const SINGLE_LINE_MAX_CHARS: usize = 240;

/// Replace control characters and non-ASCII whitespace with spaces, then
/// truncate to a bounded preview length. This keeps log previews single-line
/// safe even when attacker-controlled text includes Unicode separators.
pub fn single_line(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_control() || (ch.is_whitespace() && ch != ' ') {
                ' '
            } else {
                ch
            }
        })
        .take(SINGLE_LINE_MAX_CHARS)
        .collect()
}

/// Lossy-decode bytes to UTF-8 then sanitize for single-line logging.
pub fn single_line_bytes(data: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(data) {
        return single_line(text);
    }

    use std::fmt::Write as _;

    let mut rendered = String::from("hex:");
    let max_hex_bytes = SINGLE_LINE_MAX_CHARS.saturating_sub(rendered.len()) / 2;
    for byte in data.iter().take(max_hex_bytes) {
        let _ = write!(&mut rendered, "{:02x}", byte);
    }
    rendered
}

/// Render command output as a bounded, single-line UTF-8 or hexadecimal preview.
pub fn command_output_preview(output: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(output) {
        let text = text.trim();
        if !text.is_empty() && text.chars().all(|ch| !ch.is_control()) {
            return single_line(text);
        }
    }

    single_line_bytes(output)
}

/// Return `true` when text contains a Unicode line-separator character.
pub fn contains_unicode_line_separator(value: &str) -> bool {
    value
        .chars()
        .any(|ch| matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
}

/// Return `true` when text contains an ASCII or Unicode line separator.
pub fn contains_line_separator(value: &str) -> bool {
    value
        .chars()
        .any(|ch| matches!(ch, '\n' | '\r' | '\u{0085}' | '\u{2028}' | '\u{2029}'))
}

/// Return `true` when text contains a control character or line separator.
pub fn contains_line_separator_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|ch| ch.is_control() || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
}

/// Trim HTTP optional whitespace (space and horizontal tab) from both ends.
pub fn trim_http_ows_bytes(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

/// Trim ASCII spaces and horizontal tabs from both ends of text.
pub fn trim_ascii_spaces_tabs(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

/// Return `true` when a dot-separated name has non-empty labels that do not
/// start or end with `-` and stay within the DNS label length limit.
pub fn has_valid_domain_labels(value: &str) -> bool {
    !value.is_empty()
        && value.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.len() <= 63
                && label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        })
}

/// Return `true` when a dot-separated name consists only of ASCII digits.
pub fn has_numeric_domain_labels(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('.')
            .all(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Return `true` when every dot-separated label is non-empty and at most 63 bytes.
pub fn has_valid_domain_label_lengths(value: &str) -> bool {
    value
        .split('.')
        .all(|label| !label.is_empty() && label.len() <= 63)
}

/// Validate a DNS custom-response domain, including complete-label wildcards.
pub fn validate_dns_custom_response_domain(domain: &str) -> crate::error::Result<()> {
    const MAX_DOMAIN_BYTES: usize = 253;
    const MAX_LABEL_BYTES: usize = 63;

    let candidate = if let Some(candidate) = domain.strip_suffix('.') {
        if candidate.is_empty() || candidate.ends_with('.') {
            return Err(crate::error::Error::Config(
                "Invalid DNS custom response entry: domain must not be blank".to_string(),
            ));
        }
        candidate
    } else {
        domain
    };
    if candidate.is_empty() {
        return Err(crate::error::Error::Config(
            "Invalid DNS custom response entry: domain must not be blank".to_string(),
        ));
    }
    if candidate.len() > MAX_DOMAIN_BYTES {
        return Err(crate::error::Error::Config(format!(
            "Invalid DNS custom response domain '{}' exceeds size limit ({} > {} bytes)",
            domain,
            candidate.len(),
            MAX_DOMAIN_BYTES
        )));
    }
    if candidate.parse::<std::net::IpAddr>().is_ok() || has_numeric_domain_labels(candidate) {
        return Err(crate::error::Error::Config(format!(
            "Invalid DNS custom response domain '{}': must be a DNS name",
            domain
        )));
    }

    for label in candidate.split('.') {
        if label.is_empty() {
            return Err(crate::error::Error::Config(format!(
                "Invalid DNS custom response domain '{}': label must not be blank",
                domain
            )));
        }
        if label.len() > MAX_LABEL_BYTES {
            return Err(crate::error::Error::Config(format!(
                "Invalid DNS custom response domain '{}' has an oversized label ({} > {} bytes)",
                domain,
                label.len(),
                MAX_LABEL_BYTES
            )));
        }
        if label.contains('*') && label != "*" {
            return Err(crate::error::Error::Config(format!(
                "Invalid DNS custom response domain '{}': wildcard must be a complete label",
                domain
            )));
        }
        if label != "*"
            && (label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'))
        {
            return Err(crate::error::Error::Config(format!(
                "Invalid DNS custom response domain '{}': contains invalid label characters",
                domain
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        SINGLE_LINE_MAX_CHARS, command_output_preview, contains_line_separator,
        contains_line_separator_or_control, contains_unicode_line_separator,
        has_numeric_domain_labels, has_valid_domain_label_lengths, has_valid_domain_labels,
        single_line, single_line_bytes, trim_ascii_spaces_tabs, trim_http_ows_bytes,
        validate_dns_custom_response_domain,
    };

    #[test]
    fn single_line_replaces_unicode_whitespace_with_spaces() {
        let text = single_line("alpha\u{2028}beta\u{00a0}gamma");

        assert_eq!(text, "alpha beta gamma");
        assert!(!text.chars().any(char::is_control));
    }

    #[test]
    fn command_output_preview_handles_text_and_non_utf8_bytes() {
        assert_eq!(command_output_preview(b" status \n"), "status");
        assert_eq!(command_output_preview(&[0xff, b'o', b'k']), "hex:ff6f6b");
    }

    #[test]
    fn separator_helpers_cover_ascii_unicode_and_controls() {
        assert!(contains_unicode_line_separator("alpha\u{2028}beta"));
        assert!(!contains_unicode_line_separator("alpha\nbeta"));
        assert!(contains_line_separator("alpha\nbeta"));
        assert!(contains_line_separator_or_control("alpha\u{0001}beta"));
    }

    #[test]
    fn dns_custom_response_domain_validation_accepts_wildcards_and_trailing_dot() {
        assert!(validate_dns_custom_response_domain("*.example.test.").is_ok());
    }

    #[test]
    fn dns_custom_response_domain_validation_rejects_numeric_and_partial_wildcards() {
        assert!(validate_dns_custom_response_domain("192.0.2.1").is_err());
        assert!(validate_dns_custom_response_domain("*api.example.test").is_err());
    }

    #[test]
    fn trim_http_ows_bytes_removes_only_http_optional_whitespace() {
        assert_eq!(trim_http_ows_bytes(b" \tvalue\t "), b"value");
        assert_eq!(trim_http_ows_bytes(b"\nvalue\n"), b"\nvalue\n");
    }

    #[test]
    fn trim_ascii_spaces_tabs_preserves_other_whitespace() {
        assert_eq!(trim_ascii_spaces_tabs(" \tvalue\t "), "value");
        assert_eq!(trim_ascii_spaces_tabs("\nvalue\n"), "\nvalue\n");
    }

    #[test]
    fn single_line_bytes_preserves_non_utf8_as_hex() {
        assert_eq!(single_line_bytes(b"alpha\r\nbeta"), "alpha  beta");
        assert_eq!(single_line_bytes(&[0xff, 0x00, b'a']), "hex:ff0061");
    }

    #[test]
    fn single_line_bytes_bounds_non_utf8_hex_preview() {
        let mut bytes = vec![0xff; SINGLE_LINE_MAX_CHARS];
        bytes.push(b'a');

        let rendered = single_line_bytes(&bytes);

        assert!(rendered.starts_with("hex:"));
        assert!(rendered.len() <= SINGLE_LINE_MAX_CHARS);
        assert_eq!((rendered.len() - "hex:".len()) % 2, 0);
    }

    #[test]
    fn has_valid_domain_labels_rejects_empty_and_dashed_edges() {
        assert!(has_valid_domain_labels("example"));
        assert!(has_valid_domain_labels("mail.example.com"));
        assert!(!has_valid_domain_labels(".example"));
        assert!(!has_valid_domain_labels("example."));
        assert!(!has_valid_domain_labels("mail..example"));
        assert!(!has_valid_domain_labels("bad-.example"));
        assert!(!has_valid_domain_labels("-bad.example"));
        assert!(!has_valid_domain_labels("mail_example"));
        assert!(!has_valid_domain_labels(&format!(
            "{}.example.test",
            "a".repeat(64)
        )));
    }

    #[test]
    fn has_numeric_domain_labels_detects_digit_only_names() {
        assert!(has_numeric_domain_labels("12345"));
        assert!(has_numeric_domain_labels("192.0.2.10"));
        assert!(!has_numeric_domain_labels("example"));
        assert!(!has_numeric_domain_labels("example123"));
    }

    #[test]
    fn has_valid_domain_label_lengths_rejects_empty_and_overlong_labels() {
        assert!(has_valid_domain_label_lengths("mail.example"));
        assert!(!has_valid_domain_label_lengths("mail..example"));
        assert!(!has_valid_domain_label_lengths(&format!(
            "{}.example",
            "a".repeat(64)
        )));
    }
}
