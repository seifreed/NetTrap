//! Shared parsing helpers for bounded numeric protocol fields.

/// Parse an unsigned decimal value without accepting whitespace or signs.
pub fn unsigned_decimal<T: std::str::FromStr>(value: &str) -> Option<T> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

/// Parse a non-zero decimal TCP/UDP port.
pub fn nonzero_port(value: &str) -> Option<u16> {
    unsigned_decimal(value).filter(|port| *port != 0)
}

/// Identify a path beginning with a single ASCII Windows drive letter.
pub fn looks_like_windows_drive_path(value: &str) -> bool {
    let Some((drive, _)) = value.split_once(':') else {
        return false;
    };
    drive.len() == 1 && drive.as_bytes()[0].is_ascii_alphabetic()
}

/// Extract the authority from an HTTP or HTTPS absolute-form target.
pub fn absolute_http_authority(value: &str) -> Option<&str> {
    let scheme_pos = value.find("://")?;
    let scheme = &value[..scheme_pos];
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return None;
    }

    let rest = &value[scheme_pos + 3..];
    let authority = rest.split(['/', '\\', '?', '#']).next().unwrap_or(rest);
    (!authority.is_empty()).then_some(authority)
}

#[cfg(test)]
mod tests {
    use super::{
        absolute_http_authority, looks_like_windows_drive_path, nonzero_port, unsigned_decimal,
    };

    #[test]
    fn unsigned_decimal_rejects_signs_and_whitespace() {
        assert_eq!(unsigned_decimal::<u32>("42"), Some(42));
        assert_eq!(unsigned_decimal::<u32>("+42"), None);
        assert_eq!(unsigned_decimal::<u32>(" 42"), None);
    }

    #[test]
    fn nonzero_port_rejects_zero_and_overflow() {
        assert_eq!(nonzero_port("1"), Some(1));
        assert_eq!(nonzero_port("0"), None);
        assert_eq!(nonzero_port("65536"), None);
    }

    #[test]
    fn windows_drive_path_requires_one_ascii_letter_before_colon() {
        assert!(looks_like_windows_drive_path("C:\\tmp\\file"));
        assert!(looks_like_windows_drive_path("z:relative"));
        assert!(!looks_like_windows_drive_path("/tmp/file"));
        assert!(!looks_like_windows_drive_path("12:file"));
    }

    #[test]
    fn absolute_http_authority_rejects_other_schemes_and_extracts_host() {
        assert_eq!(
            absolute_http_authority("https://example.test:443/path"),
            Some("example.test:443")
        );
        assert_eq!(absolute_http_authority("ftp://example.test/file"), None);
        assert_eq!(
            absolute_http_authority("http://example.test\\path"),
            Some("example.test")
        );
    }
}
