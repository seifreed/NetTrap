use std::ffi::OsStr;

use rand::Rng;

pub fn resolve_service_name(input: &str) -> String {
    if input == "!hostname" || input == "!gethostname" {
        hostname::get()
            .ok()
            .as_deref()
            .map(resolve_hostname_service_name)
            .unwrap_or_else(|| "nettrap.local".to_string())
    } else if input == "!random" {
        let mut rng = rand::rng();
        let len = rng.random_range(5..=12);
        let name: String = (0..len)
            .map(|_| rng.random_range(b'a'..=b'z') as char)
            .collect();
        format!("{}.local", name)
    } else {
        sanitize_service_name(input)
    }
}

pub(crate) fn is_usable_service_name_input(input: &str) -> bool {
    matches!(input, "!hostname" | "!gethostname" | "!random") || is_valid_service_name(input)
}

pub fn resolve_hostname_service_name(hostname: &OsStr) -> String {
    hostname
        .to_str()
        .map(sanitize_service_name)
        .unwrap_or_else(|| "nettrap.local".to_string())
}

fn sanitize_service_name(input: &str) -> String {
    if input.trim_matches([' ', '\t']) != input {
        return "nettrap.local".to_string();
    }

    let value = input.strip_suffix('.').unwrap_or(input);
    if value.is_empty()
        || nettrap_core::sanitize::contains_unicode_line_separator(value)
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        || !is_valid_service_name(value)
    {
        "nettrap.local".to_string()
    } else {
        value.to_ascii_lowercase()
    }
}

fn is_valid_service_name(value: &str) -> bool {
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
        && nettrap_core::sanitize::has_valid_domain_labels(value)
        && !value
            .split('.')
            .all(|label| label.chars().all(|ch| ch.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn test_resolve_hostname() {
        let result = resolve_service_name("!hostname");
        assert!(!result.is_empty());
        assert_ne!(result, "nettrap.local");
    }

    #[cfg(unix)]
    #[test]
    fn resolve_hostname_service_name_falls_back_for_non_utf8_hostnames() {
        let hostname = OsString::from_vec(b"nettrap-\xff".to_vec());

        assert_eq!(resolve_hostname_service_name(&hostname), "nettrap.local");
    }

    #[test]
    fn test_resolve_random() {
        let result = resolve_service_name("!random");
        assert!(result.ends_with(".local"));
    }

    #[test]
    fn test_resolve_domain() {
        assert_eq!(resolve_service_name("example.com"), "example.com");
        assert_eq!(resolve_service_name("mail.example.com"), "mail.example.com");
    }

    #[test]
    fn test_resolve_domain_with_spaces() {
        assert_eq!(resolve_service_name("example.com extra"), "nettrap.local");
    }

    #[test]
    fn test_resolve_domain_rejects_ascii_padding() {
        assert_eq!(resolve_service_name(" example.com "), "nettrap.local");
    }

    #[test]
    fn service_names_are_single_safe_tokens() {
        assert_eq!(
            resolve_service_name("myserver\r\n250 injected"),
            "nettrap.local"
        );
        assert_eq!(resolve_service_name("myserver\x1b[31m"), "nettrap.local");
        assert_eq!(resolve_service_name("  example.com extra"), "nettrap.local");
        assert_eq!(resolve_service_name("\r\n"), "nettrap.local");
    }

    #[test]
    fn service_names_reject_unicode_whitespace_padding() {
        assert_eq!(resolve_service_name("\u{00a0}example.com"), "nettrap.local");
    }

    #[test]
    fn service_names_reject_c1_controls() {
        assert_eq!(resolve_service_name("example\u{009f}.com"), "nettrap.local");
    }

    #[test]
    fn test_resolve_domain_rejects_empty_labels() {
        assert_eq!(resolve_service_name(".example"), "nettrap.local");
        assert_eq!(resolve_service_name("mail..example"), "nettrap.local");
    }

    #[test]
    fn test_resolve_domain_accepts_absolute_hostnames_with_trailing_dots() {
        assert_eq!(resolve_service_name("example."), "example");
    }

    #[test]
    fn test_resolve_domain_canonicalizes_hostname_case() {
        assert_eq!(resolve_service_name("EXAMPLE."), "example");
    }

    #[test]
    fn test_resolve_domain_rejects_overlong_host_labels() {
        let hostname = format!("{}.example.test", "a".repeat(64));

        assert_eq!(resolve_service_name(&hostname), "nettrap.local");
    }

    #[test]
    fn test_resolve_domain_rejects_multiple_trailing_dots() {
        assert_eq!(resolve_service_name("example..."), "nettrap.local");
    }

    #[test]
    fn test_resolve_domain_rejects_underscores() {
        assert_eq!(resolve_service_name("mail_example.local"), "nettrap.local");
    }

    #[test]
    fn test_resolve_domain_rejects_all_numeric_hostnames() {
        assert_eq!(resolve_service_name("12345"), "nettrap.local");
        assert_eq!(resolve_service_name("192.0.2.10"), "nettrap.local");
    }

    #[test]
    fn test_resolve_domain_rejects_dashed_label_edges() {
        assert_eq!(resolve_service_name("bad-.example"), "nettrap.local");
        assert_eq!(resolve_service_name("-bad.example"), "nettrap.local");
    }

    #[test]
    fn test_resolve_plain() {
        assert_eq!(resolve_service_name("localhost"), "localhost");
        assert_eq!(resolve_service_name("myserver"), "myserver");
    }
}
