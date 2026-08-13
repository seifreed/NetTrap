/// Common file extensions whose trailing label the domain regex would otherwise
/// misread as a TLD — e.g. an HTTP request line like `GET /payload.exe` makes
/// `payload.exe` look like a domain. A honeypot fetches these constantly
/// (malware downloads, archives, documents), so leaking them as "C2 domains"
/// floods the IOC stream with false positives. Lowercased; matched against the
/// final label only.
///
/// Deliberately excludes extensions that are also delegated TLDs (`.com`,
/// `.app`, `.dev`, `.zip`, `.mov`, `.sh`, `.box`, `.page`, …) — dropping those
/// would discard real C2 domains, which is worse than an occasional false
/// positive. When an extension collides with a TLD we keep the match.
const NON_DOMAIN_FINAL_LABELS: &[&str] = &[
    "exe", "dll", "bin", "sys", "msi", "bat", "cmd", "ps1", "vbs", "jar", "apk", "elf", "dylib",
    "scr", "cpl", "ocx", "msc", "lnk", // Archives
    "rar", "tar", "gz", "tgz", "bz2", "xz", "iso", "cab", "7z", "deb", "rpm", "pdf", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "rtf", "csv", "txt", "xml", "htm", "css",
    "jsp", // Media / images
    "jpg", "jpeg", "gif", "bmp", "svg", "ico", "mp3", "mp4", "avi", "wav", "dat", "tmp", "log",
    "sqlite", "pem", "crt", "der",
];

/// Normalize a regex-matched domain for IOC reporting.
///
/// Strips a leading `www.` so a C2 domain like `www.evil-c2.com` is recorded
/// as `evil-c2.com` instead of being silently discarded, filters out
/// internal-only suffixes, and drops matches whose final label is a known file
/// extension (so request paths like `/payload.exe` are not misreported as
/// domains). Returns the domain to record, or `None` to drop it.
pub fn normalize_ioc_domain(domain: &str) -> Option<String> {
    let normalized = domain.to_ascii_lowercase();
    let candidate = match normalized.strip_prefix("www.") {
        // Only strip `www.` when the remainder is still a multi-label domain;
        // a degenerate match like `www.com` is kept verbatim rather than
        // reduced to a bare TLD.
        Some(rest) if rest.contains('.') => rest,
        _ => normalized.as_str(),
    };
    let candidate = if let Some(candidate) = candidate.strip_suffix('.') {
        if candidate.is_empty() || candidate.ends_with('.') {
            return None;
        }
        candidate
    } else {
        candidate
    };
    if candidate == "localhost"
        || candidate.ends_with(".local")
        || candidate.ends_with(".localhost")
    {
        return None;
    }
    if let Some(final_label) = candidate.rsplit('.').next() {
        let final_label = final_label.to_ascii_lowercase();
        if NON_DOMAIN_FINAL_LABELS.contains(&final_label.as_str()) {
            return None;
        }
    }
    if candidate
        .split('.')
        .all(|label| label.chars().all(|ch| ch.is_ascii_digit()))
    {
        return None;
    }
    if candidate.len() > 253 || !nettrap_core::sanitize::has_valid_domain_labels(candidate) {
        return None;
    }
    Some(candidate.to_string())
}

/// Returns true when `ip` is a routable external IPv4 address worth recording
/// as an IOC. Replaces ad-hoc string-prefix matching with real classification
/// so private, loopback, link-local, multicast, broadcast, documentation,
/// special-purpose and unspecified addresses are excluded instead of leaking as
/// "external".
pub fn is_external_ipv4(ip: &str) -> bool {
    match ip.parse::<std::net::Ipv4Addr>() {
        Ok(addr) => {
            !addr.is_private()
                && !addr.is_loopback()
                && !addr.is_link_local()
                && !addr.is_broadcast()
                && !addr.is_documentation()
                && !addr.is_unspecified()
                && !addr.is_multicast()
                && !is_special_purpose_ipv4(addr)
        }
        Err(_) => false,
    }
}

fn is_special_purpose_ipv4(addr: std::net::Ipv4Addr) -> bool {
    let [a, b, _, _] = addr.octets();

    a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0)
        || (a == 198 && (18..=19).contains(&b))
        || a >= 240
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn www_prefixed_domains_are_kept_without_the_prefix() {
        assert_eq!(
            normalize_ioc_domain("www.evil-c2.com"),
            Some("evil-c2.com".to_string())
        );
        assert_eq!(
            normalize_ioc_domain("malware.example.org"),
            Some("malware.example.org".to_string())
        );
        // Degenerate `www.<tld>` is not reduced to a bare TLD.
        assert_eq!(normalize_ioc_domain("www.com"), Some("www.com".to_string()));
    }

    #[test]
    fn internal_only_domains_are_dropped() {
        assert_eq!(normalize_ioc_domain("localhost"), None);
        assert_eq!(normalize_ioc_domain("localhost."), None);
        assert_eq!(normalize_ioc_domain("printer.local"), None);
        assert_eq!(normalize_ioc_domain("host.localhost"), None);
        assert_eq!(normalize_ioc_domain("www.fileshare.local"), None);
        assert_eq!(normalize_ioc_domain("PRINTER.LOCAL"), None);
        assert_eq!(normalize_ioc_domain("WWW.FILESHARE.LOCAL"), None);
    }

    #[test]
    fn multiple_trailing_dots_are_rejected() {
        assert_eq!(normalize_ioc_domain("www.evil-c2.com..."), None);
        assert_eq!(normalize_ioc_domain("evil-c2.com..."), None);
    }

    #[test]
    fn all_numeric_domains_are_rejected() {
        assert_eq!(normalize_ioc_domain("12345"), None);
        assert_eq!(normalize_ioc_domain("192.0.2.10"), None);
    }

    #[test]
    fn invalid_domain_labels_are_rejected() {
        for domain in [
            "-bad.example.com",
            "bad-.example.com",
            "bad..example.com",
            "bad_example.com",
            "toolong.example.com",
        ] {
            let domain = domain.replace("toolong", &"a".repeat(64));
            assert_eq!(normalize_ioc_domain(&domain), None, "{domain}");
        }
    }

    #[test]
    fn overlong_domain_names_are_rejected() {
        let domain = ["a"; 128].join(".");

        assert!(domain.len() > 253);
        assert_eq!(normalize_ioc_domain(&domain), None);
    }

    #[test]
    fn file_extension_labels_are_not_treated_as_domains() {
        // Request paths captured from a honeypot must not surface as C2 domains.
        for payload in [
            "payload.exe",
            "sample.bin",
            "update.dll",
            "report.pdf",
            "shell.PS1", // case-insensitive
            "archive.tar",
            "image.jpeg",
        ] {
            assert_eq!(
                normalize_ioc_domain(payload),
                None,
                "{payload} must not be reported as a domain"
            );
        }
        assert_eq!(
            normalize_ioc_domain("evil-c2.com"),
            Some("evil-c2.com".to_string())
        );
        assert_eq!(
            normalize_ioc_domain("download.malware.net"),
            Some("download.malware.net".to_string())
        );
        // Extensions that are also delegated TLDs are intentionally kept rather
        // than risk discarding a real C2 domain.
        assert_eq!(
            normalize_ioc_domain("loader.zip"),
            Some("loader.zip".to_string())
        );
        assert_eq!(
            normalize_ioc_domain("beacon.app"),
            Some("beacon.app".to_string())
        );
    }

    #[test]
    fn extract_domains_ignores_request_path_filenames() {
        // The HTTP enricher scans "host\nURI\nbody"; the URI filename must not leak.
        let domains = crate::extract::extract_domains("probe.test\n/payload.exe\n");
        assert_eq!(domains, vec!["probe.test".to_string()]);
    }

    #[test]
    fn external_ipv4_classification() {
        assert!(is_external_ipv4("8.8.8.8"));
        assert!(is_external_ipv4("1.2.3.4"));
        assert!(is_external_ipv4("45.33.32.156"));
        assert!(!is_external_ipv4("203.0.113.5"));
        assert!(!is_external_ipv4("192.0.2.10"));
        for ip in [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.5.5",
            "172.31.255.255",
            "127.0.0.1",
            "169.254.1.1", // link-local — previously leaked as external
            "100.64.0.1",  // shared address space
            "192.0.0.8",   // IETF protocol assignments
            "198.18.0.1",  // benchmark network
            "224.0.0.1",   // multicast — previously leaked
            "240.0.0.1",   // reserved
            "255.255.255.255",
            "0.0.0.0",
            "0.1.2.3",
        ] {
            assert!(!is_external_ipv4(ip), "{ip} must be excluded");
        }
        assert!(is_external_ipv4("172.15.0.1"));
        assert!(is_external_ipv4("172.32.0.1"));
    }
}
