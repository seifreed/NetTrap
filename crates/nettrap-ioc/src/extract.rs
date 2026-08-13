use once_cell::sync::Lazy;
use regex::Regex;

const MAX_EXTRACTED_IOCS: usize = 1024;

#[derive(Debug, Clone, thiserror::Error)]
pub enum ExtractError {
    #[error("failed to initialize {name} IOC regex: {message}")]
    RegexInit { name: &'static str, message: String },
}

pub type ExtractResult<T> = std::result::Result<T, ExtractError>;

fn compile_regex(pattern: &'static str) -> Result<Regex, regex::Error> {
    Regex::new(pattern)
}

fn regex<'a>(
    name: &'static str,
    regex: &'a Lazy<Result<Regex, regex::Error>>,
) -> ExtractResult<&'a Regex> {
    regex.as_ref().map_err(|err| ExtractError::RegexInit {
        name,
        message: err.to_string(),
    })
}

fn extract_or_log<T>(operation: &'static str, result: ExtractResult<T>, fallback: T) -> T {
    match result {
        Ok(value) => value,
        Err(err) => {
            tracing::error!("{operation} failed: {err}");
            fallback
        }
    }
}

static DOMAIN_REGEX: Lazy<Result<Regex, regex::Error>> = Lazy::new(|| {
    compile_regex(r"\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
});

static IPV4_REGEX: Lazy<Result<Regex, regex::Error>> = Lazy::new(|| {
    compile_regex(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    )
});

static URL_REGEX: Lazy<Result<Regex, regex::Error>> =
    Lazy::new(|| compile_regex(r##"\b[Hh][Tt][Tt][Pp][Ss]?://[^\s<>"{}|\\^`\[\]]{1,2048}\b"##));

static SHA256_REGEX: Lazy<Result<Regex, regex::Error>> =
    Lazy::new(|| compile_regex(r"\b[a-fA-F0-9]{64}\b"));

static SHA1_REGEX: Lazy<Result<Regex, regex::Error>> =
    Lazy::new(|| compile_regex(r"\b[a-fA-F0-9]{40}\b"));

static MD5_REGEX: Lazy<Result<Regex, regex::Error>> =
    Lazy::new(|| compile_regex(r"\b[a-fA-F0-9]{32}\b"));

pub fn extract_domains(data: &str) -> Vec<String> {
    extract_or_log(
        "domain IOC extraction",
        try_extract_domains(data),
        Vec::new(),
    )
}

pub fn try_extract_domains(data: &str) -> ExtractResult<Vec<String>> {
    Ok(regex("domain", &DOMAIN_REGEX)?
        .captures_iter(data)
        .filter_map(|cap| crate::ioc::normalize_ioc_domain(&cap[0]))
        .take(MAX_EXTRACTED_IOCS)
        .collect())
}

pub fn extract_ipv4(data: &str) -> Vec<String> {
    extract_or_log("IPv4 IOC extraction", try_extract_ipv4(data), Vec::new())
}

pub fn try_extract_ipv4(data: &str) -> ExtractResult<Vec<String>> {
    Ok(regex("IPv4", &IPV4_REGEX)?
        .captures_iter(data)
        .filter_map(|cap| {
            let ip = cap[0].to_string();
            crate::ioc::is_external_ipv4(&ip).then_some(ip)
        })
        .take(MAX_EXTRACTED_IOCS)
        .collect())
}

pub fn extract_urls(data: &str) -> Vec<String> {
    extract_or_log("URL IOC extraction", try_extract_urls(data), Vec::new())
}

pub fn try_extract_urls(data: &str) -> ExtractResult<Vec<String>> {
    Ok(regex("URL", &URL_REGEX)?
        .captures_iter(data)
        .filter_map(|cap| valid_url_ioc(&cap[0]).then(|| cap[0].to_string()))
        .take(MAX_EXTRACTED_IOCS)
        .collect())
}

pub fn extract_hashes(data: &str) -> Vec<(String, String)> {
    extract_or_log("hash IOC extraction", try_extract_hashes(data), Vec::new())
}

pub fn try_extract_hashes(data: &str) -> ExtractResult<Vec<(String, String)>> {
    let mut hashes = Vec::new();

    for cap in regex("SHA-256", &SHA256_REGEX)?.captures_iter(data) {
        if hashes.len() >= MAX_EXTRACTED_IOCS {
            break;
        }
        hashes.push(("sha256".to_string(), cap[0].to_string()));
    }

    for cap in regex("SHA-1", &SHA1_REGEX)?.captures_iter(data) {
        if hashes.len() >= MAX_EXTRACTED_IOCS {
            break;
        }
        let hash = cap[0].to_string();
        let is_substring_of_longer = hashes
            .iter()
            .any(|(_, h)| h.len() > hash.len() && h.contains(&hash));
        if !is_substring_of_longer {
            hashes.push(("sha1".to_string(), hash));
        }
    }

    for cap in regex("MD5", &MD5_REGEX)?.captures_iter(data) {
        if hashes.len() >= MAX_EXTRACTED_IOCS {
            break;
        }
        let hash = cap[0].to_string();
        let is_substring_of_longer = hashes
            .iter()
            .any(|(_, h)| h.len() > hash.len() && h.contains(&hash));
        if !is_substring_of_longer {
            hashes.push(("md5".to_string(), hash));
        }
    }

    Ok(hashes)
}

pub fn extract_emails(data: &str) -> Vec<String> {
    extract_or_log("email IOC extraction", try_extract_emails(data), Vec::new())
}

pub fn try_extract_emails(data: &str) -> ExtractResult<Vec<String>> {
    static EMAIL_REGEX: Lazy<Result<Regex, regex::Error>> = Lazy::new(|| {
        // TLD class is [A-Za-z]{2,} — NOT [A-Z|a-z], where the `|` is a literal
        // class member (a common char-class-vs-alternation slip), which would
        // accept a pipe as a "letter" and over-match a TLD like `a|b`.
        compile_regex(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,}\b")
    });

    Ok(regex("email", &EMAIL_REGEX)?
        .captures_iter(data)
        .filter_map(|cap| valid_email_ioc(&cap[0]).then(|| cap[0].to_string()))
        .take(MAX_EXTRACTED_IOCS)
        .collect())
}

fn valid_email_ioc(email: &str) -> bool {
    let Some((_, domain)) = email.rsplit_once('@') else {
        return false;
    };
    crate::ioc::normalize_ioc_domain(domain).is_some()
}

fn valid_url_ioc(url: &str) -> bool {
    let Some((scheme, authority_and_path)) = url.split_once("://") else {
        return false;
    };
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return false;
    }
    let authority = authority_and_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match host_port.rsplit_once(':') {
        Some((host, port))
            if !host.contains(':')
                && !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit())
                && port.parse::<u16>().is_ok_and(|port| port != 0) =>
        {
            host
        }
        Some(_) => return false,
        None => host_port,
    };

    if host.is_empty() {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return crate::ioc::is_external_ipv4(&ip.to_string());
    }

    crate::ioc::normalize_ioc_domain(host).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_domains_recovers_www_prefixed_c2() {
        let domains = extract_domains("callback www.evil-c2.com and svc.internal.local");
        assert!(domains.contains(&"evil-c2.com".to_string()));
        assert!(!domains.iter().any(|d| d.ends_with(".local")));
    }

    #[test]
    fn extract_emails_basic_and_no_pipe_in_tld() {
        let emails = extract_emails("contact operator@evil.example.com now");
        assert_eq!(emails, vec!["operator@evil.example.com".to_string()]);

        // The TLD class must be [A-Za-z], not [A-Z|a-z]: a pipe is not a letter,
        // so the match must stop before it rather than swallowing `a|b`.
        let emails = extract_emails("user@host.a|b trailing");
        assert!(
            emails.iter().all(|e| !e.contains('|')),
            "no extracted email may contain a pipe: {emails:?}"
        );
    }

    #[test]
    fn extract_ipv4_excludes_private_and_reserved() {
        let ips = extract_ipv4("c2 45.33.32.156 lan 192.168.1.1 ll 169.254.0.1");
        assert_eq!(ips, vec!["45.33.32.156".to_string()]);
    }

    #[test]
    fn extract_urls_rejects_internal_only_hosts() {
        let urls = extract_urls(
            "keep http://evil.example.com/payload.bin \
             local http://printer.local/status \
             loop http://127.0.0.1/admin \
             lan http://192.168.1.10/payload.bin \
             userinfo http://evil.example.com@127.0.0.1/admin",
        );

        assert_eq!(
            urls,
            vec!["http://evil.example.com/payload.bin".to_string()]
        );
    }

    #[test]
    fn extract_urls_accepts_case_insensitive_http_schemes() {
        let urls =
            extract_urls("upper HTTP://evil.example.com/payload mixed HtTpS://cdn.badactor.com/a");

        assert_eq!(
            urls,
            vec![
                "HTTP://evil.example.com/payload".to_string(),
                "HtTpS://cdn.badactor.com/a".to_string()
            ]
        );
    }

    #[test]
    fn extract_urls_rejects_invalid_ports() {
        let urls = extract_urls(
            "good http://evil.example.com:443/payload \
             zero http://evil.example.com:0/payload \
             high http://evil.example.com:99999/payload",
        );

        assert_eq!(
            urls,
            vec!["http://evil.example.com:443/payload".to_string()]
        );
    }

    #[test]
    fn extract_emails_matches_normal_addresses() {
        let emails = extract_emails("contact bad.actor@evil-c2.com for keys");
        assert_eq!(emails, vec!["bad.actor@evil-c2.com".to_string()]);
    }

    #[test]
    fn extract_emails_rejects_pipe_in_tld() {
        // `|` is not a valid TLD character; the old `[A-Z|a-z]` class leaked it.
        let emails = extract_emails("user@host.a|b");
        assert!(
            !emails.iter().any(|e| e.contains('|')),
            "no email IOC should contain a pipe, got: {emails:?}"
        );
    }

    #[test]
    fn extract_emails_rejects_invalid_domain_labels() {
        let emails = extract_emails(
            "good operator@evil-c2.com bad user@bad..example.com edge user@bad-.example.com",
        );

        assert_eq!(emails, vec!["operator@evil-c2.com".to_string()]);
    }

    #[test]
    fn extract_emails_rejects_internal_only_domains() {
        let emails = extract_emails(
            "good operator@evil-c2.com local user@printer.local host admin@localhost",
        );

        assert_eq!(emails, vec!["operator@evil-c2.com".to_string()]);
    }

    #[test]
    fn extract_domains_caps_result_count() {
        let mut data = String::new();
        for index in 0..MAX_EXTRACTED_IOCS + 10 {
            data.push_str(&format!("d{index}.example.com "));
        }

        let domains = extract_domains(&data);

        assert_eq!(domains.len(), MAX_EXTRACTED_IOCS);
    }

    #[test]
    fn extract_hashes_caps_result_count() {
        let mut data = String::new();
        for index in 0..MAX_EXTRACTED_IOCS + 10 {
            data.push_str(&format!("{index:064x} "));
        }

        let hashes = extract_hashes(&data);

        assert_eq!(hashes.len(), MAX_EXTRACTED_IOCS);
    }
}
