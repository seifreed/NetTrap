use once_cell::sync::Lazy;

static DOMAIN_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
        .expect("invalid domain regex")
});

static IPV4_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
        .expect("invalid ipv4 regex")
});

static URL_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r#"\bhttps?://[^\s<>"{}|\\^`\[\]]+\b"#).expect("invalid url regex")
});

static SHA256_REGEX: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"\b[a-fA-F0-9]{64}\b").expect("invalid sha256 regex"));

static SHA1_REGEX: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"\b[a-fA-F0-9]{40}\b").expect("invalid sha1 regex"));

static MD5_REGEX: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"\b[a-fA-F0-9]{32}\b").expect("invalid md5 regex"));

pub fn extract_domains(data: &str) -> Vec<String> {
    DOMAIN_REGEX
        .captures_iter(data)
        .filter_map(|cap| {
            let domain = cap[0].to_string();
            if !domain.ends_with(".local")
                && !domain.ends_with(".localhost")
                && !domain.starts_with("www.")
            {
                Some(domain)
            } else {
                None
            }
        })
        .collect()
}

pub fn extract_ipv4(data: &str) -> Vec<String> {
    IPV4_REGEX
        .captures_iter(data)
        .filter_map(|cap| {
            let ip = cap[0].to_string();
            if !ip.starts_with("192.168.")
                && !ip.starts_with("10.")
                && !crate::ioc::is_rfc1918_172(&ip)
                && !ip.starts_with("127.")
            {
                Some(ip)
            } else {
                None
            }
        })
        .collect()
}

pub fn extract_urls(data: &str) -> Vec<String> {
    URL_REGEX
        .captures_iter(data)
        .map(|cap| cap[0].to_string())
        .collect()
}

pub fn extract_hashes(data: &str) -> Vec<(String, String)> {
    let mut hashes = Vec::new();

    for cap in SHA256_REGEX.captures_iter(data) {
        hashes.push(("sha256".to_string(), cap[0].to_string()));
    }

    for cap in SHA1_REGEX.captures_iter(data) {
        let hash = cap[0].to_string();
        // Only skip if this hash is a substring of a longer (e.g. SHA256) hash
        let is_substring_of_longer = hashes
            .iter()
            .any(|(_, h)| h.len() > hash.len() && h.contains(&hash));
        if !is_substring_of_longer {
            hashes.push(("sha1".to_string(), hash));
        }
    }

    for cap in MD5_REGEX.captures_iter(data) {
        let hash = cap[0].to_string();
        let is_substring_of_longer = hashes
            .iter()
            .any(|(_, h)| h.len() > hash.len() && h.contains(&hash));
        if !is_substring_of_longer {
            hashes.push(("md5".to_string(), hash));
        }
    }

    hashes
}

pub fn extract_emails(data: &str) -> Vec<String> {
    static EMAIL_REGEX: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
            .expect("invalid email regex")
    });

    EMAIL_REGEX
        .captures_iter(data)
        .map(|cap| cap[0].to_string())
        .collect()
}
