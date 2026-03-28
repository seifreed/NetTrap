pub fn extract_domains(data: &str) -> Vec<String> {
    let re =
        regex::Regex::new(r"\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
            .unwrap();

    re.captures_iter(data)
        .filter_map(|cap| {
            let domain = cap[0].to_string();
            if !domain.ends_with(".local") && !domain.ends_with(".localhost") {
                Some(domain)
            } else {
                None
            }
        })
        .collect()
}

pub fn extract_ipv4(data: &str) -> Vec<String> {
    let re = regex::Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap();

    re.captures_iter(data)
        .filter_map(|cap| {
            let ip = cap[0].to_string();
            if !ip.starts_with("192.168.")
                && !ip.starts_with("10.")
                && !ip.starts_with("172.")
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
    let re = regex::Regex::new(r#"\bhttps?://[^\s<>"{}|\\^`\[\]]+\b"#).unwrap();

    re.captures_iter(data)
        .map(|cap| cap[0].to_string())
        .collect()
}

pub fn extract_hashes(data: &str) -> Vec<(String, String)> {
    let mut hashes = Vec::new();

    let sha256 = regex::Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap();
    for cap in sha256.captures_iter(data) {
        hashes.push(("sha256".to_string(), cap[0].to_string()));
    }

    let sha1 = regex::Regex::new(r"\b[a-fA-F0-9]{40}\b").unwrap();
    for cap in sha1.captures_iter(data) {
        let hash = cap[0].to_string();
        if !hashes.iter().any(|(_, h)| h.contains(&hash)) {
            hashes.push(("sha1".to_string(), hash));
        }
    }

    let md5 = regex::Regex::new(r"\b[a-fA-F0-9]{32}\b").unwrap();
    for cap in md5.captures_iter(data) {
        let hash = cap[0].to_string();
        if !hashes.iter().any(|(_, h)| h.contains(&hash)) {
            hashes.push(("md5".to_string(), hash));
        }
    }

    hashes
}

pub fn extract_emails(data: &str) -> Vec<String> {
    let re = regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();

    re.captures_iter(data)
        .map(|cap| cap[0].to_string())
        .collect()
}
