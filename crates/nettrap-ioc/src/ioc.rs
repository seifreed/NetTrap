use regex::Regex;

#[derive(Debug, Clone)]
pub struct IoC {
    pub ioc_type: IoCType,
    pub value: String,
    pub confidence: f32,
    pub source: String,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IoCType {
    Domain,
    IpAddress,
    Url,
    HashMd5,
    HashSha1,
    HashSha256,
    Email,
    FilePath,
    Registry,
    Mutex,
}

pub struct IoCDetector {
    domain_pattern: Regex,
    ipv4_pattern: Regex,
    url_pattern: Regex,
    md5_pattern: Regex,
    sha1_pattern: Regex,
    sha256_pattern: Regex,
    email_pattern: Regex,
    filepath_pattern: Regex,
    registry_pattern: Regex,
}

impl IoCDetector {
    pub fn new() -> Self {
        Self {
            domain_pattern: Regex::new(r"\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b").unwrap(),
            ipv4_pattern: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
            url_pattern: Regex::new(r#"\bhttps?://[^\s<>"{}|\\^`\[\]]+\b"#).unwrap(),
            md5_pattern: Regex::new(r"\b[a-fA-F0-9]{32}\b").unwrap(),
            sha1_pattern: Regex::new(r"\b[a-fA-F0-9]{40}\b").unwrap(),
            sha256_pattern: Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap(),
            email_pattern: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap(),
            filepath_pattern: Regex::new(r#"[A-Za-z]:\\[^\s"<>|]*|/[\w/.-]+"#).unwrap(),
            registry_pattern: Regex::new(r"HKEY_[A-Z_]+(?:\\[\w\s]+)*").unwrap(),
        }
    }

    pub fn detect(&self, data: &str) -> Vec<IoC> {
        let mut iocs = Vec::new();

        iocs.extend(self.detect_domains(data));
        iocs.extend(self.detect_ipv4(data));
        iocs.extend(self.detect_urls(data));
        iocs.extend(self.detect_hashes(data));
        iocs.extend(self.detect_emails(data));
        iocs.extend(self.detect_filepaths(data));
        iocs.extend(self.detect_registry(data));

        iocs
    }

    fn detect_domains(&self, data: &str) -> Vec<IoC> {
        let mut domains = Vec::new();

        for cap in self.domain_pattern.captures_iter(data) {
            let domain = cap[0].to_string();
            if !domain.ends_with(".local")
                && !domain.ends_with(".localhost")
                && !domain.starts_with("www.")
            {
                domains.push(IoC {
                    ioc_type: IoCType::Domain,
                    value: domain,
                    confidence: 0.7,
                    source: "regex".to_string(),
                    context: None,
                });
            }
        }

        domains
    }

    fn detect_ipv4(&self, data: &str) -> Vec<IoC> {
        let mut ips = Vec::new();

        for cap in self.ipv4_pattern.captures_iter(data) {
            let ip = cap[0].to_string();
            if !ip.starts_with("192.168.")
                && !ip.starts_with("10.")
                && !is_rfc1918_172(&ip)
                && !ip.starts_with("127.")
            {
                ips.push(IoC {
                    ioc_type: IoCType::IpAddress,
                    value: ip,
                    confidence: 0.8,
                    source: "regex".to_string(),
                    context: None,
                });
            }
        }

        ips
    }

    fn detect_urls(&self, data: &str) -> Vec<IoC> {
        self.url_pattern
            .captures_iter(data)
            .map(|cap| IoC {
                ioc_type: IoCType::Url,
                value: cap[0].to_string(),
                confidence: 0.9,
                source: "regex".to_string(),
                context: None,
            })
            .collect()
    }

    fn detect_hashes(&self, data: &str) -> Vec<IoC> {
        let mut hashes = Vec::new();

        for cap in self.sha256_pattern.captures_iter(data) {
            hashes.push(IoC {
                ioc_type: IoCType::HashSha256,
                value: cap[0].to_string(),
                confidence: 0.9,
                source: "regex".to_string(),
                context: None,
            });
        }

        for cap in self.sha1_pattern.captures_iter(data) {
            let hash = cap[0].to_string();
            // Use exact substring check: a SHA256 contains this SHA1 as a substring
            let is_substring_of_longer = hashes
                .iter()
                .any(|h| h.value.len() > hash.len() && h.value.contains(&hash));
            if !is_substring_of_longer {
                hashes.push(IoC {
                    ioc_type: IoCType::HashSha1,
                    value: hash,
                    confidence: 0.8,
                    source: "regex".to_string(),
                    context: None,
                });
            }
        }

        for cap in self.md5_pattern.captures_iter(data) {
            let hash = cap[0].to_string();
            // Use exact substring check: a longer hash contains this MD5 as a substring
            let is_substring_of_longer = hashes
                .iter()
                .any(|h| h.value.len() > hash.len() && h.value.contains(&hash));
            if !is_substring_of_longer {
                hashes.push(IoC {
                    ioc_type: IoCType::HashMd5,
                    value: hash,
                    confidence: 0.7,
                    source: "regex".to_string(),
                    context: None,
                });
            }
        }

        hashes
    }

    fn detect_emails(&self, data: &str) -> Vec<IoC> {
        self.email_pattern
            .captures_iter(data)
            .map(|cap| IoC {
                ioc_type: IoCType::Email,
                value: cap[0].to_string(),
                confidence: 0.8,
                source: "regex".to_string(),
                context: None,
            })
            .collect()
    }

    fn detect_filepaths(&self, data: &str) -> Vec<IoC> {
        self.filepath_pattern
            .captures_iter(data)
            .map(|cap| IoC {
                ioc_type: IoCType::FilePath,
                value: cap[0].to_string(),
                confidence: 0.6,
                source: "regex".to_string(),
                context: None,
            })
            .collect()
    }

    fn detect_registry(&self, data: &str) -> Vec<IoC> {
        self.registry_pattern
            .captures_iter(data)
            .map(|cap| IoC {
                ioc_type: IoCType::Registry,
                value: cap[0].to_string(),
                confidence: 0.7,
                source: "regex".to_string(),
                context: None,
            })
            .collect()
    }
}

/// Check if IP is in the RFC1918 172.16.0.0/12 range (172.16.x.x - 172.31.x.x)
pub fn is_rfc1918_172(ip: &str) -> bool {
    if let Some(rest) = ip.strip_prefix("172.") {
        if let Some(second_octet_str) = rest.split('.').next() {
            if let Ok(second_octet) = second_octet_str.parse::<u8>() {
                return (16..=31).contains(&second_octet);
            }
        }
    }
    false
}

impl Default for IoCDetector {
    fn default() -> Self {
        Self::new()
    }
}
