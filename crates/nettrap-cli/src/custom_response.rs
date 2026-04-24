//! Custom response configuration for HTTP listeners.
//! Supports matching by host and/or URI, with multiple response types.
use std::io::Read;
use std::path::Path;

const MAX_CUSTOM_RESPONSE_FILE_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CustomResponseConfig {
    pub rules: Vec<CustomResponseRule>,
}

#[derive(Debug, Clone)]
pub struct CustomResponseRule {
    /// Match hosts (comma-separated, case-insensitive)
    pub hosts: Vec<String>,
    /// Match URI suffixes (comma-separated)
    pub uris: Vec<String>,
    /// Response to send when matched
    pub response: CustomResponseType,
    /// Content-Type header (for HttpStaticString)
    pub content_type: Option<String>,
}

#[derive(Debug, Clone)]
pub enum CustomResponseType {
    /// Raw file contents as HTTP response
    HttpRawFile(String),
    /// Static string with HTTP headers
    HttpStaticString(String),
    /// Base64-decoded binary response
    HttpBase64(Vec<u8>),
}

enum LimitedFileRead {
    Content(Vec<u8>),
    TooLarge,
    NotFile,
}

impl CustomResponseConfig {
    /// Parse from a custom response config string.
    /// Format (INI-like, semicolon-separated rules):
    /// "host=evil.com,uri=/gate;type=static;body=OK"
    /// "host=*,uri=.exe;type=file;path=/path/to/payload.bin"
    /// "host=*,uri=*;type=base64;data=SGVsbG8="
    pub fn parse(config_str: &str) -> Self {
        let mut rules = Vec::new();

        for rule_str in config_str.split("||") {
            let rule_str = rule_str.trim();
            if rule_str.is_empty() {
                continue;
            }

            let mut hosts = Vec::new();
            let mut uris = Vec::new();
            let mut response_type = None;
            let mut body = String::new();
            let mut content_type = None;

            for part in rule_str.split(';') {
                let part = part.trim();
                if let Some(val) = part.strip_prefix("host=") {
                    hosts = val.split(',').map(|s| s.trim().to_lowercase()).collect();
                } else if let Some(val) = part.strip_prefix("uri=") {
                    uris = val.split(',').map(|s| s.trim().to_string()).collect();
                } else if let Some(val) = part.strip_prefix("type=") {
                    response_type = Some(val.trim().to_string());
                } else if let Some(val) = part.strip_prefix("body=") {
                    body = val.to_string();
                } else if let Some(val) = part.strip_prefix("path=") {
                    body = val.to_string();
                } else if let Some(val) = part.strip_prefix("data=") {
                    body = val.to_string();
                } else if let Some(val) = part.strip_prefix("content_type=") {
                    content_type = Some(val.to_string());
                }
            }

            let response = match response_type.as_deref() {
                Some("file") => CustomResponseType::HttpRawFile(body),
                Some("base64") => {
                    use base64::Engine as _;
                    match base64::engine::general_purpose::STANDARD.decode(&body) {
                        Ok(decoded) => CustomResponseType::HttpBase64(decoded),
                        Err(e) => {
                            tracing::error!(
                                "Invalid base64 in custom response (type=base64), ignoring rule: {}",
                                e
                            );
                            continue; // Skip this rule entirely rather than silently changing type
                        }
                    }
                }
                _ => CustomResponseType::HttpStaticString(body),
            };

            rules.push(CustomResponseRule {
                hosts,
                uris,
                response,
                content_type,
            });
        }

        Self { rules }
    }

    /// Find matching rule for a request
    pub fn find_match(&self, host: &str, uri: &str) -> Option<&CustomResponseRule> {
        for rule in &self.rules {
            let host_match =
                rule.hosts.is_empty() || rule.hosts.iter().any(|h| host_matches_pattern(host, h));
            let uri_match =
                rule.uris.is_empty() || rule.uris.iter().any(|u| uri_matches_pattern(uri, u));

            // If both specified, both must match (conjunctive)
            // If only one specified, that one must match
            if !rule.hosts.is_empty() && !rule.uris.is_empty() {
                if host_match && uri_match {
                    return Some(rule);
                }
            } else if host_match && uri_match {
                return Some(rule);
            }
        }
        None
    }

    /// Build HTTP response from matched rule
    pub fn build_response(&self, host: &str, uri: &str) -> Option<Vec<u8>> {
        self.build_response_for_request(host, uri, uri)
    }

    /// Build an HTTP response using a normalized routing URI while preserving the
    /// original request target for template variables.
    pub fn build_response_for_request(
        &self,
        host: &str,
        route_uri: &str,
        request_target: &str,
    ) -> Option<Vec<u8>> {
        let rule = self.find_match(host, route_uri)?;
        let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");

        // Build template variables for the template engine
        let mut vars = std::collections::HashMap::new();
        vars.insert("host".to_string(), host.to_string());
        vars.insert("uri".to_string(), request_target.to_string());
        vars.insert("server".to_string(), "NetTrap".to_string());

        match &rule.response {
            CustomResponseType::HttpRawFile(path) => {
                match read_limited_file(Path::new(path), MAX_CUSTOM_RESPONSE_FILE_BYTES) {
                    Ok(LimitedFileRead::Content(content)) => Some(content),
                    Ok(LimitedFileRead::TooLarge) => {
                        tracing::warn!(
                            "Custom response file {} exceeds response size limit (>{})",
                            path,
                            MAX_CUSTOM_RESPONSE_FILE_BYTES
                        );
                        Some(payload_too_large_response(&date.to_string()))
                    }
                    Ok(LimitedFileRead::NotFile) => None,
                    Err(e) => {
                        tracing::warn!("Failed to read custom response file {}: {}", path, e);
                        None
                    }
                }
            }
            CustomResponseType::HttpStaticString(body) => {
                let ct = rule.content_type.as_deref().unwrap_or("text/html");
                // Support both legacy <RAW-DATE> and new {{date:...}} templates
                let body_replaced = body.replace("<RAW-DATE>", &date.to_string());
                let body_rendered = crate::template::render_template(&body_replaced, &vars);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nDate: {}\r\nServer: NetTrap\r\n\r\n{}",
                    ct,
                    body_rendered.len(),
                    date,
                    body_rendered
                );
                Some(response.into_bytes())
            }
            CustomResponseType::HttpBase64(decoded) => {
                let ct = rule
                    .content_type
                    .as_deref()
                    .unwrap_or("application/octet-stream");
                let mut response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nDate: {}\r\nServer: NetTrap\r\n\r\n",
                    ct, decoded.len(), date
                ).into_bytes();
                response.extend_from_slice(decoded);
                Some(response)
            }
        }
    }
}

fn payload_too_large_response(date: &str) -> Vec<u8> {
    let body = "Payload Too Large";
    format!(
        "HTTP/1.1 413 Payload Too Large\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nDate: {}\r\nServer: NetTrap\r\n\r\n{}",
        body.len(),
        date,
        body
    )
    .into_bytes()
}

fn read_limited_file(path: &Path, max_bytes: u64) -> std::io::Result<LimitedFileRead> {
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Ok(LimitedFileRead::NotFile);
    }
    if metadata.len() > max_bytes {
        return Ok(LimitedFileRead::TooLarge);
    }

    let mut limited = file.take(max_bytes + 1);
    let mut content = Vec::new();
    limited.read_to_end(&mut content)?;
    if content.len() as u64 > max_bytes {
        return Ok(LimitedFileRead::TooLarge);
    }

    Ok(LimitedFileRead::Content(content))
}

pub(crate) fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let host = normalize_http_host(host);
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    host == pattern || host.ends_with(&format!(".{}", pattern))
}

fn normalize_http_host(host: &str) -> String {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();

    if let Some(stripped) = host.strip_prefix('[') {
        if let Some(end_bracket) = stripped.find(']') {
            return stripped[..end_bracket].to_string();
        }
    }

    if let Some((base, port)) = host.rsplit_once(':') {
        if !base.contains(':') && !base.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) {
            return base.to_string();
        }
    }

    host
}

fn uri_matches_pattern(uri: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.starts_with('.') {
        return uri.ends_with(pattern);
    }

    uri == pattern
}

#[cfg(test)]
mod tests {
    use super::{
        CustomResponseConfig, MAX_CUSTOM_RESPONSE_FILE_BYTES, host_matches_pattern,
        uri_matches_pattern,
    };

    #[test]
    fn host_matches_are_exact_or_subdomain_only() {
        assert!(host_matches_pattern("evil.com", "evil.com"));
        assert!(host_matches_pattern("api.evil.com", "evil.com"));
        assert!(host_matches_pattern("evil.com:8080", "evil.com"));
        assert!(!host_matches_pattern("notevil.com", "evil.com"));
        assert!(!host_matches_pattern("evil.com.attacker.test", "evil.com"));
    }

    #[test]
    fn uri_matches_use_exact_paths_or_suffix_patterns() {
        assert!(uri_matches_pattern("/gate", "/gate"));
        assert!(!uri_matches_pattern("/delegate", "/gate"));
        assert!(uri_matches_pattern("/dropper.exe", ".exe"));
        assert!(!uri_matches_pattern("/dropper.dll", ".exe"));
    }

    #[test]
    fn custom_response_matching_uses_safe_host_and_uri_semantics() {
        let config = CustomResponseConfig::parse(
            "host=evil.com;uri=/gate;type=static;body=OK||host=*;uri=.exe;type=static;body=BIN",
        );

        let exact = config.find_match("evil.com", "/gate");
        assert!(exact.is_some());

        let subdomain = config.find_match("api.evil.com", "/gate");
        assert!(subdomain.is_some());

        assert!(config.find_match("notevil.com", "/gate").is_none());
        assert!(config.find_match("evil.com", "/delegate").is_none());
        assert!(config.find_match("evil.com", "/payload.exe").is_some());
    }

    #[test]
    fn custom_response_file_rejects_oversized_file() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-custom-response-limit-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("large.http");
        let file = std::fs::File::create(&path).expect("create sparse file");
        file.set_len(MAX_CUSTOM_RESPONSE_FILE_BYTES + 1)
            .expect("extend sparse file");
        let config =
            CustomResponseConfig::parse(&format!("host=*;uri=*;type=file;path={}", path.display()));

        let response = config
            .build_response_for_request("example.com", "/", "/")
            .expect("matching file rule should respond");

        assert!(response.starts_with(b"HTTP/1.1 413 Payload Too Large"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn custom_response_file_preserves_raw_bytes() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-custom-response-raw-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("raw.http");
        let content = b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n\xff<RAW-DATE>{{host}}";
        std::fs::write(&path, content).expect("write raw response");
        let config =
            CustomResponseConfig::parse(&format!("host=*;uri=*;type=file;path={}", path.display()));

        let response = config
            .build_response_for_request("example.com", "/", "/")
            .expect("matching file rule should respond");

        assert_eq!(response, content);
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }
}
