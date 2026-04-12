/// Custom response configuration for HTTP listeners.
/// Supports matching by host and/or URI, with multiple response types.
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
        let host_lower = host.to_lowercase();

        for rule in &self.rules {
            let host_match = rule.hosts.is_empty()
                || rule
                    .hosts
                    .iter()
                    .any(|h| h == "*" || host_lower.contains(h));
            let uri_match = rule.uris.is_empty()
                || rule
                    .uris
                    .iter()
                    .any(|u| u == "*" || uri.ends_with(u) || uri.contains(u));

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
        let rule = self.find_match(host, uri)?;
        let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");

        // Build template variables for the template engine
        let mut vars = std::collections::HashMap::new();
        vars.insert("host".to_string(), host.to_string());
        vars.insert("uri".to_string(), uri.to_string());
        vars.insert("server".to_string(), "NetTrap".to_string());

        match &rule.response {
            CustomResponseType::HttpRawFile(path) => {
                match std::fs::read(path) {
                    Ok(content) => {
                        let content_str = String::from_utf8_lossy(&content);
                        // Support both legacy <RAW-DATE> and new {{date:...}} templates
                        let replaced = content_str.replace("<RAW-DATE>", &date.to_string());
                        let rendered = crate::template::render_template(&replaced, &vars);
                        Some(rendered.into_bytes())
                    }
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
