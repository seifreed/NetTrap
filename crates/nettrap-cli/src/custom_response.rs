//! Custom response configuration for HTTP listeners.
//! Supports matching by host and/or URI, with multiple response types.
use std::path::Path;

use nettrap_core::parse::nonzero_port as parse_http_port;
use nettrap_core::sanitize::{
    has_numeric_domain_labels, has_valid_domain_label_lengths, has_valid_domain_labels,
    trim_ascii_spaces_tabs as trim_ascii_edges,
};
use nettrap_fsutil::{LimitedFileRead, read_limited_file};

const MAX_CUSTOM_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
const MAX_CUSTOM_RESPONSE_FILE_BYTES: u64 = MAX_CUSTOM_RESPONSE_BYTES as u64;
const MAX_CUSTOM_RESPONSE_BASE64_CONFIG_BYTES: usize = MAX_CUSTOM_RESPONSE_BYTES.div_ceil(3) * 4;
const MAX_CUSTOM_RESPONSE_RULES: usize = 256;
const MAX_CUSTOM_RESPONSE_MATCHERS_PER_FIELD: usize = 64;

#[derive(Debug, Clone)]
pub struct CustomResponseConfig {
    pub rules: Vec<CustomResponseRule>,
    /// Value for the HTTP `Server` header on synthesized (static/base64)
    /// responses, from the listener's `server_version`. Defaults to "NetTrap".
    /// `type=file` responses are served verbatim and are unaffected.
    server_version: String,
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
    pub fn parse(config_str: &str) -> crate::Result<Self> {
        if config_str.is_empty() {
            return Err(crate::Error::Config(
                "Custom response config must not be blank".to_string(),
            ));
        }

        let mut rules = Vec::new();

        for rule_str in config_str.split("||") {
            let rule_str = trim_ascii_edges(rule_str);
            if rule_str.is_empty() {
                return Err(crate::Error::Config(
                    "Custom response rule segment must not be blank".to_string(),
                ));
            }
            if rules.len() >= MAX_CUSTOM_RESPONSE_RULES {
                return Err(crate::Error::Config(format!(
                    "Too many custom response rules (max {})",
                    MAX_CUSTOM_RESPONSE_RULES
                )));
            }

            let mut hosts = Vec::new();
            let mut uris = Vec::new();
            let mut response_type = None;
            let mut body = String::new();
            let mut payload_field = None;
            let mut content_type = None;
            let mut saw_host = false;
            let mut saw_uri = false;
            let mut saw_type = false;
            let mut saw_body = false;
            let mut saw_content_type = false;

            for part in split_rule_fields(rule_str)? {
                let part = trim_ascii_edges(&part);
                if let Some(val) = part.strip_prefix("host=") {
                    if saw_host {
                        return Err(crate::Error::Config(
                            "Duplicate custom response rule field 'host'".to_string(),
                        ));
                    }
                    ensure_rule_token_is_safe(val, "host")?;
                    ensure_rule_list_items_are_safe(val, "host")?;
                    saw_host = true;
                    hosts = normalize_rule_list(val, "host", normalize_rule_host)?;
                    if hosts.iter().any(|host| host.is_empty()) {
                        return Err(crate::Error::Config(
                            "Invalid custom response rule field 'host': invalid host matcher"
                                .to_string(),
                        ));
                    }
                } else if let Some(val) = part.strip_prefix("uri=") {
                    if saw_uri {
                        return Err(crate::Error::Config(
                            "Duplicate custom response rule field 'uri'".to_string(),
                        ));
                    }
                    ensure_rule_token_is_safe(val, "uri")?;
                    ensure_rule_list_items_are_safe(val, "uri")?;
                    saw_uri = true;
                    uris = normalize_rule_list(val, "uri", normalize_rule_uri)?;
                } else if let Some(val) = part.strip_prefix("type=") {
                    if saw_type {
                        return Err(crate::Error::Config(
                            "Duplicate custom response rule field 'type'".to_string(),
                        ));
                    }
                    ensure_rule_token_is_safe(val, "type")?;
                    saw_type = true;
                    response_type = Some(normalize_rule_type(val));
                } else if let Some(val) = part.strip_prefix("body=") {
                    if saw_body {
                        return Err(crate::Error::Config(
                            "Duplicate custom response rule field 'body'".to_string(),
                        ));
                    }
                    saw_body = true;
                    payload_field = Some("body");
                    body = val.to_string();
                } else if let Some(val) = part.strip_prefix("content_type=") {
                    if saw_content_type {
                        return Err(crate::Error::Config(
                            "Duplicate custom response rule field 'content_type'".to_string(),
                        ));
                    }
                    ensure_rule_token_is_safe(val, "content_type")?;
                    saw_content_type = true;
                    content_type = Some(normalize_rule_header_value(val));
                } else if let Some(val) = part.strip_prefix("path=") {
                    if saw_body {
                        return Err(crate::Error::Config(
                            "Duplicate custom response rule field 'path'".to_string(),
                        ));
                    }
                    ensure_path_field_is_safe(val)?;
                    saw_body = true;
                    payload_field = Some("path");
                    body = val.to_string();
                } else if let Some(val) = part.strip_prefix("data=") {
                    if saw_body {
                        return Err(crate::Error::Config(
                            "Duplicate custom response rule field 'data'".to_string(),
                        ));
                    }
                    saw_body = true;
                    payload_field = Some("data");
                    body = val.to_string();
                } else if !part.is_empty() {
                    return Err(crate::Error::Config(format!(
                        "Unknown custom response rule field '{}'",
                        part
                    )));
                }
            }

            let response = match response_type.as_deref() {
                Some("static") | None => {
                    if matches!(payload_field, Some("path") | Some("data")) {
                        return Err(crate::Error::Config(
                            "Custom response rule type 'file' or 'base64' is required for path= or data=".to_string(),
                        ));
                    }
                    if body.len() > MAX_CUSTOM_RESPONSE_BYTES {
                        return Err(crate::Error::Config(format!(
                            "Custom response static body exceeds size limit ({} > {} bytes)",
                            body.len(),
                            MAX_CUSTOM_RESPONSE_BYTES
                        )));
                    }
                    CustomResponseType::HttpStaticString(body)
                }
                Some("file") => {
                    if payload_field != Some("path") || body.is_empty() {
                        return Err(crate::Error::Config(
                            "Custom response rule type 'file' requires non-empty path=".to_string(),
                        ));
                    }
                    CustomResponseType::HttpRawFile(body)
                }
                Some("base64") => {
                    if payload_field != Some("data") || body.is_empty() {
                        return Err(crate::Error::Config(
                            "Custom response rule type 'base64' requires non-empty data="
                                .to_string(),
                        ));
                    }
                    if body.len() > MAX_CUSTOM_RESPONSE_BASE64_CONFIG_BYTES {
                        return Err(crate::Error::Config(format!(
                            "Custom response base64 data exceeds encoded size limit ({} > {} bytes)",
                            body.len(),
                            MAX_CUSTOM_RESPONSE_BASE64_CONFIG_BYTES
                        )));
                    }
                    use base64::Engine as _;
                    match base64::engine::general_purpose::STANDARD.decode(&body) {
                        Ok(decoded) if decoded.len() <= MAX_CUSTOM_RESPONSE_BYTES => {
                            CustomResponseType::HttpBase64(decoded)
                        }
                        Ok(decoded) => {
                            return Err(crate::Error::Config(format!(
                                "Custom response base64 data exceeds decoded size limit ({} > {} bytes)",
                                decoded.len(),
                                MAX_CUSTOM_RESPONSE_BYTES
                            )));
                        }
                        Err(e) => {
                            return Err(crate::Error::Config(format!(
                                "Invalid base64 in custom response rule: {}",
                                e
                            )));
                        }
                    }
                }
                Some(unknown) => {
                    return Err(crate::Error::Config(format!(
                        "Unknown custom response rule type '{}'",
                        unknown
                    )));
                }
            };

            rules.push(CustomResponseRule {
                hosts,
                uris,
                response,
                content_type,
            });
        }

        Ok(Self {
            rules,
            server_version: "NetTrap".to_string(),
        })
    }

    /// Override the HTTP `Server` header used for synthesized static/base64
    /// responses (from the listener's `server_version`). When unset, NetTrap is
    /// used. Mirrors `WebrootServer::with_server_version` so all HTTP response
    /// paths present a consistent Server header.
    pub fn with_server_version(mut self, version: Option<&str>) -> crate::Result<Self> {
        if let Some(version) = version
            && let Some(valid) = validate_http_header_value(version, "server_version")?
        {
            self.server_version = valid;
        }
        Ok(self)
    }

    /// Find matching rule for a request
    pub fn find_match(&self, host: &str, uri: &str) -> Option<&CustomResponseRule> {
        let uri_candidates = uri_match_candidates(uri);
        for rule in &self.rules {
            let host_match =
                rule.hosts.is_empty() || rule.hosts.iter().any(|h| host_matches_pattern(host, h));
            let uri_match = rule.uris.is_empty()
                || rule.uris.iter().any(|pattern| {
                    uri_candidates
                        .iter()
                        .any(|candidate| uri_matches_pattern(candidate, pattern))
                });

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
        let rule = if request_target == route_uri {
            self.find_match(host, route_uri)
        } else {
            self.find_match(host, request_target)
                .or_else(|| self.find_match(host, route_uri))
        }?;
        let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");

        let mut vars = std::collections::HashMap::new();
        vars.insert("host".to_string(), host.to_string());
        vars.insert("uri".to_string(), request_target.to_string());
        vars.insert("server".to_string(), self.server_version.clone());

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
                        Some(payload_too_large_response(
                            &date.to_string(),
                            &self.server_version,
                        ))
                    }
                    Ok(LimitedFileRead::NotFile) => {
                        tracing::warn!("Custom response file {} is not a regular file", path);
                        Some(internal_server_error_response(
                            &date.to_string(),
                            &self.server_version,
                        ))
                    }
                    Err(e) => {
                        tracing::warn!("Failed to read custom response file {}: {}", path, e);
                        Some(internal_server_error_response(
                            &date.to_string(),
                            &self.server_version,
                        ))
                    }
                }
            }
            CustomResponseType::HttpStaticString(body) => {
                let ct = match resolve_response_content_type(
                    rule.content_type.as_deref(),
                    "text/html",
                    "content_type",
                    &date.to_string(),
                    &self.server_version,
                ) {
                    Ok(ct) => ct,
                    Err(response) => return Some(response),
                };
                let body_replaced = body.replace("<RAW-DATE>", &date.to_string());
                let body_rendered = match crate::template::render_template(&body_replaced, &vars) {
                    Ok(rendered) => rendered,
                    Err(err) => {
                        tracing::error!(
                            "Failed to render custom response template for rule {:?}: {}",
                            rule,
                            err
                        );
                        return Some(internal_server_error_response(
                            &date.to_string(),
                            &self.server_version,
                        ));
                    }
                };
                if body_rendered.len() > MAX_CUSTOM_RESPONSE_BYTES {
                    tracing::warn!(
                        "Custom static response body exceeds response size limit ({} > {})",
                        body_rendered.len(),
                        MAX_CUSTOM_RESPONSE_BYTES
                    );
                    return Some(payload_too_large_response(
                        &date.to_string(),
                        &self.server_version,
                    ));
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nDate: {}\r\nServer: {}\r\n\r\n{}",
                    ct,
                    body_rendered.len(),
                    date,
                    self.server_version,
                    body_rendered
                );
                Some(response.into_bytes())
            }
            CustomResponseType::HttpBase64(decoded) => {
                let ct = match resolve_response_content_type(
                    rule.content_type.as_deref(),
                    "application/octet-stream",
                    "content_type",
                    &date.to_string(),
                    &self.server_version,
                ) {
                    Ok(ct) => ct,
                    Err(response) => return Some(response),
                };
                let mut response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nDate: {}\r\nServer: {}\r\n\r\n",
                    ct, decoded.len(), date, self.server_version
                ).into_bytes();
                response.extend_from_slice(decoded);
                Some(response)
            }
        }
    }
}

fn payload_too_large_response(date: &str, server: &str) -> Vec<u8> {
    let body = "Payload Too Large";
    format!(
        "HTTP/1.1 413 Payload Too Large\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nDate: {}\r\nServer: {}\r\n\r\n{}",
        body.len(),
        date,
        server,
        body
    )
    .into_bytes()
}

fn internal_server_error_response(date: &str, server: &str) -> Vec<u8> {
    let body = "Internal Server Error";
    format!(
        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nDate: {}\r\nServer: {}\r\n\r\n{}",
        body.len(),
        date,
        server,
        body
    )
    .into_bytes()
}

fn split_rule_fields(rule: &str) -> crate::Result<Vec<String>> {
    let mut fields = Vec::new();
    let parts: Vec<&str> = rule.split(';').collect();
    for (idx, part) in parts.iter().enumerate() {
        let part = trim_ascii_edges(part);
        if part.is_empty() {
            return Err(crate::Error::Config(
                "Custom response rule segment must not be blank".to_string(),
            ));
        }
        if part.starts_with("host=") || part.starts_with("uri=") {
            fields.extend(
                split_embedded_key_fields(part)
                    .into_iter()
                    .map(str::to_string),
            );
        } else if part.starts_with("body=") {
            let mut value = String::from(part);
            if idx + 1 < parts.len() {
                let tail_fields: Vec<&str> = parts[idx + 1..]
                    .iter()
                    .map(|part| trim_ascii_edges(part))
                    .collect();
                if tail_fields
                    .iter()
                    .copied()
                    .find(|part| starts_with_rule_field_assignment(part))
                    .is_some()
                {
                    fields.push(value);
                    continue;
                }
                let tail = tail_fields.join(";");
                value.push(';');
                value.push_str(&tail);
            }
            fields.push(value);
            break;
        } else if part.starts_with("type=")
            || part.starts_with("path=")
            || part.starts_with("data=")
        {
            fields.push(part.to_string());
        } else if part.starts_with("content_type=") {
            let mut value = String::from(part);
            if idx + 1 < parts.len() {
                let raw_tail_fields: Vec<&str> = parts[idx + 1..].to_vec();
                let tail_fields: Vec<&str> = raw_tail_fields
                    .iter()
                    .copied()
                    .map(trim_ascii_edges)
                    .collect();
                if let Some(next_field) = tail_fields
                    .iter()
                    .copied()
                    .find(|part| starts_with_known_field(part))
                {
                    return Err(crate::Error::Config(format!(
                        "Unknown custom response rule field '{}'",
                        next_field
                    )));
                }
                let tail = raw_tail_fields.join(";");
                value.push(';');
                value.push_str(&tail);
            }
            fields.push(value);
            break;
        } else {
            return Err(crate::Error::Config(format!(
                "Unknown custom response rule field '{}'",
                part
            )));
        }
    }
    Ok(fields)
}

fn split_embedded_key_fields(value: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut start = 0usize;
    let bytes = value.as_bytes();
    for idx in 0..bytes.len() {
        if bytes[idx] == b',' && starts_with_rule_field_assignment(&value[idx + 1..]) {
            fields.push(trim_ascii_edges(&value[start..idx]));
            start = idx + 1;
        }
    }
    let tail = trim_ascii_edges(&value[start..]);
    if !tail.is_empty() {
        fields.push(tail);
    }
    fields
}

fn starts_with_known_field(value: &str) -> bool {
    matches!(
        trim_ascii_start(value),
        value if value.starts_with("host=")
            || value.starts_with("uri=")
            || value.starts_with("type=")
            || value.starts_with("body=")
            || value.starts_with("path=")
            || value.starts_with("data=")
            || value.starts_with("content_type=")
    )
}

fn starts_with_rule_field_assignment(value: &str) -> bool {
    let value = trim_ascii_start(value);
    if starts_with_known_field(value) {
        return true;
    }

    value
        .split_once('=')
        .is_some_and(|(field, _)| is_rule_field_name(field))
}

fn is_rule_field_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn validate_http_header_value(value: &str, field: &str) -> crate::Result<Option<String>> {
    if value.is_empty() {
        return Ok(None);
    }

    if value.trim_matches([' ', '\t']) != value {
        return Err(crate::Error::Config(format!(
            "Custom response {} header value cannot be padded",
            field
        )));
    }

    if value.chars().any(|ch| {
        matches!(ch, '\r' | '\n' | '\u{0085}' | '\u{2028}' | '\u{2029}')
            || (ch.is_control() && ch != '\t')
            || (ch.is_whitespace() && ch != ' ')
    }) {
        return Err(crate::Error::Config(format!(
            "Custom response {} header value contains unsafe characters",
            field
        )));
    }

    Ok(Some(value.to_string()))
}

fn resolve_response_content_type(
    value: Option<&str>,
    default: &'static str,
    field: &str,
    date: &str,
    server: &str,
) -> std::result::Result<String, Vec<u8>> {
    match value {
        None => Ok(default.to_string()),
        Some(value) => match validate_http_header_value(value, field) {
            Ok(Some(valid)) => Ok(valid),
            Ok(None) => Ok(default.to_string()),
            Err(_) => Err(internal_server_error_response(date, server)),
        },
    }
}

pub(crate) fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    let host = trim_ascii_edges(host);
    if contains_unicode_whitespace_or_control(host) {
        return false;
    }

    if pattern == "*" {
        return host.is_empty() || normalize_http_host_with_port(host).is_some();
    }

    let Some((host, host_port)) = normalize_http_host_with_port_for_match(host) else {
        return false;
    };
    let Some((pattern, pattern_port)) = normalize_http_host_with_port_for_match(pattern) else {
        let Ok(pattern_ip) = pattern.parse::<std::net::IpAddr>() else {
            return false;
        };
        let Ok(host_ip) = host.parse::<std::net::IpAddr>() else {
            return false;
        };
        return host_ip == pattern_ip;
    };

    let host_match = host == pattern || host.ends_with(&format!(".{}", pattern));
    if !host_match {
        return false;
    }

    match (host_port, pattern_port) {
        (None, Some(_)) => false,
        (Some(host_port), Some(pattern_port)) => host_port == pattern_port,
        _ => true,
    }
}

fn normalize_http_host_with_port(host: &str) -> Option<(String, Option<u16>)> {
    let host = trim_ascii_edges(host);
    if contains_unicode_whitespace_or_control(host) {
        return None;
    }

    let host = host.to_ascii_lowercase();

    if let Some(rest) = host.strip_prefix('[') {
        let (inner, suffix) = rest.split_once(']')?;
        let Ok(ip) = inner.parse::<std::net::Ipv6Addr>() else {
            return None;
        };
        if is_special_http_authority_ip_literal(&std::net::IpAddr::V6(ip)) {
            return None;
        }
        let normalized = ip
            .to_ipv4_mapped()
            .map_or_else(|| ip.to_string(), |mapped| mapped.to_string());
        if suffix.is_empty() {
            return Some((normalized, None));
        }
        let port = suffix.strip_prefix(':').and_then(parse_http_port)?;
        return Some((normalized, Some(port)));
    }

    if host.contains(':')
        && let Ok(ip) = host.parse::<std::net::IpAddr>()
    {
        return match ip {
            std::net::IpAddr::V4(ip)
                if !is_special_http_authority_ip_literal(&std::net::IpAddr::V4(ip)) =>
            {
                Some((ip.to_string(), None))
            }
            std::net::IpAddr::V4(_) => None,
            std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped().and_then(|mapped| {
                (!is_special_http_authority_ip_literal(&std::net::IpAddr::V4(mapped)))
                    .then_some((mapped.to_string(), None))
            }),
        };
    }

    if let Some((base, port)) = host.rsplit_once(':') {
        if !base.contains(':') && !base.is_empty() && parse_http_port(port).is_some() {
            let port = parse_http_port(port)?;
            if let Ok(ip) = base.parse::<std::net::Ipv4Addr>() {
                if is_special_http_authority_ip_literal(&std::net::IpAddr::V4(ip)) {
                    return None;
                }
                return Some((ip.to_string(), Some(port)));
            }
            let normalized = normalize_domain_host(base);
            return (!normalized.is_empty()).then_some((normalized, Some(port)));
        }
        return None;
    }

    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        if is_special_http_authority_ip_literal(&std::net::IpAddr::V4(ip)) {
            return None;
        }
        return Some((ip.to_string(), None));
    }

    let normalized = normalize_domain_host(&host);
    (!normalized.is_empty()).then_some((normalized, None))
}

fn normalize_http_host_with_port_for_match(host: &str) -> Option<(String, Option<u16>)> {
    let host = trim_ascii_edges(host);
    if contains_unicode_whitespace_or_control(host) {
        return None;
    }

    let host = host.to_ascii_lowercase();

    if let Some(rest) = host.strip_prefix('[') {
        let (inner, suffix) = rest.split_once(']')?;
        let Ok(ip) = inner.parse::<std::net::Ipv6Addr>() else {
            return None;
        };
        let normalized = ip
            .to_ipv4_mapped()
            .map_or_else(|| ip.to_string(), |mapped| mapped.to_string());
        if suffix.is_empty() {
            return Some((normalized, None));
        }
        let port = suffix.strip_prefix(':').and_then(parse_http_port)?;
        return Some((normalized, Some(port)));
    }

    if let Ok(std::net::IpAddr::V6(ip)) = host.parse::<std::net::IpAddr>() {
        let normalized = ip.to_ipv4_mapped()?.to_string();
        return Some((normalized, None));
    }

    if let Some((base, port)) = host.rsplit_once(':') {
        if !base.contains(':') && !base.is_empty() && parse_http_port(port).is_some() {
            let port = parse_http_port(port)?;
            if let Ok(ip) = base.parse::<std::net::Ipv4Addr>() {
                return Some((ip.to_string(), Some(port)));
            }
            let normalized = normalize_domain_host(base);
            return (!normalized.is_empty()).then_some((normalized, Some(port)));
        }
        return None;
    }

    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return Some((ip.to_string(), None));
    }

    let normalized = normalize_domain_host(&host);
    (!normalized.is_empty()).then_some((normalized, None))
}

fn normalize_domain_host(host: &str) -> String {
    let host = if let Some(host) = host.strip_suffix('.') {
        if host.is_empty() || host.ends_with('.') {
            return String::new();
        }
        host
    } else {
        host
    };
    if host.len() > 253 {
        return String::new();
    }
    if !has_valid_domain_labels(host) || has_numeric_domain_labels(host) {
        return String::new();
    }
    if !has_valid_domain_label_lengths(host) {
        return String::new();
    }
    host.to_string()
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

fn uri_match_candidates(uri: &str) -> Vec<String> {
    let exact = uri.to_string();
    let lookup = normalize_uri_for_lookup(uri);
    if lookup == exact {
        vec![exact]
    } else {
        vec![exact, lookup]
    }
}

fn normalize_uri_for_lookup(uri: &str) -> String {
    let mut normalized = String::with_capacity(uri.len());
    for segment in uri.split('/') {
        let segment = segment.split_once(';').map_or(segment, |(head, _)| head);
        if !segment.is_empty() {
            if !normalized.is_empty() {
                normalized.push('/');
            }
            normalized.push_str(segment);
        }
    }

    if uri.starts_with('/') {
        normalized.insert(0, '/');
    }
    if uri.ends_with('/') && !normalized.ends_with('/') {
        normalized.push('/');
    }
    if normalized.is_empty() {
        "/".to_string()
    } else {
        normalized
    }
}

fn trim_ascii_start(value: &str) -> &str {
    value.trim_start_matches([' ', '\t'])
}

fn contains_unicode_whitespace_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
}

fn normalize_rule_host(value: &str) -> String {
    let trimmed = trim_ascii_edges(value);
    if trimmed == "*" {
        return "*".to_string();
    }
    if trimmed.contains('*') {
        return String::new();
    }
    let Some((normalized, port)) = normalize_http_host_with_port(trimmed) else {
        return String::new();
    };
    if normalized.is_empty() || normalized == "*" {
        return normalized;
    }

    match port {
        Some(port) if normalized.contains(':') => format!("[{}]:{}", normalized, port),
        Some(port) => format!("{}:{}", normalized, port),
        None => normalized,
    }
}

fn normalize_rule_uri(value: &str) -> String {
    trim_ascii_edges(value).to_string()
}

fn normalize_rule_type(value: &str) -> String {
    trim_ascii_edges(value).to_ascii_lowercase()
}

fn normalize_rule_header_value(value: &str) -> String {
    trim_ascii_edges(value).to_string()
}

fn ensure_rule_token_is_safe(value: &str, field: &str) -> crate::Result<()> {
    if value.trim_matches([' ', '\t']) != value {
        return Err(crate::Error::Config(format!(
            "Invalid custom response rule field '{}': invalid whitespace",
            field
        )));
    }

    if value.is_empty() || contains_unicode_whitespace_or_control(value) {
        return Err(crate::Error::Config(format!(
            "Invalid custom response rule field '{}': invalid whitespace",
            field
        )));
    }
    Ok(())
}

fn ensure_rule_list_items_are_safe(value: &str, field: &str) -> crate::Result<()> {
    for item in value.split(',') {
        ensure_rule_token_is_safe(item, field)?;
        if field == "host" && item.contains('=') {
            return Err(crate::Error::Config(format!(
                "Unknown custom response rule field '{}'",
                trim_ascii_edges(item)
            )));
        }
    }
    Ok(())
}

fn ensure_path_field_is_safe(value: &str) -> crate::Result<()> {
    if value.trim_matches([' ', '\t']) != value {
        return Err(crate::Error::Config(
            "Invalid custom response rule field 'path': invalid whitespace".to_string(),
        ));
    }
    if contains_unicode_whitespace_or_control(value) {
        return Err(crate::Error::Config(
            "Invalid custom response rule field 'path': contains control characters or unicode whitespace".to_string(),
        ));
    }
    Ok(())
}

fn is_special_http_authority_ip_literal(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()
        }
        std::net::IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.to_ipv4_mapped().is_some_and(|mapped| {
                    is_special_http_authority_ip_literal(&std::net::IpAddr::V4(mapped))
                })
        }
    }
}

fn normalize_rule_list(
    value: &str,
    field: &str,
    normalize: fn(&str) -> String,
) -> crate::Result<Vec<String>> {
    let mut normalized = Vec::new();
    for item in value.split(',') {
        if normalized.len() >= MAX_CUSTOM_RESPONSE_MATCHERS_PER_FIELD {
            return Err(crate::Error::Config(format!(
                "Too many custom response {} matchers (max {})",
                field, MAX_CUSTOM_RESPONSE_MATCHERS_PER_FIELD
            )));
        }
        normalized.push(normalize(item));
    }
    Ok(normalized)
}

#[cfg(test)]
#[path = "custom_response_tests.rs"]
mod tests;
