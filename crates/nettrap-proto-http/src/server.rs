use async_trait::async_trait;
use parking_lot::RwLock;

use crate::parser::parse_http_request_bytes;
use crate::prelude::*;
use crate::request::{normalize_host_header_value, request_target_host};
use nettrap_core::parse::absolute_http_authority as absolute_form_authority;
use nettrap_core::parse::nonzero_port as parse_http_port;
use nettrap_core::sanitize::{
    has_numeric_domain_labels, has_valid_domain_label_lengths, has_valid_domain_labels,
};

const MAX_RESPONSE_BODY_BYTES: usize = 10 * 1024 * 1024;
const MAX_CUSTOM_RESPONSES: usize = 256;
const MAX_CUSTOM_RESPONSE_PATH_BYTES: usize = 2048;

pub struct HttpServer {
    bind_address: std::net::SocketAddr,
    default_response: String,
    custom_responses: RwLock<std::collections::BTreeMap<String, String>>,
}

impl HttpServer {
    pub fn new(bind_address: std::net::SocketAddr) -> Self {
        Self {
            bind_address,
            default_response: "<html></html>".to_string(),
            custom_responses: RwLock::new(std::collections::BTreeMap::new()),
        }
    }

    pub fn bind_address(&self) -> std::net::SocketAddr {
        self.bind_address
    }

    pub fn add_custom_response(
        &self,
        path: impl Into<String>,
        response: impl Into<String>,
    ) -> Result<()> {
        let Some(path) = normalize_request_path(&path.into()) else {
            return Err(Error::Config(
                "Invalid HTTP custom response path".to_string(),
            ));
        };
        if path.len() > MAX_CUSTOM_RESPONSE_PATH_BYTES {
            return Err(Error::Config(format!(
                "HTTP custom response path exceeds size limit ({} > {} bytes)",
                path.len(),
                MAX_CUSTOM_RESPONSE_PATH_BYTES
            )));
        }

        let response = bounded_response_body(response.into())?;
        let mut custom_responses = self.custom_responses.write();
        if !custom_responses.contains_key(&path) && custom_responses.len() >= MAX_CUSTOM_RESPONSES {
            return Err(Error::Config(format!(
                "Too many HTTP custom responses (max {})",
                MAX_CUSTOM_RESPONSES
            )));
        }
        custom_responses.insert(path, response);
        Ok(())
    }

    pub fn remove_custom_response(&self, path: &str) -> Result<()> {
        let Some(exact_path) = normalize_request_path(path) else {
            return Err(Error::Config(
                "Invalid HTTP custom response path".to_string(),
            ));
        };
        let lookup_path = normalize_request_path_for_lookup(&exact_path);
        let mut custom_responses = self.custom_responses.write();
        if custom_responses.remove(exact_path.as_str()).is_none() && lookup_path != exact_path {
            custom_responses.remove(lookup_path.as_str());
        }
        Ok(())
    }

    fn build_response(&self, request: &HttpRequest) -> HttpResponse {
        let exact_path = normalize_request_path(request.uri.as_str());
        let lookup_path = exact_path
            .as_deref()
            .map(normalize_request_path_for_lookup)
            .unwrap_or_default();

        let body = exact_path
            .as_ref()
            .and_then(|path| self.custom_responses.read().get(path.as_str()).cloned())
            .or_else(|| {
                if lookup_path != exact_path.as_deref().unwrap_or_default() {
                    self.custom_responses
                        .read()
                        .get(lookup_path.as_str())
                        .cloned()
                } else {
                    None
                }
            })
            .unwrap_or_else(|| self.default_response.clone());

        HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            headers: std::collections::BTreeMap::from([
                ("Content-Type".to_string(), "text/html".to_string()),
                ("Content-Length".to_string(), body.len().to_string()),
            ]),
            body: body.into_bytes(),
            suppress_body: false,
        }
    }
}

fn normalize_request_path_for_lookup(target: &str) -> String {
    let path = target.split(['?', '#']).next().unwrap_or(target);
    let mut normalized = String::with_capacity(path.len());

    for segment in path.split('/') {
        let segment = segment.split_once(';').map_or(segment, |(head, _)| head);
        if !segment.is_empty() {
            if !normalized.is_empty() {
                normalized.push('/');
            }
            normalized.push_str(segment);
        }
    }

    if path.starts_with('/') {
        normalized.insert(0, '/');
    }
    if path.ends_with('/') && !normalized.ends_with('/') {
        normalized.push('/');
    }
    if normalized.is_empty() {
        "/".to_string()
    } else {
        normalized
    }
}

fn bounded_response_body(response: String) -> Result<String> {
    if response.len() > MAX_RESPONSE_BODY_BYTES {
        return Err(Error::Config(format!(
            "HTTP response body exceeds size limit ({} > {} bytes)",
            response.len(),
            MAX_RESPONSE_BODY_BYTES
        )));
    }
    Ok(response)
}

fn normalize_request_path(target: &str) -> Option<String> {
    if target.is_empty() {
        return None;
    }
    if nettrap_core::sanitize::contains_unicode_line_separator(target) {
        return None;
    }
    if target == "*" {
        return Some(target.to_string());
    }

    if is_special_authority_like_target(target) {
        return None;
    }

    if is_valid_authority_port(target) {
        let normalized = normalize_authority_target_case(target);
        return normalized;
    }

    if target.contains(':')
        && !target.starts_with('/')
        && !target.contains("://")
        && !nettrap_core::parse::looks_like_windows_drive_path(target)
    {
        return None;
    }

    if let Some(authority) = absolute_form_authority(target) {
        if !is_valid_authority_port(authority) {
            return None;
        }
    } else if target.contains("://") {
        return None;
    }

    if nettrap_core::parse::looks_like_windows_drive_path(target) {
        return None;
    }

    let normalized = target.replace('\\', "/");
    let path = if let Some(scheme_pos) = normalized.find("://") {
        let scheme = &normalized[..scheme_pos];
        if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
            let rest = &normalized[scheme_pos + 3..];
            rest.find('/').map(|pos| &rest[pos..]).unwrap_or("/")
        } else {
            normalized.as_str()
        }
    } else {
        normalized.as_str()
    };

    let path = path.split('#').next().unwrap_or(path);
    let path = path.split('?').next().unwrap_or(path);

    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            _ => components.push(component),
        }
    }

    if components.is_empty() {
        Some("/".to_string())
    } else {
        Some(format!("/{}", components.join("/")))
    }
}

fn is_special_authority_like_target(target: &str) -> bool {
    let Some((host, port)) = target.rsplit_once(':') else {
        return false;
    };
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }

    if let Some(rest) = host.strip_prefix('[') {
        let Some((inner, suffix)) = rest.split_once(']') else {
            return false;
        };
        let Ok(ip) = inner.parse::<std::net::Ipv6Addr>() else {
            return false;
        };
        if !is_special_http_authority_ipv6_literal(ip) {
            return false;
        }
        return suffix.is_empty()
            || (suffix.starts_with(':')
                && suffix[1..].bytes().all(|byte| byte.is_ascii_digit())
                && suffix[1..]
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .is_some());
    }

    host.parse::<std::net::Ipv4Addr>()
        .is_ok_and(is_special_http_authority_ipv4_literal)
}

fn is_valid_authority_port(authority: &str) -> bool {
    if authority.contains('@') {
        return false;
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let Some((inner, suffix)) = rest.split_once(']') else {
            return false;
        };
        if inner.is_empty() || !suffix.is_empty() && !suffix.starts_with(':') {
            return false;
        }
        if suffix.is_empty() {
            return inner
                .parse::<std::net::Ipv6Addr>()
                .is_ok_and(is_usable_http_authority_ipv6_literal);
        }
        if suffix[1..].contains(':') {
            return false;
        }
        return inner
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(is_usable_http_authority_ipv6_literal)
            && parse_http_port(&suffix[1..]).is_some();
    }

    if let Some((host, port)) = authority.rsplit_once(':') {
        if host.is_empty() {
            return false;
        }
        if host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(is_usable_http_authority_ipv4_literal)
        {
            return parse_http_port(port).is_some();
        }
        return host_is_valid_authority_host(host) && parse_http_port(port).is_some();
    }

    if authority
        .parse::<std::net::Ipv4Addr>()
        .is_ok_and(is_usable_http_authority_ipv4_literal)
    {
        return true;
    }
    host_is_valid_authority_host(authority)
}

fn host_is_valid_authority_host(host: &str) -> bool {
    let host = if let Some(host) = host.strip_suffix('.') {
        if host.is_empty() || host.ends_with('.') {
            return false;
        }
        host
    } else {
        host
    };
    !host.contains(':')
        && !host.contains('/')
        && !host.contains('\\')
        && !host.contains('?')
        && !host.contains('#')
        && host.len() <= 253
        && has_valid_domain_labels(host)
        && has_valid_domain_label_lengths(host)
        && !has_numeric_domain_labels(host)
}

fn is_usable_http_authority_ipv4_literal(ip: std::net::Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
}

fn is_usable_http_authority_ipv6_literal(ip: std::net::Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_usable_http_authority_ipv4_literal(mapped);
    }

    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
}

fn is_special_http_authority_ipv4_literal(ip: std::net::Ipv4Addr) -> bool {
    ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()
}

fn is_special_http_authority_ipv6_literal(ip: std::net::Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_special_http_authority_ipv4_literal(mapped);
    }

    ip.is_unspecified() || ip.is_loopback() || ip.is_multicast()
}

fn normalize_authority_target_case(target: &str) -> Option<String> {
    if let Some(rest) = target.strip_prefix('[') {
        let (inner, suffix) = rest.split_once(']')?;
        let Ok(ip) = inner.parse::<std::net::Ipv6Addr>() else {
            return None;
        };
        if !is_usable_http_authority_ipv6_literal(ip) {
            return None;
        }
        let mapped = ip.to_ipv4_mapped();
        let inner = mapped.map_or_else(|| ip.to_string(), |mapped| mapped.to_string());
        return if mapped.is_some() {
            if suffix.is_empty() {
                Some(inner)
            } else {
                let port = suffix.strip_prefix(':')?;
                parse_http_port(port).map(|port| format!("{}:{}", inner, port))
            }
        } else {
            if suffix.is_empty() {
                Some(format!("[{}]", inner))
            } else {
                let port = suffix.strip_prefix(':')?;
                parse_http_port(port).map(|port| format!("[{}]:{}", inner, port))
            }
        };
    }

    if let Some((host, port)) = target.rsplit_once(':') {
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            if !is_usable_http_authority_ipv4_literal(ip) {
                return None;
            }
            return parse_http_port(port).map(|port| format!("{}:{}", ip, port));
        }

        let lowered = host.to_ascii_lowercase();
        return host_is_valid_authority_host(&lowered)
            .then(|| parse_http_port(port).map(|port| format!("{}:{}", lowered, port)))
            .flatten();
    }

    if let Ok(ip) = target.parse::<std::net::Ipv4Addr>() {
        if !is_usable_http_authority_ipv4_literal(ip) {
            return None;
        }
        return Some(ip.to_string());
    }

    let lowered = target.to_ascii_lowercase();
    host_is_valid_authority_host(&lowered).then_some(lowered)
}

#[async_trait]
impl HttpHandlerTrait for HttpServer {
    async fn handle_request(&self, request: HttpRequest) -> Result<HttpResponse> {
        tracing::debug!(
            "HTTP request: {} {} {}",
            request.method,
            request.uri,
            request.version
        );
        let mut response = self.build_response(&request);
        if request.method.eq_ignore_ascii_case("HEAD") {
            response.suppress_body = true;
        }
        Ok(response)
    }

    fn name(&self) -> &'static str {
        "http"
    }
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: std::collections::BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub has_body: bool,
}

impl HttpRequest {
    pub fn parse(data: &[u8]) -> Result<Option<Self>> {
        let parsed = match parse_http_request_bytes(data)? {
            Some(parsed) => parsed,
            None => return Ok(None),
        };
        if parsed.method.eq_ignore_ascii_case("CONNECT")
            && !crate::request::request_target_has_explicit_port(&parsed.target)
        {
            return Err(Error::Protocol(format!(
                "Invalid HTTP request-target authority: {}",
                parsed.target
            )));
        }

        let mut headers = std::collections::BTreeMap::new();
        let mut host = None;
        let mut host_header_seen = false;
        let mut host_header_count = 0usize;
        let mut user_agent = None;
        let has_body = parsed.headers.iter().any(|(name, _)| {
            name.eq_ignore_ascii_case("Content-Length")
                || name.eq_ignore_ascii_case("Transfer-Encoding")
        });

        for (key, value) in parsed.headers {
            let normalized_key = key.to_lowercase();

            if normalized_key == "host" {
                host_header_seen = true;
                host_header_count += 1;
                if host_header_count > 1 {
                    return Ok(None);
                }
                let normalized = normalize_host_header_value(&value);
                if normalized.is_empty() {
                    headers.insert(normalized_key, value);
                } else {
                    host = Some(normalized.clone());
                    headers.insert(normalized_key, normalized);
                }
                continue;
            } else if normalized_key == "user-agent" && !value.is_empty() {
                user_agent = Some(value.clone());
            }

            headers.insert(normalized_key, value);
        }
        if host.is_none() && !host_header_seen {
            host = request_target_host(&parsed.target)?;
        }

        Ok(Some(Self {
            method: parsed.method,
            uri: parsed.target,
            version: parsed.version,
            headers,
            body: parsed.body,
            host,
            user_agent,
            has_body,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub headers: std::collections::BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub suppress_body: bool,
}

impl HttpResponse {
    fn reason_phrase(status: u16) -> &'static str {
        match status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            301 => "Moved Permanently",
            302 => "Found",
            304 => "Not Modified",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            _ => "Unknown",
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        if self.headers.iter().any(|(key, value)| {
            !crate::header::is_valid_header_name(key)
                || !crate::header::is_valid_header_value(value)
        }) || !crate::header::is_valid_reason_phrase(&self.status_text)
        {
            return invalid_header_response();
        }
        let status_text = &self.status_text;
        let mut response = format!("HTTP/1.1 {} ", self.status_code).into_bytes();
        if let Some(status_bytes) = crate::header::header_value_to_bytes(status_text) {
            response.extend_from_slice(&status_bytes);
        } else {
            response.extend_from_slice(Self::reason_phrase(self.status_code).as_bytes());
        }
        response.extend_from_slice(b"\r\n");
        let mut headers = self.headers.clone();

        headers.retain(|key, _| {
            !key.eq_ignore_ascii_case("Content-Length")
                && !key.eq_ignore_ascii_case("Transfer-Encoding")
        });
        headers.insert(
            "Content-Length".to_string(),
            if response_has_no_body(self.status_code) {
                "0".to_string()
            } else {
                self.body.len().to_string()
            },
        );

        for (key, value) in &headers {
            if !crate::header::is_valid_header_name(key) {
                continue;
            }
            let Some(value_bytes) = crate::header::header_value_to_bytes(value) else {
                continue;
            };
            response.extend_from_slice(key.as_bytes());
            response.extend_from_slice(b": ");
            response.extend_from_slice(&value_bytes);
            response.extend_from_slice(b"\r\n");
        }

        response.extend_from_slice(b"\r\n");

        if !response_has_no_body(self.status_code) && !self.suppress_body {
            response.extend_from_slice(&self.body);
        }
        response
    }

    pub fn ok(html: impl Into<String>) -> Self {
        let body = html.into();
        Self {
            status_code: 200,
            status_text: "OK".to_string(),
            headers: std::collections::BTreeMap::from([
                ("Content-Type".to_string(), "text/html".to_string()),
                ("Content-Length".to_string(), body.len().to_string()),
            ]),
            body: body.into_bytes(),
            suppress_body: false,
        }
    }

    pub fn not_found(html: impl Into<String>) -> Self {
        let body = html.into();
        Self {
            status_code: 404,
            status_text: "Not Found".to_string(),
            headers: std::collections::BTreeMap::from([
                ("Content-Type".to_string(), "text/html".to_string()),
                ("Content-Length".to_string(), body.len().to_string()),
            ]),
            body: body.into_bytes(),
            suppress_body: false,
        }
    }
}

fn invalid_header_response() -> Vec<u8> {
    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 19\r\n\r\nInvalid HTTP header".to_vec()
}

fn response_has_no_body(status_code: u16) -> bool {
    matches!(status_code, 100..=199 | 204 | 205 | 304)
}

#[async_trait]
pub trait HttpHandlerTrait: Send + Sync {
    async fn handle_request(&self, request: HttpRequest) -> Result<HttpResponse>;
    fn name(&self) -> &'static str;
}

#[cfg(test)]
fn block_on_ready<F: std::future::Future>(future: F) -> F::Output {
    use std::pin::Pin;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn raw_waker() -> RawWaker {
        fn clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        fn wake(_: *const ()) {}
        fn wake_by_ref(_: *const ()) {}
        fn drop(_: *const ()) {}

        RawWaker::new(
            std::ptr::null(),
            &RawWakerVTable::new(clone, wake, wake_by_ref, drop),
        )
    }

    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut future = Box::pin(future);
    let mut cx = Context::from_waker(&waker);

    loop {
        match Pin::as_mut(&mut future).poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
