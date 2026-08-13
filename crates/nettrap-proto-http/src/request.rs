use nettrap_core::error::{Error, Result};

use crate::parser::{is_valid_http_host_name, parse_http_content_length, parse_http_request_bytes};

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub target: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub body: Option<Vec<u8>>,
    pub has_body: bool,
}

impl HttpRequest {
    pub fn parse(data: &[u8]) -> Result<Option<Self>> {
        let parsed = match parse_http_request_bytes(data)? {
            Some(parsed) => parsed,
            None => return Ok(None),
        };
        if parsed.method.eq_ignore_ascii_case("CONNECT")
            && !request_target_has_explicit_port(&parsed.target)
        {
            return Err(Error::Protocol(format!(
                "Invalid HTTP request-target authority: {}",
                parsed.target
            )));
        }
        let has_body = parsed.headers.iter().any(|(name, _)| {
            name.eq_ignore_ascii_case("Content-Length")
                || name.eq_ignore_ascii_case("Transfer-Encoding")
        });
        let body = if has_body {
            if parsed.body.is_empty() {
                None
            } else {
                Some(parsed.body)
            }
        } else {
            None
        };
        let mut headers = Vec::with_capacity(parsed.headers.len());
        let mut host = None;
        let mut host_header_seen = false;
        let mut host_header_count = 0usize;
        let mut user_agent = None;
        for (key, value) in parsed.headers {
            if key.eq_ignore_ascii_case("Host") {
                host_header_seen = true;
                host_header_count += 1;
                if host_header_count > 1 {
                    return Ok(None);
                }
                let normalized = normalize_host_header_value(&value);
                if normalized.is_empty() {
                    headers.push((key, value));
                } else {
                    host = Some(normalized.clone());
                    headers.push((key, normalized));
                }
            } else if key.eq_ignore_ascii_case("User-Agent") && !value.is_empty() {
                user_agent = Some(value.clone());
                headers.push((key, value));
            } else {
                headers.push((key, value));
            }
        }
        if host.is_none() && !host_header_seen {
            host = request_target_host(&parsed.target)?;
        }

        Ok(Some(Self {
            method: parsed.method,
            target: parsed.target,
            path: parsed.path,
            version: parsed.version,
            headers,
            body,
            has_body,
            host,
            user_agent,
        }))
    }

    pub fn header(&self, name: &str) -> Option<&String> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    pub fn host(&self) -> Option<&String> {
        self.host.as_ref()
    }

    pub fn content_length(&self) -> Option<usize> {
        self.header("Content-Length")
            .and_then(|s| parse_http_content_length(s))
    }
}

pub(crate) fn normalize_host_header_value(value: &str) -> String {
    let value = value.trim_matches([' ', '\t']);
    if let Some(rest) = value.strip_prefix('[') {
        let Some((inner, suffix)) = rest.split_once(']') else {
            return String::new();
        };
        let Ok(ip) = inner.parse::<std::net::Ipv6Addr>() else {
            return String::new();
        };
        if is_special_http_host_header_ip_literal(&std::net::IpAddr::V6(ip)) {
            return String::new();
        }
        let mapped = ip.to_ipv4_mapped();
        let inner = mapped.map_or_else(|| ip.to_string(), |mapped| mapped.to_string());
        return if mapped.is_some() {
            if suffix.is_empty() {
                inner
            } else {
                let Some(port) = suffix.strip_prefix(':') else {
                    return String::new();
                };
                if !is_http_port(port) {
                    return String::new();
                }
                let Some(port) = port.parse::<u16>().ok().filter(|port| *port != 0) else {
                    return String::new();
                };
                format!("{}:{}", inner, port)
            }
        } else {
            if suffix.is_empty() {
                format!("[{}]", inner)
            } else {
                let Some(port) = suffix.strip_prefix(':') else {
                    return String::new();
                };
                if !is_http_port(port) {
                    return String::new();
                }
                let Some(port) = port.parse::<u16>().ok().filter(|port| *port != 0) else {
                    return String::new();
                };
                format!("[{}]:{}", inner, port)
            }
        };
    }

    if let Some((host, port)) = value.rsplit_once(':')
        && !host.contains(':')
    {
        if !is_http_port(port) {
            return String::new();
        }
        let Some(port) = port.parse::<u16>().ok().filter(|port| *port != 0) else {
            return String::new();
        };
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            if is_special_http_authority_ipv4_literal(ip) {
                return String::new();
            }
            return format!("{ip}:{port}");
        }
        return normalize_host_component(host)
            .map(|host| format!("{host}:{port}"))
            .unwrap_or_default();
    }

    if value.contains(':') {
        return String::new();
    }

    if let Ok(ip) = value.parse::<std::net::Ipv4Addr>() {
        return if !is_special_http_authority_ipv4_literal(ip) {
            ip.to_string()
        } else {
            String::new()
        };
    }

    normalize_host_component(value).unwrap_or_default()
}

fn normalize_host_component(value: &str) -> Option<String> {
    if value
        .strip_suffix('.')
        .is_some_and(|host| host.parse::<std::net::Ipv4Addr>().is_ok())
    {
        return None;
    }

    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() || value.ends_with('.') {
        return None;
    }

    if let Ok(ip) = value.parse::<std::net::Ipv4Addr>() {
        return (!is_special_http_authority_ipv4_literal(ip)).then(|| ip.to_string());
    }

    if !is_valid_http_host_name(value) {
        return None;
    }
    if nettrap_core::sanitize::has_numeric_domain_labels(value) {
        return None;
    }

    Some(value.to_ascii_lowercase())
}

fn is_http_port(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u16>().ok().is_some_and(|port| port != 0)
}

fn is_special_http_host_header_ip_literal(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => is_special_http_authority_ipv4_literal(*ip),
        std::net::IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_special_http_authority_ipv4_literal(mapped);
            }

            ip.is_unspecified() || ip.is_loopback() || ip.is_multicast()
        }
    }
}

fn is_special_http_authority_ipv4_literal(ip: std::net::Ipv4Addr) -> bool {
    ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()
}

pub(crate) fn request_target_host(target: &str) -> Result<Option<String>> {
    if let Some(authority) = absolute_form_authority(target) {
        return canonicalize_target_authority(authority)
            .map(Some)
            .ok_or_else(|| invalid_request_target_authority(target));
    }

    if target.contains("://") || is_authority_form_like_target(target) {
        return canonicalize_target_authority(target)
            .map(Some)
            .ok_or_else(|| invalid_request_target_authority(target));
    }

    Ok(None)
}

fn canonicalize_target_authority(authority: &str) -> Option<String> {
    let normalized = normalize_host_header_value(authority);
    (!normalized.is_empty()).then_some(normalized)
}

pub(crate) fn request_target_has_explicit_port(target: &str) -> bool {
    if let Some(rest) = target.strip_prefix('[') {
        let Some((inner, suffix)) = rest.split_once(']') else {
            return false;
        };
        if inner.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        let Some(port) = suffix.strip_prefix(':') else {
            return false;
        };
        return is_http_port(port);
    }

    let Some((host, port)) = target.rsplit_once(':') else {
        return false;
    };
    if host.contains(':') || !is_http_port(port) {
        return false;
    }
    host.parse::<std::net::Ipv4Addr>().is_ok() || normalize_host_component(host).is_some()
}

fn invalid_request_target_authority(target: &str) -> Error {
    Error::Protocol(format!("Invalid HTTP request-target authority: {target}"))
}

fn absolute_form_authority(value: &str) -> Option<&str> {
    let scheme_pos = value.find("://")?;
    let scheme = &value[..scheme_pos];
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")) {
        return None;
    }

    let rest = &value[scheme_pos + 3..];
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    (!authority.is_empty()).then_some(authority)
}

fn is_authority_form_like_target(value: &str) -> bool {
    !value.starts_with('/')
        && !value.contains("://")
        && !value.contains('/')
        && !value.contains('?')
        && !value.contains('#')
        && !nettrap_core::parse::looks_like_windows_drive_path(value)
        && value.contains(':')
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub suppress_body: bool,
    invalid_header: bool,
}

impl HttpResponse {
    pub fn new(status_code: u16) -> Self {
        Self {
            status_code,
            status_text: Self::reason_phrase(status_code).to_string(),
            headers: Vec::new(),
            body: None,
            suppress_body: false,
            invalid_header: false,
        }
    }

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
        if self.invalid_header
            || self.headers.iter().any(|(name, value)| {
                !crate::header::is_valid_header_name(name)
                    || !crate::header::is_valid_header_value(value)
            })
            || !crate::header::is_valid_reason_phrase(&self.status_text)
        {
            return invalid_header_response();
        }

        let status_text = &self.status_text;
        let mut output = format!("HTTP/1.1 {} ", self.status_code).into_bytes();
        if let Some(status_bytes) = crate::header::header_value_to_bytes(status_text) {
            output.extend_from_slice(&status_bytes);
        } else {
            output.extend_from_slice(Self::reason_phrase(self.status_code).as_bytes());
        }
        output.extend_from_slice(b"\r\n");
        let mut headers = self.headers.clone();

        headers.retain(|(name, _)| {
            !name.eq_ignore_ascii_case("Content-Length")
                && !name.eq_ignore_ascii_case("Content-Type")
                && !name.eq_ignore_ascii_case("Transfer-Encoding")
        });

        if response_has_no_body(self.status_code) || self.body.is_none() {
            upsert_header(&mut headers, "Content-Length", "0".to_string());
        } else if let Some(ref body) = self.body {
            upsert_header(&mut headers, "Content-Length", body.len().to_string());
            upsert_header(&mut headers, "Content-Type", "text/html".to_string());
        }

        for (name, value) in &headers {
            if crate::header::is_valid_header_name(name) {
                let Some(value_bytes) = crate::header::header_value_to_bytes(value) else {
                    continue;
                };
                output.extend_from_slice(name.as_bytes());
                output.extend_from_slice(b": ");
                output.extend_from_slice(&value_bytes);
                output.extend_from_slice(b"\r\n");
            }
        }

        output.extend_from_slice(b"\r\n");

        let mut bytes = output;
        if !response_has_no_body(self.status_code)
            && !self.suppress_body
            && let Some(ref body) = self.body
        {
            bytes.extend_from_slice(body);
        }

        bytes
    }
}

fn response_has_no_body(status_code: u16) -> bool {
    matches!(status_code, 100..=199 | 204 | 205 | 304)
}

fn upsert_header(headers: &mut Vec<(String, String)>, name: &str, value: String) {
    if let Some((_, existing_value)) = headers
        .iter_mut()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
    {
        *existing_value = value;
    } else {
        headers.push((name.to_string(), value));
    }
}

fn invalid_header_response() -> Vec<u8> {
    b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 19\r\n\r\nInvalid HTTP header".to_vec()
}

#[cfg(test)]
mod tests {
    use super::{HttpRequest, HttpResponse};
    use crate::parser::MAX_TOTAL_SIZE;

    #[test]
    fn parse_accepts_complete_post_body() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("complete request should parse");
        };

        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.target, "/upload");
        assert_eq!(parsed.path, "/upload");
        assert!(parsed.has_body);
        assert_eq!(parsed.body.as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn parse_preserves_original_target_alongside_normalized_path() {
        let request = b"GET /alpha/../gate?id=1 HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request with query should parse");
        };

        assert_eq!(parsed.target, "/alpha/../gate?id=1");
        assert_eq!(parsed.path, "/gate");
    }

    #[test]
    fn parse_rejects_truncated_post_body() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhel";

        assert!(matches!(HttpRequest::parse(request), Ok(None)));
    }

    #[test]
    fn parse_accepts_get_without_body() {
        let request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.method, "GET");
        assert!(!parsed.has_body);
        assert!(parsed.body.is_none());
        assert_eq!(parsed.host.as_deref(), Some("example.test"));
    }

    #[test]
    fn parse_captures_user_agent_header() {
        let request =
            b"GET / HTTP/1.1\r\nHost: example.test\r\nUser-Agent: NetTrapTest/1.0\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.user_agent.as_deref(), Some("NetTrapTest/1.0"));
    }

    #[test]
    fn parse_rejects_headerless_http_1_1_request() {
        let request = b"GET / HTTP/1.1\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_preserves_explicit_empty_body_framing() {
        let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert!(parsed.has_body);
        assert!(parsed.body.is_none());
    }

    #[test]
    fn parse_rejects_body_larger_than_maximum() {
        let oversized = MAX_TOTAL_SIZE + 1;
        let request = format!(
            "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
            oversized
        );

        assert!(HttpRequest::parse(request.as_bytes()).is_err());
    }

    #[test]
    fn parse_rejects_invalid_content_length() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: abc\r\n\r\nhello";

        assert!(HttpRequest::parse(request).is_err());

        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: +5\r\n\r\nhello";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_rejects_transfer_encoding_with_content_length() {
        let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 14\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_rejects_oversized_request_without_framing() {
        let mut request = Vec::with_capacity(crate::parser::MAX_TOTAL_SIZE + 1);
        request.extend_from_slice(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n");
        request.resize(crate::parser::MAX_TOTAL_SIZE + 1, b'a');

        assert!(HttpRequest::parse(&request).is_err());
    }

    #[test]
    fn parse_rejects_header_without_colon() {
        let request = b"GET / HTTP/1.1\r\nHost: example.test\r\nBroken-Header\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_rejects_nul_in_header_value() {
        let request = b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Test: hello\0world\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_rejects_oversized_headers() {
        let mut request = Vec::with_capacity(crate::parser::MAX_HEADER_SIZE + 64);
        request.extend_from_slice(b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Big: ");
        request.extend(std::iter::repeat_n(
            b'a',
            crate::parser::MAX_HEADER_SIZE + 1,
        ));
        request.extend_from_slice(b"\r\n\r\n");

        assert!(HttpRequest::parse(&request).is_err());
    }

    #[test]
    fn parse_rejects_conflicting_duplicate_content_length() {
        let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\nContent-Length: 4\r\n\r\nhello";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_rejects_duplicate_host_headers_even_with_absolute_form_target() {
        let request = b"GET http://example.test/index.html HTTP/1.0\r\nHost: example.test\r\nHost: backup.test\r\n\r\n";

        assert!(matches!(HttpRequest::parse(request), Ok(None)));
    }

    #[test]
    fn parse_normalizes_host_header_case_and_absolute_form() {
        let request = b"GET / HTTP/1.1\r\nHost: EXAMPLE.TEST.:8080\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.host.as_deref(), Some("example.test:8080"));
        assert_eq!(
            parsed.header("Host").map(String::as_str),
            Some("example.test:8080")
        );
    }

    #[test]
    fn parse_trims_ows_around_host_header_before_canonicalizing() {
        let request = b"GET / HTTP/1.1\r\nHost:  Example.Test.:8080 \t\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.host.as_deref(), Some("example.test:8080"));
        assert_eq!(
            parsed.header("Host").map(String::as_str),
            Some("example.test:8080")
        );
    }

    #[test]
    fn parse_uses_absolute_form_authority_without_host_header() {
        let request = b"GET http://example.test:8080/index.html HTTP/1.0\r\nX-Test: 1\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.host.as_deref(), Some("example.test:8080"));
    }

    #[test]
    fn parse_rejects_fallback_to_absolute_form_authority_when_host_header_is_invalid() {
        let request = b"GET http://example.test/index.html HTTP/1.0\r\nHost: bad name\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.host, None);
        assert_eq!(parsed.header("Host").map(String::as_str), Some("bad name"));
    }

    #[test]
    fn parse_uses_connect_authority_without_host_header() {
        let request = b"CONNECT example.test:443 HTTP/1.0\r\nX-Test: 1\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.host.as_deref(), Some("example.test:443"));
    }

    #[test]
    fn parse_uses_connect_authority_with_bracketed_ipv6_host() {
        let request = b"CONNECT [2001:db8::1]:443 HTTP/1.0\r\nX-Test: 1\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.host.as_deref(), Some("[2001:db8::1]:443"));
    }

    #[test]
    fn parse_rejects_connect_authority_without_explicit_port() {
        let request = b"CONNECT example.test HTTP/1.1\r\nX-Test: 1\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
        assert!(!super::request_target_has_explicit_port("example.test"));
        assert!(!super::request_target_has_explicit_port("[2001:db8::1]"));
    }

    #[test]
    fn request_target_host_accepts_bracketed_ipv6_authority_with_port() {
        assert_eq!(
            super::request_target_host("[2001:db8::1]:443")
                .unwrap()
                .as_deref(),
            Some("[2001:db8::1]:443")
        );
    }

    #[test]
    fn parse_rejects_zero_port_host_header_for_canonicalization() {
        let request = b"GET / HTTP/1.0\r\nHost: example.test:0\r\nX-Test: 1\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.host, None);
        assert_eq!(
            parsed.header("Host").map(String::as_str),
            Some("example.test:0")
        );
        assert_eq!(parsed.host(), None);
    }

    #[test]
    fn parse_accepts_bracketed_ipv6_host_header() {
        let request = b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.host.as_deref(), Some("[2001:db8::1]:443"));
        assert_eq!(
            parsed.header("Host").map(String::as_str),
            Some("[2001:db8::1]:443")
        );
    }

    #[test]
    fn parse_canonicalizes_bracketed_ipv6_host_header() {
        let request = b"GET / HTTP/1.1\r\nHost: [2001:db8:0:0::1]:443\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.host.as_deref(), Some("[2001:db8::1]:443"));
        assert_eq!(
            parsed.header("Host").map(String::as_str),
            Some("[2001:db8::1]:443")
        );
    }

    #[test]
    fn parse_canonicalizes_bracketed_ipv4_mapped_host_header() {
        let request = b"GET / HTTP/1.1\r\nHost: [::ffff:192.0.2.10]:443\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.host.as_deref(), Some("192.0.2.10:443"));
        assert_eq!(
            parsed.header("Host").map(String::as_str),
            Some("192.0.2.10:443")
        );
    }

    #[test]
    fn parse_rejects_malformed_bracketed_ipv6_authority() {
        let request = b"GET http://[2001:db8::1]:443:80/index.html HTTP/1.0\r\nX-Test: 1\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn request_target_host_rejects_malformed_bracketed_ipv6_authority() {
        assert!(super::request_target_host("[2001:db8::1]:443:80").is_err());
    }

    #[test]
    fn request_target_host_rejects_userinfo_authority() {
        assert!(super::request_target_host("user@example.test:443").is_err());
    }

    #[test]
    fn request_target_host_canonicalizes_bracketed_ipv4_mapped_authority() {
        assert_eq!(
            super::request_target_host("[::ffff:192.0.2.10]:443")
                .unwrap()
                .as_deref(),
            Some("192.0.2.10:443")
        );
    }

    #[test]
    fn request_target_host_rejects_unsupported_absolute_form_scheme() {
        assert!(super::request_target_host("ftp://example.test/path").is_err());
    }

    #[test]
    fn parse_rejects_ipv6_loopback_host_header_for_canonicalization() {
        let request = b"GET / HTTP/1.0\r\nHost: [::1]\r\nX-Test: 1\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.host, None);
        assert_eq!(parsed.header("Host").map(String::as_str), Some("[::1]"));
        assert_eq!(parsed.host(), None);
    }

    #[test]
    fn parse_rejects_trailing_dot_ipv4_host_header_for_canonicalization() {
        let request = b"GET / HTTP/1.0\r\nHost: 192.0.2.10.\r\nX-Test: 1\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.host, None);
        assert_eq!(
            parsed.header("Host").map(String::as_str),
            Some("192.0.2.10.")
        );
    }

    #[test]
    fn parse_canonicalizes_zero_padded_host_port() {
        let request = b"GET / HTTP/1.0\r\nHost: example.test:080\r\nX-Test: 1\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.host.as_deref(), Some("example.test:80"));
        assert_eq!(
            parsed.header("Host").map(String::as_str),
            Some("example.test:80")
        );
    }

    #[test]
    fn parse_rejects_unbracketed_ipv6_host_header_for_canonicalization() {
        let request = b"GET / HTTP/1.0\r\nHost: 2001:db8::1\r\nX-Test: 1\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("request should parse");
        };

        assert_eq!(parsed.host, None);
        assert_eq!(
            parsed.header("Host").map(String::as_str),
            Some("2001:db8::1")
        );
        assert_eq!(parsed.host(), None);
    }

    #[test]
    fn parse_accepts_matching_duplicate_content_length() {
        let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("matching content-length should parse");
        };

        assert_eq!(parsed.body.as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn parse_rejects_truncated_chunked_body() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntes";

        assert!(matches!(HttpRequest::parse(request), Ok(None)));
    }

    #[test]
    fn parse_rejects_signed_chunk_size() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n+4\r\ntest\r\n0\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_accepts_complete_chunked_body() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        let Ok(Some(parsed)) = HttpRequest::parse(request) else {
            panic!("complete chunked request should parse");
        };

        assert_eq!(parsed.body.as_deref(), Some(&b"test"[..]));
    }

    #[test]
    fn parse_rejects_unsupported_transfer_coding_before_chunked() {
        let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_does_not_absorb_coalesced_request_as_body_without_framing() {
        let request =
            b"GET /a HTTP/1.1\r\nHost: example.test\r\n\r\nGET /b HTTP/1.1\r\nHost: example.test\r\n\r\n";

        assert!(matches!(HttpRequest::parse(request), Ok(None)));
    }

    #[test]
    fn parse_rejects_request_line_with_extra_fields() {
        let request = b"GET / HTTP/1.1 junk\r\nHost: example.test\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_rejects_tabs_as_request_line_separators() {
        let request = b"GET\t/\tHTTP/1.1\r\nHost: example.test\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_rejects_invalid_http_version() {
        let request = b"GET / HTTP/2.0\r\nHost: example.test\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_rejects_multi_dot_trailing_authority_host() {
        let request = b"GET http://example.com.../ HTTP/1.1\r\nHost: example.test\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_rejects_non_token_method() {
        let request = b"GE(T / HTTP/1.1\r\nHost: example.test\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_rejects_http_11_without_host_header() {
        let request = b"GET / HTTP/1.1\r\nUser-Agent: NetTrap\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_rejects_http_11_with_blank_host_header() {
        let request = b"GET / HTTP/1.1\r\nHost:\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_rejects_mixed_line_endings_in_headers() {
        let request = b"GET / HTTP/1.1\r\nHost: example.test\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn parse_rejects_invalid_chunked_trailers() {
        let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nBad-Trailer\r\n\r\n";

        assert!(HttpRequest::parse(request).is_err());
    }

    #[test]
    fn response_builder_rejects_injected_headers() {
        let response = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            headers: vec![
                ("X-Test\r\nX-Injected".to_string(), "ok".to_string()),
                ("X-Test".to_string(), "ok\r\nX-Injected: yes".to_string()),
            ],
            body: None,
            suppress_body: false,
            invalid_header: false,
        }
        .to_bytes();
        let Ok(text) = std::str::from_utf8(&response) else {
            panic!("response is utf-8");
        };

        assert!(text.starts_with("HTTP/1.1 500 Internal Server Error\r\n"));
        assert!(text.contains("Invalid HTTP header"));
    }

    #[test]
    fn response_builder_preserves_latin1_header_values_as_single_bytes() {
        let response = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            headers: vec![("X-Test".to_string(), "\u{00ff}".to_string())],
            body: None,
            suppress_body: false,
            invalid_header: false,
        }
        .to_bytes();

        assert!(
            response
                .windows(b"X-Test: \xff\r\n".len())
                .any(|window| window == b"X-Test: \xff\r\n")
        );
        assert!(
            !response
                .windows(b"X-Test: \xc3\xbf\r\n".len())
                .any(|window| window == b"X-Test: \xc3\xbf\r\n")
        );
    }

    #[test]
    fn response_builder_preserves_latin1_nbsp_header_value_as_single_byte() {
        let response = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            headers: vec![("X-Test".to_string(), "\u{00a0}".to_string())],
            body: None,
            suppress_body: false,
            invalid_header: false,
        }
        .to_bytes();

        assert!(
            response
                .windows(b"X-Test: \xa0\r\n".len())
                .any(|window| window == b"X-Test: \xa0\r\n")
        );
    }

    #[test]
    fn response_serializer_filters_public_status_and_header_mutations() {
        let mut response = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            headers: vec![("Server".to_string(), "NetTrap".to_string())],
            body: None,
            suppress_body: false,
            invalid_header: false,
        };
        response.status_text = "OK\r\nX-Injected: yes".to_string();
        response
            .headers
            .push(("X-Test".to_string(), "ok".to_string()));

        let bytes = response.to_bytes();
        let Ok(text) = std::str::from_utf8(&bytes) else {
            panic!("response is utf-8");
        };

        assert!(text.starts_with("HTTP/1.1 500 Internal Server Error\r\n"));
        assert!(text.contains("Invalid HTTP header"));
        assert!(!text.contains("X-Injected"));
    }

    #[test]
    fn response_serializer_rewrites_content_length_for_mutated_body() {
        let mut response = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            headers: vec![
                ("Content-Length".to_string(), "5".to_string()),
                ("Content-Type".to_string(), "text/html".to_string()),
            ],
            body: Some(b"hello".to_vec()),
            suppress_body: false,
            invalid_header: false,
        };
        response.body = Some(b"goodbye".to_vec());

        let bytes = response.to_bytes();
        let Ok(text) = std::str::from_utf8(&bytes) else {
            panic!("response is utf-8");
        };

        assert!(text.contains("Content-Length: 7\r\n"));
        assert!(!text.contains("Content-Length: 5\r\n"));
    }

    #[test]
    fn response_serializer_removes_transfer_encoding_for_materialized_body() {
        let mut response = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            headers: vec![
                ("Content-Length".to_string(), "5".to_string()),
                ("Content-Type".to_string(), "text/html".to_string()),
            ],
            body: Some(b"hello".to_vec()),
            suppress_body: false,
            invalid_header: false,
        };
        response
            .headers
            .push(("Transfer-Encoding".to_string(), "chunked".to_string()));

        let bytes = response.to_bytes();
        let Ok(text) = std::str::from_utf8(&bytes) else {
            panic!("response is utf-8");
        };

        assert!(text.contains("Content-Length: 5\r\n"));
        assert!(!text.contains("Transfer-Encoding:"));
    }

    #[test]
    fn response_serializer_removes_content_headers_when_body_is_removed() {
        let mut response = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            headers: vec![
                ("Content-Length".to_string(), "5".to_string()),
                ("Content-Type".to_string(), "text/html".to_string()),
            ],
            body: Some(b"hello".to_vec()),
            suppress_body: false,
            invalid_header: false,
        };
        response.body = None;

        let bytes = response.to_bytes();
        let Ok(text) = std::str::from_utf8(&bytes) else {
            panic!("response is utf-8");
        };

        assert!(text.contains("Content-Length: 0\r\n"));
        assert!(!text.contains("Content-Type:"));
    }

    #[test]
    fn response_serializer_emits_zero_length_when_body_is_absent() {
        let response = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            headers: vec![("Server".to_string(), "NetTrap".to_string())],
            body: None,
            suppress_body: false,
            invalid_header: false,
        };

        let bytes = response.to_bytes();
        let Ok(text) = std::str::from_utf8(&bytes) else {
            panic!("response is utf-8");
        };

        assert!(text.contains("Content-Length: 0\r\n"));
        assert!(!text.contains("Content-Type:"));
    }

    #[test]
    fn response_serializer_omits_body_for_no_content_status() {
        let response = HttpResponse {
            status_code: 204,
            status_text: "No Content".to_string(),
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            body: Some(b"payload".to_vec()),
            suppress_body: false,
            invalid_header: false,
        };

        let bytes = response.to_bytes();
        let Ok(text) = std::str::from_utf8(&bytes) else {
            panic!("response is utf-8");
        };

        assert!(text.starts_with("HTTP/1.1 204 No Content\r\n"));
        assert!(text.contains("Content-Length: 0\r\n"));
        assert!(!text.ends_with("payload"));
    }

    #[test]
    fn response_serializer_omits_body_for_reset_content_status() {
        let response = HttpResponse {
            status_code: 205,
            status_text: "Reset Content".to_string(),
            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
            body: Some(b"payload".to_vec()),
            suppress_body: false,
            invalid_header: false,
        };

        let bytes = response.to_bytes();
        let Ok(text) = std::str::from_utf8(&bytes) else {
            panic!("response is utf-8");
        };

        assert!(text.starts_with("HTTP/1.1 205 Reset Content\r\n"));
        assert!(text.contains("Content-Length: 0\r\n"));
        assert!(!text.ends_with("payload"));
    }

    // Deterministic property-fuzz of the request parser. cargo-fuzz/nightly are
    // not available in CI, but `HttpRequest::parse` is the project's one fuzz
    // target, so exercise it here with a fixed-seed PRNG: it must never panic on
    // arbitrary or malformed bytes, only return Some/None. A fixed seed keeps
    // the test reproducible (no Date/random dependence).
    #[test]
    fn parse_never_panics_on_arbitrary_bytes() {
        let mut state: u64 = 0x9E3779B97F4A7C15;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545F4914F6CDD1D)
        };

        let methods: [&[u8]; 6] = [b"GET", b"POST", b"PUT", b"HEAD", b"\xff\xfe", b""];
        for _ in 0..20_000 {
            let r = next();
            let len = (r % 512) as usize;
            let mut buf = Vec::with_capacity(len + 32);

            // Half the inputs start from a plausible request line so the parser
            // gets past the method/path stage into header and body handling;
            // the rest are pure random bytes.
            if r & 1 == 0 {
                let Some(m) = methods.get((next() as usize) % methods.len()) else {
                    return;
                };
                buf.extend_from_slice(m);
                buf.push(b' ');
                buf.extend_from_slice(b"/x HTTP/1.1\r\n");
                if next() & 1 == 0 {
                    // Sometimes inject a Content-Length that lies about the body.
                    let cl = next() % 100_000;
                    buf.extend_from_slice(format!("Content-Length: {cl}\r\n").as_bytes());
                }
                buf.extend_from_slice(b"\r\n");
            }
            for _ in 0..len {
                buf.push((next() & 0xFF) as u8);
            }

            // Must return without panicking; we don't care which variant.
            let _ = HttpRequest::parse(&buf);
        }
    }

    #[test]
    fn with_body_replaces_existing_content_headers() {
        let response = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            headers: vec![
                ("Content-Length".to_string(), "1".to_string()),
                ("Content-Type".to_string(), "text/plain".to_string()),
            ],
            body: Some(b"<html></html>".to_vec()),
            suppress_body: false,
            invalid_header: false,
        }
        .to_bytes();
        let Ok(text) = std::str::from_utf8(&response) else {
            panic!("response is utf-8");
        };

        assert_eq!(text.matches("Content-Length:").count(), 1);
        assert_eq!(text.matches("Content-Type:").count(), 1);
        assert!(text.contains("Content-Length: 13\r\n"));
        assert!(text.contains("Content-Type: text/html\r\n"));
    }

    #[test]
    fn default_response_serializes_expected_html_body() {
        let bytes = HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            headers: vec![
                ("Server".to_string(), "NetTrap".to_string()),
                ("Content-Length".to_string(), "44".to_string()),
                ("Content-Type".to_string(), "text/html".to_string()),
            ],
            body: Some(b"<html><body>Hello from NetTrap</body></html>".to_vec()),
            suppress_body: false,
            invalid_header: false,
        }
        .to_bytes();
        let Ok(text) = std::str::from_utf8(&bytes) else {
            panic!("response is utf-8");
        };

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Server: NetTrap\r\n"));
        assert!(text.contains("Content-Type: text/html\r\n"));
        assert!(text.contains("Content-Length: 44\r\n"));
        assert!(text.ends_with("<html><body>Hello from NetTrap</body></html>"));
    }
}
