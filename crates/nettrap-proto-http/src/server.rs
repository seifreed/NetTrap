use async_trait::async_trait;
use parking_lot::RwLock;

use crate::parser::parse_http_request_bytes;
use crate::prelude::*;

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

    pub fn with_default_response(mut self, response: impl Into<String>) -> Self {
        self.default_response = response.into();
        self
    }

    pub fn add_custom_response(&self, path: impl Into<String>, response: impl Into<String>) {
        let path = normalize_request_path(&path.into());
        self.custom_responses.write().insert(path, response.into());
    }

    pub fn remove_custom_response(&self, path: &str) {
        let path = normalize_request_path(path);
        self.custom_responses.write().remove(path.as_str());
    }

    fn build_response(&self, request: &HttpRequest) -> HttpResponse {
        let path = normalize_request_path(request.uri.as_str());

        let body = self
            .custom_responses
            .read()
            .get(path.as_str())
            .cloned()
            .unwrap_or_else(|| self.default_response.clone());

        HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            headers: std::collections::BTreeMap::from([
                ("Content-Type".to_string(), "text/html".to_string()),
                ("Content-Length".to_string(), body.len().to_string()),
            ]),
            body: body.into_bytes(),
        }
    }
}

fn normalize_request_path(target: &str) -> String {
    let path = if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        rest.find('/').map(|pos| &rest[pos..]).unwrap_or("/")
    } else {
        target
    };

    let path = path.split('#').next().unwrap_or(path);
    let path = path.split('?').next().unwrap_or(path);

    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
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
        Ok(self.build_response(&request))
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
}

impl HttpRequest {
    pub fn parse(data: &[u8]) -> Result<Option<Self>> {
        let parsed = match parse_http_request_bytes(data)? {
            Some(parsed) => parsed,
            None => return Ok(None),
        };

        let mut headers = std::collections::BTreeMap::new();
        let mut host = None;
        let mut user_agent = None;

        for (key, value) in parsed.headers {
            let normalized_key = key.to_lowercase();

            if normalized_key == "host" {
                host = Some(value.clone());
            } else if normalized_key == "user-agent" {
                user_agent = Some(value.clone());
            }

            headers.insert(normalized_key, value);
        }

        Ok(Some(Self {
            method: parsed.method,
            uri: parsed.path,
            version: parsed.version,
            headers,
            body: parsed.body,
            host,
            user_agent,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub headers: std::collections::BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut response = format!("HTTP/1.1 {} {}\r\n", self.status_code, self.status_text);

        for (key, value) in &self.headers {
            response.push_str(&format!("{}: {}\r\n", key, value));
        }

        response.push_str("\r\n");

        let mut bytes = response.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
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
        }
    }
}

#[async_trait]
pub trait HttpHandlerTrait: Send + Sync {
    async fn handle_request(&self, request: HttpRequest) -> Result<HttpResponse>;
    fn name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::{HttpRequest, HttpServer};

    #[test]
    fn parse_rejects_truncated_post_body() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhel";

        let parsed = HttpRequest::parse(request).expect("parser should not error");
        assert!(parsed.is_none(), "truncated body should remain incomplete");
    }

    #[test]
    fn parse_accepts_complete_post_body() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello";

        let parsed = HttpRequest::parse(request)
            .expect("parser should not error")
            .expect("complete request should parse");

        assert_eq!(parsed.uri, "/upload");
        assert_eq!(parsed.body, b"hello");
        assert_eq!(
            parsed.headers.get("content-length").map(String::as_str),
            Some("5")
        );
    }

    #[test]
    fn parse_rejects_invalid_content_length() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: abc\r\n\r\nhello";

        let parsed = HttpRequest::parse(request).expect("parser should not error");
        assert!(
            parsed.is_none(),
            "invalid content-length should remain incomplete"
        );
    }

    #[test]
    fn parse_rejects_truncated_chunked_body() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntes";

        let parsed = HttpRequest::parse(request).expect("parser should not error");
        assert!(
            parsed.is_none(),
            "truncated chunked body should remain incomplete"
        );
    }

    #[test]
    fn parse_accepts_complete_chunked_body() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

        let parsed = HttpRequest::parse(request)
            .expect("parser should not error")
            .expect("complete chunked request should parse");

        assert_eq!(parsed.uri, "/upload");
        assert_eq!(parsed.body, b"test");
    }

    #[test]
    fn parse_rejects_transfer_encoding_with_content_length() {
        let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 14\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

        let parsed = HttpRequest::parse(request).expect("parser should not error");

        assert!(parsed.is_none());
    }

    #[test]
    fn parse_rejects_chunked_when_not_final_transfer_coding() {
        let request = b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked, gzip\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

        let parsed = HttpRequest::parse(request).expect("parser should not error");

        assert!(parsed.is_none());
    }

    #[test]
    fn parse_does_not_absorb_coalesced_request_as_body_without_framing() {
        let request =
            b"GET /a HTTP/1.1\r\nHost: example.test\r\n\r\nGET /b HTTP/1.1\r\nHost: example.test\r\n\r\n";

        let parsed = HttpRequest::parse(request)
            .expect("parser should not error")
            .expect("request should parse");

        assert_eq!(parsed.uri, "/a");
        assert!(parsed.body.is_empty());
    }

    #[test]
    fn custom_responses_match_normalized_paths_with_query() {
        let server = HttpServer::new("127.0.0.1:0".parse().expect("socket addr"));
        server.add_custom_response("/index.html", "custom");

        let request = HttpRequest {
            method: "GET".to_string(),
            uri: "/index.html?v=1".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: std::collections::BTreeMap::new(),
            body: Vec::new(),
            host: Some("example.test".to_string()),
            user_agent: None,
        };

        let response = server.build_response(&request);
        assert_eq!(response.body, b"custom");
    }

    #[test]
    fn custom_responses_match_normalized_paths_with_absolute_form() {
        let server = HttpServer::new("127.0.0.1:0".parse().expect("socket addr"));
        server.add_custom_response("/index.html", "custom");

        let request = HttpRequest {
            method: "GET".to_string(),
            uri: "http://example.test/index.html".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: std::collections::BTreeMap::new(),
            body: Vec::new(),
            host: Some("example.test".to_string()),
            user_agent: None,
        };

        let response = server.build_response(&request);
        assert_eq!(response.body, b"custom");
    }

    #[test]
    fn add_custom_response_normalizes_registered_paths() {
        let server = HttpServer::new("127.0.0.1:0".parse().expect("socket addr"));
        server.add_custom_response("http://example.test/index.html?v=1", "custom");

        let request = HttpRequest {
            method: "GET".to_string(),
            uri: "/index.html".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: std::collections::BTreeMap::new(),
            body: Vec::new(),
            host: Some("example.test".to_string()),
            user_agent: None,
        };

        let response = server.build_response(&request);
        assert_eq!(response.body, b"custom");
    }

    #[test]
    fn remove_custom_response_normalizes_registered_paths() {
        let server = HttpServer::new("127.0.0.1:0".parse().expect("socket addr"));
        server.add_custom_response("http://example.test/index.html?v=1", "custom");
        server.remove_custom_response("/index.html");

        let request = HttpRequest {
            method: "GET".to_string(),
            uri: "/index.html".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: std::collections::BTreeMap::new(),
            body: Vec::new(),
            host: Some("example.test".to_string()),
            user_agent: None,
        };

        let response = server.build_response(&request);
        assert_eq!(response.body, b"<html></html>");
    }
}
