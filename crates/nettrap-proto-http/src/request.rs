use crate::parser::parse_http_request_bytes;

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    pub fn parse(data: &[u8]) -> Option<Self> {
        let parsed = parse_http_request_bytes(data).ok()??;
        let body = if parsed.body.is_empty() {
            None
        } else {
            Some(parsed.body)
        };

        Some(Self {
            method: parsed.method,
            path: parsed.path,
            version: parsed.version,
            headers: parsed.headers,
            body,
        })
    }

    pub fn header(&self, name: &str) -> Option<&String> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    pub fn host(&self) -> Option<&String> {
        self.header("Host")
    }

    pub fn content_length(&self) -> Option<usize> {
        self.header("Content-Length").and_then(|s| s.parse().ok())
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl HttpResponse {
    pub fn new(status_code: u16) -> Self {
        Self {
            status_code,
            status_text: Self::reason_phrase(status_code).to_string(),
            headers: Vec::new(),
            body: None,
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

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        let body = body.into();
        self.headers
            .push(("Content-Length".to_string(), body.len().to_string()));
        self.headers
            .push(("Content-Type".to_string(), "text/html".to_string()));
        self.body = Some(body.into_bytes());
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = format!("HTTP/1.1 {} {}\r\n", self.status_code, self.status_text);

        for (name, value) in &self.headers {
            output.push_str(&format!("{}: {}\r\n", name, value));
        }

        output.push_str("\r\n");

        let mut bytes = output.into_bytes();
        if let Some(ref body) = self.body {
            bytes.extend_from_slice(body);
        }

        bytes
    }
}

pub fn default_response() -> HttpResponse {
    HttpResponse::new(200)
        .with_header("Server", "NetTrap")
        .with_body("<html><body>Hello from NetTrap</body></html>")
}

#[cfg(test)]
mod tests {
    use super::HttpRequest;
    use crate::parser::MAX_TOTAL_SIZE;

    #[test]
    fn parse_accepts_complete_post_body() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello";
        let parsed = HttpRequest::parse(request).expect("complete request should parse");

        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/upload");
        assert_eq!(parsed.body.as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn parse_rejects_truncated_post_body() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhel";

        assert!(HttpRequest::parse(request).is_none());
    }

    #[test]
    fn parse_accepts_get_without_body() {
        let request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let parsed = HttpRequest::parse(request).expect("request should parse");

        assert_eq!(parsed.method, "GET");
        assert!(parsed.body.is_none());
    }

    #[test]
    fn parse_rejects_body_larger_than_maximum() {
        let oversized = MAX_TOTAL_SIZE + 1;
        let request = format!(
            "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
            oversized
        );

        assert!(HttpRequest::parse(request.as_bytes()).is_none());
    }

    #[test]
    fn parse_rejects_invalid_content_length() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: abc\r\n\r\nhello";

        assert!(HttpRequest::parse(request).is_none());
    }

    #[test]
    fn parse_rejects_truncated_chunked_body() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntes";

        assert!(HttpRequest::parse(request).is_none());
    }

    #[test]
    fn parse_accepts_complete_chunked_body() {
        let request =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        let parsed = HttpRequest::parse(request).expect("complete chunked request should parse");

        assert_eq!(parsed.body.as_deref(), Some(&b"test"[..]));
    }

    #[test]
    fn parse_does_not_absorb_coalesced_request_as_body_without_framing() {
        let request =
            b"GET /a HTTP/1.1\r\nHost: example.test\r\n\r\nGET /b HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let parsed = HttpRequest::parse(request).expect("request should parse");

        assert_eq!(parsed.path, "/a");
        assert!(parsed.body.is_none());
    }

    #[test]
    fn parse_rejects_request_line_with_extra_fields() {
        let request = b"GET / HTTP/1.1 junk\r\nHost: example.test\r\n\r\n";

        assert!(HttpRequest::parse(request).is_none());
    }

    #[test]
    fn parse_rejects_tabs_as_request_line_separators() {
        let request = b"GET\t/\tHTTP/1.1\r\nHost: example.test\r\n\r\n";

        assert!(HttpRequest::parse(request).is_none());
    }

    #[test]
    fn parse_rejects_invalid_http_version() {
        let request = b"GET / HTTP/2.0\r\nHost: example.test\r\n\r\n";

        assert!(HttpRequest::parse(request).is_none());
    }

    #[test]
    fn parse_rejects_non_token_method() {
        let request = b"GE(T / HTTP/1.1\r\nHost: example.test\r\n\r\n";

        assert!(HttpRequest::parse(request).is_none());
    }
}
