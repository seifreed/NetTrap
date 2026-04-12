use async_trait::async_trait;
use parking_lot::RwLock;

use crate::prelude::*;

pub struct HttpServer {
    bind_address: std::net::SocketAddr,
    default_response: String,
    custom_responses: RwLock<std::collections::HashMap<String, String>>,
}

impl HttpServer {
    pub fn new(bind_address: std::net::SocketAddr) -> Self {
        Self {
            bind_address,
            default_response: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<html></html>".to_string(),
            custom_responses: RwLock::new(std::collections::HashMap::new()),
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
        self.custom_responses
            .write()
            .insert(path.into(), response.into());
    }

    pub fn remove_custom_response(&self, path: &str) {
        self.custom_responses.write().remove(path);
    }

    fn build_response(&self, request: &HttpRequest) -> HttpResponse {
        let path = request.uri.as_str();

        let body = self
            .custom_responses
            .read()
            .get(path)
            .cloned()
            .unwrap_or_else(|| self.default_response.clone());

        HttpResponse {
            status_code: 200,
            status_text: "OK".to_string(),
            headers: std::collections::HashMap::from([
                ("Content-Type".to_string(), "text/html".to_string()),
                ("Content-Length".to_string(), body.len().to_string()),
            ]),
            body: body.into_bytes(),
        }
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
    pub headers: std::collections::HashMap<String, String>,
    pub body: Vec<u8>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
}

impl HttpRequest {
    pub fn parse(data: &[u8]) -> Result<Option<Self>> {
        // Return None for incomplete data (headers not fully received yet)
        let header_end = match data.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(pos) => pos,
            None => return Ok(None),
        };

        let headers_str =
            std::str::from_utf8(&data[..header_end]).map_err(|e| Error::Parse(e.to_string()))?;

        let mut lines = headers_str.lines();

        let request_line = lines
            .next()
            .ok_or_else(|| Error::Parse("No request line".into()))?;

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(Error::Parse("Invalid request line".into()));
        }

        let method = parts[0].to_string();
        let uri = parts[1].to_string();
        let version = parts[2].to_string();

        let mut headers = std::collections::HashMap::new();
        let mut host = None;
        let mut user_agent = None;

        for line in lines {
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();

                if key == "host" {
                    host = Some(value.clone());
                } else if key == "user-agent" {
                    user_agent = Some(value.clone());
                }

                headers.insert(key, value);
            }
        }

        let body_start = header_end + 4;
        let body = if body_start < data.len() {
            data[body_start..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Some(Self {
            method,
            uri,
            version,
            headers,
            body,
            host,
            user_agent,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub headers: std::collections::HashMap<String, String>,
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
            headers: std::collections::HashMap::from([
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
            headers: std::collections::HashMap::from([
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
