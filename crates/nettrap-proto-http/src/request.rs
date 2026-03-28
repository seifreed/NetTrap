
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
        let header_end = data.windows(4).position(|w| w == b"\r\n\r\n")?;
        let header_str = std::str::from_utf8(&data[..header_end]).ok()?;

        let mut lines = header_str.lines();

        let request_line = lines.next()?;
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }

        let method = parts[0].to_string();
        let path = parts[1].to_string();
        let version = parts[2].to_string();

        let headers: Vec<(String, String)> = lines
            .filter_map(|line| {
                let colon_pos = line.find(':')?;
                let key = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();
                Some((key, value))
            })
            .collect();

        let body_start = header_end + 4;
        let body = if body_start < data.len() {
            Some(data[body_start..].to_vec())
        } else {
            None
        };

        Some(Self {
            method,
            path,
            version,
            headers,
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
            status_text: "OK".to_string(),
            headers: Vec::new(),
            body: None,
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
