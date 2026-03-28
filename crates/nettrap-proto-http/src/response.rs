pub fn ok_response() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<html></html>"
        .to_vec()
}

pub fn not_found_response() -> Vec<u8> {
    b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 9\r\n\r\nNot Found"
        .to_vec()
}

#[derive(Debug, Clone)]
pub struct StaticResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl StaticResponse {
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: String::new(),
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into();
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut response = format!("HTTP/1.1 {} OK\r\n", self.status);

        for (name, value) in &self.headers {
            response.push_str(&format!("{}: {}\r\n", name, value));
        }

        response.push_str("Content-Length: ");
        response.push_str(&self.body.len().to_string());
        response.push_str("\r\n\r\n");
        response.push_str(&self.body);

        response.into_bytes()
    }
}
