//! Utility functions for the engine module
//!
//! This module contains helper functions extracted from the main engine
//! for better separation of concerns and reusability.
//!
//! # Functions
//!
//! - [`log_event`]: Log connection events to JSONL file
//! - [`dump_http_post`]: Dump HTTP POST data to file
//! - [`extract_http_host`]: Extract Host header from HTTP request
//! - [`extract_http_method`]: Extract HTTP method from request
//! - [`extract_http_path`]: Extract path from HTTP request
//! - [`build_http_response_with_version`]: Build simple HTTP 200 response
//! - [`build_http_response_with_fakefile`]: Build HTTP response with fake file content

use std::path::Path;
use tokio::io::AsyncWriteExt;

/// Log an event to the output file in JSONL format.
///
/// # Arguments
///
/// * `output_path` - Optional path to the log file
/// * `listener` - Name of the listener that received the connection
/// * `peer` - Socket address of the peer
/// * `event` - Event type (e.g., "connect", "dns_query")
/// * `detail` - Additional event details
///
/// # Example
///
/// ```ignore
/// log_event(Some(Path::new("/var/log/nettrap/events.jsonl")), "dns", &addr, "dns_query", "query=example.com").await;
/// ```
pub async fn log_event(
    output_path: Option<&Path>,
    listener: &str,
    peer: &std::net::SocketAddr,
    event: &str,
    detail: &str,
) {
    if let Some(path) = output_path {
        let line = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "listener": listener,
            "src_ip": peer.ip().to_string(),
            "src_port": peer.port(),
            "event": event,
            "detail": detail,
        });
        if let Ok(mut file) = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
        {
            let _ = file.write_all(line.to_string().as_bytes()).await;
            let _ = file.write_all(b"\n").await;
        }
    }
}

/// Dump HTTP POST data to a file for analysis.
///
/// Creates a file named `http_post_YYYYMMDD_HHMMSS_PORT.bin` or uses
/// a custom prefix if provided.
///
/// # Arguments
///
/// * `data` - HTTP POST body data
/// * `prefix` - Optional prefix for the output file path
/// * `peer` - Socket address of the peer (used for port extraction)
pub async fn dump_http_post(data: &[u8], prefix: &Option<String>, peer: &std::net::SocketAddr) {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = if let Some(pfx) = prefix {
        format!("{}/{}_{}.bin", pfx, timestamp, peer.port())
    } else {
        format!("http_post_{}_{}.bin", timestamp, peer.port())
    };

    if let Some(parent) = std::path::Path::new(&filename).parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }

    match tokio::fs::write(&filename, data).await {
        Ok(()) => tracing::info!("HTTP POST dumped to {}", filename),
        Err(e) => tracing::warn!("Failed to dump HTTP POST: {}", e),
    }
}

/// Extract the Host header from HTTP request data.
///
/// Parses HTTP headers and returns the value of the Host header.
///
/// # Arguments
///
/// * `data` - Raw HTTP request bytes
///
/// # Returns
///
/// The Host header value, or empty string if not found.
pub fn extract_http_host(data: &[u8]) -> String {
    let text = std::str::from_utf8(data).unwrap_or("");
    for line in text.lines().skip(1) {
        if line.to_lowercase().starts_with("host:") {
            return line[5..].trim().to_string();
        }
    }
    String::new()
}

/// Extract the HTTP method from request data (GET, POST, etc.).
///
/// # Arguments
///
/// * `data` - Raw HTTP request bytes
///
/// # Returns
///
/// The HTTP method (defaults to "GET" if parsing fails).
pub fn extract_http_method(data: &[u8]) -> String {
    let text = std::str::from_utf8(data).unwrap_or("");
    if let Some(first_line) = text.lines().next() {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if !parts.is_empty() {
            return parts[0].to_string();
        }
    }
    "GET".to_string()
}

/// Extract the HTTP path from request data.
///
/// # Arguments
///
/// * `data` - Raw HTTP request bytes
///
/// # Returns
///
/// The request path (defaults to "/" if parsing fails).
pub fn extract_http_path(data: &[u8]) -> String {
    let text = std::str::from_utf8(data).unwrap_or("");
    if let Some(first_line) = text.lines().next() {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 2 {
            return parts[1].to_string();
        }
    }
    "/".to_string()
}

/// Build a simple HTTP 200 OK response with server version header.
///
/// # Arguments
///
/// * `server` - Server name to include in Server header
///
/// # Returns
///
/// Complete HTTP response bytes including body.
pub fn build_http_response_with_version(server: &str) -> Vec<u8> {
    let body = b"<html><body><h1>It works!</h1></body></html>";
    let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nDate: {}\r\nServer: {}\r\n\r\n",
        body.len(),
        date,
        server
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

/// Build an HTTP response with fake file content based on path extension.
///
/// Attempts to serve a fake file based on the extension (e.g., .html, .css, .js).
/// Falls back to a simple "It works!" HTML page for unknown extensions.
///
/// # Arguments
///
/// * `path` - Request path to determine extension
/// * `server` - Server name for Server header
///
/// # Returns
///
/// Complete HTTP response bytes.
pub fn build_http_response_with_fakefile(path: &str, server: &str) -> Vec<u8> {
    use std::collections::HashMap;
    
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let mime_types: HashMap<&str, &str> = HashMap::from([
        ("html", "text/html"),
        ("htm", "text/html"),
        ("css", "text/css"),
        ("js", "application/javascript"),
        ("json", "application/json"),
        ("xml", "application/xml"),
        ("png", "image/png"),
        ("jpg", "image/jpeg"),
        ("jpeg", "image/jpeg"),
        ("gif", "image/gif"),
        ("svg", "image/svg+xml"),
        ("ico", "image/x-icon"),
        ("txt", "text/plain"),
        ("pdf", "application/pdf"),
        ("zip", "application/zip"),
    ]);

    let content = fake_file_for_extension(&ext);
    let mime = mime_types.get(ext.as_str()).copied().unwrap_or("application/octet-stream");
    let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");

    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nDate: {}\r\nServer: {}\r\n\r\n",
        mime,
        content.len(),
        date,
        server
    )
    .into_bytes()
    .into_iter()
    .chain(content)
    .collect()
}

/// Generate fake file content for common file extensions.
///
/// # Arguments
///
/// * `ext` - File extension (without dot)
///
/// # Returns
///
/// Fake content appropriate for the extension.
fn fake_file_for_extension(ext: &str) -> Vec<u8> {
    match ext {
        "html" | "htm" => b"<html><head><title>Index</title></head><body><h1>Index</h1></body></html>".to_vec(),
        "css" => b"body { font-family: sans-serif; margin: 0; }".to_vec(),
        "js" => b"console.log('loaded');".to_vec(),
        "json" => b"{\"status\":\"ok\"}".to_vec(),
        "xml" => b"<?xml version=\"1.0\"?><root/>".to_vec(),
        "txt" => b"OK".to_vec(),
        "png" => vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        "jpg" | "jpeg" => vec![0xFF, 0xD8, 0xFF, 0xE0],
        "gif" => b"GIF89a".to_vec(),
        "svg" => b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>".to_vec(),
        "ico" => vec![0x00, 0x00, 0x01, 0x00],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_http_host() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(extract_http_host(data), "example.com");
        
        let data2 = b"GET / HTTP/1.1\r\nhost: example.org\r\n\r\n";
        assert_eq!(extract_http_host(data2), "example.org");
        
        let data3 = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_host(data3), "");
    }

    #[test]
    fn test_extract_http_method() {
        let data = b"POST /login HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_method(data), "POST");
        
        let data2 = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_method(data2), "GET");
        
        let data3 = b"";
        assert_eq!(extract_http_method(data3), "GET");
    }

    #[test]
    fn test_extract_http_path() {
        let data = b"GET /path/to/resource?q=1 HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data), "/path/to/resource?q=1");
        
        let data2 = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(extract_http_path(data2), "/");
        
        let data3 = b"GET\r\n\r\n";
        let result = extract_http_path(data3);
        assert!(result.is_empty() || result == "/");
    }

    #[test]
    fn test_fake_file() {
        let html = fake_file_for_extension("html");
        assert!(html.starts_with(b"<html>"));
        
        let css = fake_file_for_extension("css");
        assert!(css.starts_with(b"body"));
        
        let unknown = fake_file_for_extension("xyz");
        assert!(unknown.is_empty());
    }

    #[test]
    fn test_build_http_response() {
        let response = build_http_response_with_version("TestServer/1.0");
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(response.windows(4).any(|w| w == b"html"));
    }
}