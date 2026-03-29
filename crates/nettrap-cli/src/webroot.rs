use std::path::PathBuf;
use std::collections::HashMap;

/// Serves files from a webroot directory with MIME type detection
pub struct WebrootServer {
    root: PathBuf,
    mime_types: HashMap<String, String>,
}

impl WebrootServer {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let mut mime_types = HashMap::new();
        mime_types.insert("html".into(), "text/html".into());
        mime_types.insert("htm".into(), "text/html".into());
        mime_types.insert("css".into(), "text/css".into());
        mime_types.insert("js".into(), "application/javascript".into());
        mime_types.insert("json".into(), "application/json".into());
        mime_types.insert("xml".into(), "application/xml".into());
        mime_types.insert("txt".into(), "text/plain".into());
        mime_types.insert("png".into(), "image/png".into());
        mime_types.insert("jpg".into(), "image/jpeg".into());
        mime_types.insert("jpeg".into(), "image/jpeg".into());
        mime_types.insert("gif".into(), "image/gif".into());
        mime_types.insert("ico".into(), "image/x-icon".into());
        mime_types.insert("svg".into(), "image/svg+xml".into());
        mime_types.insert("pdf".into(), "application/pdf".into());
        mime_types.insert("zip".into(), "application/zip".into());
        mime_types.insert("exe".into(), "application/octet-stream".into());
        mime_types.insert("dll".into(), "application/octet-stream".into());
        mime_types.insert("bin".into(), "application/octet-stream".into());

        Self {
            root: root.into(),
            mime_types,
        }
    }

    /// Resolve a request path to a file and return (content, mime_type)
    pub fn serve(&self, path: &str) -> Option<(Vec<u8>, String)> {
        let clean_path = path.trim_start_matches('/');
        let file_path = self.root.join(clean_path);

        // Prevent path traversal
        if !file_path.starts_with(&self.root) {
            tracing::warn!("Path traversal attempt blocked: {}", path);
            return None;
        }

        // Try exact path, then with index.html
        let candidates = vec![
            file_path.clone(),
            file_path.join("index.html"),
        ];

        for candidate in candidates {
            if candidate.is_file() {
                if let Ok(content) = std::fs::read(&candidate) {
                    let ext = candidate.extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("")
                        .to_lowercase();
                    let mime = self.mime_types
                        .get(&ext)
                        .cloned()
                        .unwrap_or_else(|| "application/octet-stream".into());
                    return Some((content, mime));
                }
            }
        }

        None
    }

    /// Try to find the defaultFiles directory relative to the executable
    pub fn default_files_dir() -> Option<PathBuf> {
        // Try relative to executable
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let default_dir = dir.join("defaultFiles");
                if default_dir.is_dir() {
                    return Some(default_dir);
                }
                // Try one level up (for dev builds)
                if let Some(parent) = dir.parent() {
                    let default_dir = parent.join("defaultFiles");
                    if default_dir.is_dir() {
                        return Some(default_dir);
                    }
                }
            }
        }
        // Try current directory
        let cwd = PathBuf::from("defaultFiles");
        if cwd.is_dir() {
            return Some(cwd);
        }
        None
    }

    /// Build an HTTP response from webroot file
    pub fn build_http_response(&self, path: &str) -> Vec<u8> {
        if let Some((content, mime)) = self.serve(path) {
            let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT");
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nDate: {}\r\nServer: NetTrap\r\n\r\n",
                mime, content.len(), date
            ).into_bytes()
            .into_iter()
            .chain(content)
            .collect()
        } else {
            let body = b"<html><body><h1>404 Not Found</h1></body></html>";
            format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n",
                body.len()
            ).into_bytes()
            .into_iter()
            .chain(body.iter().copied())
            .collect()
        }
    }
}
