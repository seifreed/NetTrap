mod fake_files;

pub use fake_files::fake_file_for_extension;

use std::collections::HashMap;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::utils::{normalize_request_path, normalize_request_path_for_lookup};
use nettrap_fsutil::{LimitedFileRead, read_limited_file_beneath_root};

const MAX_FILE_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;
const LOG_PATH_PREVIEW_CHARS: usize = 240;

enum WebrootServeResult {
    Found { content: Vec<u8>, mime: String },
    TooLarge,
    UnsafePath,
    NotFound,
    ReadError,
}

/// Serves files from a webroot directory with MIME type detection
#[derive(Debug)]
pub struct WebrootServer {
    root: PathBuf,
    mime_types: HashMap<String, String>,
    /// Value emitted in the HTTP `Server` header. Defaults to "NetTrap" but is
    /// overridden by the listener's `server_version` so webroot responses match
    /// the (deceptive) server identity used by the non-webroot HTTP path.
    server_name: String,
}

impl WebrootServer {
    pub fn new(root: impl Into<PathBuf>) -> crate::Result<Self> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(crate::Error::Config(
                "webroot directory must not be empty".to_string(),
            ));
        }

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

        Ok(Self {
            root,
            mime_types,
            server_name: "NetTrap".to_string(),
        })
    }

    /// Override the HTTP `Server` header (from the listener's `server_version`).
    /// `None` or an empty string leaves the default ("NetTrap").
    pub fn with_server_version(mut self, version: Option<&str>) -> crate::Result<Self> {
        if let Some(version) = version
            && let Some(valid) = validate_http_header_value(version, "server_version")?
        {
            self.server_name = valid;
        }
        Ok(self)
    }

    /// Resolve a request path to a file and return (content, mime_type)
    pub fn serve(&self, path: &str) -> Option<(Vec<u8>, String)> {
        match self.serve_result(path) {
            WebrootServeResult::Found { content, mime } => Some((content, mime)),
            WebrootServeResult::TooLarge
            | WebrootServeResult::UnsafePath
            | WebrootServeResult::NotFound
            | WebrootServeResult::ReadError => None,
        }
    }

    fn serve_result(&self, path: &str) -> WebrootServeResult {
        let clean_path = path.trim_start_matches('/');
        if is_unsafe_webroot_path(clean_path) {
            tracing::warn!("Path traversal attempt blocked: {}", safe_log_path(path));
            return WebrootServeResult::UnsafePath;
        }
        let relative_path = PathBuf::from(clean_path);
        let candidates = vec![relative_path.clone(), relative_path.join("index.html")];

        for candidate in candidates {
            match self.read_candidate(&candidate) {
                WebrootServeResult::NotFound => {}
                result => return result,
            }
        }

        WebrootServeResult::NotFound
    }

    fn read_candidate(&self, candidate: &Path) -> WebrootServeResult {
        match read_limited_file_beneath_root(&self.root, candidate, MAX_FILE_RESPONSE_BYTES) {
            Ok(LimitedFileRead::Content(content)) => WebrootServeResult::Found {
                mime: self.mime_for_path(candidate),
                content,
            },
            Ok(LimitedFileRead::TooLarge) => {
                tracing::warn!(
                    "Webroot file {} exceeds response size limit (>{})",
                    safe_log_path_path(candidate),
                    MAX_FILE_RESPONSE_BYTES
                );
                WebrootServeResult::TooLarge
            }
            Ok(LimitedFileRead::NotFile) => WebrootServeResult::NotFound,
            Err(err) if err.kind() == io::ErrorKind::NotFound => WebrootServeResult::NotFound,
            Err(err) => {
                tracing::warn!(
                    "Webroot failed to read {}: {}",
                    safe_log_path_path(candidate),
                    err
                );
                WebrootServeResult::ReadError
            }
        }
    }

    fn mime_for_path(&self, path: &Path) -> String {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        self.mime_types
            .get(&ext)
            .cloned()
            .unwrap_or_else(|| "application/octet-stream".into())
    }

    /// Try to find the defaultFiles directory relative to the executable
    pub fn default_files_dir() -> Option<PathBuf> {
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            let default_dir = dir.join("defaultFiles");
            if default_dir.is_dir() {
                return Some(default_dir);
            }
            if let Some(parent) = dir.parent() {
                let default_dir = parent.join("defaultFiles");
                if default_dir.is_dir() {
                    return Some(default_dir);
                }
            }
        }
        let cwd = PathBuf::from("defaultFiles");
        if cwd.is_dir() {
            return Some(cwd);
        }
        None
    }

    /// Build an HTTP response from webroot file, falling back to fake file generation
    pub fn build_http_response(&self, path: &str) -> Vec<u8> {
        let exact_path = normalize_request_path(path).to_string();
        let lookup_path = normalize_request_path_for_lookup(path);

        match self.serve_result(&exact_path) {
            WebrootServeResult::Found { content, mime } => {
                let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
                return format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nDate: {}\r\nServer: {}\r\n\r\n",
                    mime, content.len(), date, self.server_name
                ).into_bytes()
                .into_iter()
                .chain(content)
                .collect();
            }
            WebrootServeResult::TooLarge => {
                return simple_http_response(
                    413,
                    "Payload Too Large",
                    "Payload Too Large",
                    &self.server_name,
                );
            }
            WebrootServeResult::ReadError => {
                return simple_http_response(
                    500,
                    "Internal Server Error",
                    "Internal Server Error",
                    &self.server_name,
                );
            }
            WebrootServeResult::UnsafePath => {
                return not_found_response(&self.server_name);
            }
            WebrootServeResult::NotFound => {}
        }

        if lookup_path != exact_path {
            match self.serve_result(&lookup_path) {
                WebrootServeResult::Found { content, mime } => {
                    let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
                    return format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nDate: {}\r\nServer: {}\r\n\r\n",
                        mime, content.len(), date, self.server_name
                    )
                    .into_bytes()
                    .into_iter()
                    .chain(content)
                    .collect();
                }
                WebrootServeResult::TooLarge => {
                    return simple_http_response(
                        413,
                        "Payload Too Large",
                        "Payload Too Large",
                        &self.server_name,
                    );
                }
                WebrootServeResult::ReadError => {
                    return simple_http_response(
                        500,
                        "Internal Server Error",
                        "Internal Server Error",
                        &self.server_name,
                    );
                }
                WebrootServeResult::UnsafePath | WebrootServeResult::NotFound => {}
            }
        }

        if let Some(default_files) = Self::default_files_dir() {
            match self.read_default_file(&default_files, &exact_path) {
                WebrootServeResult::Found { content, mime } => {
                    let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
                    return format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nDate: {}\r\nServer: {}\r\n\r\n",
                        mime, content.len(), date, self.server_name
                    )
                    .into_bytes()
                    .into_iter()
                    .chain(content)
                    .collect();
                }
                WebrootServeResult::TooLarge => {
                    return simple_http_response(
                        413,
                        "Payload Too Large",
                        "Payload Too Large",
                        &self.server_name,
                    );
                }
                WebrootServeResult::ReadError => {
                    return simple_http_response(
                        500,
                        "Internal Server Error",
                        "Internal Server Error",
                        &self.server_name,
                    );
                }
                WebrootServeResult::UnsafePath | WebrootServeResult::NotFound => {}
            }
        }

        if is_unsafe_webroot_path(lookup_path.trim_start_matches('/')) {
            return not_found_response(&self.server_name);
        }

        let ext = std::path::Path::new(&lookup_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        if let Some((content, mime)) = fake_file_for_extension(&ext) {
            let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
            return format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nDate: {}\r\nServer: {}\r\n\r\n",
                mime, content.len(), date, self.server_name
            ).into_bytes()
            .into_iter()
            .chain(content)
            .collect();
        }

        not_found_response(&self.server_name)
    }

    fn read_default_file(&self, default_root: &Path, path: &str) -> WebrootServeResult {
        let clean_path = path.trim_start_matches('/');
        if is_unsafe_webroot_path(clean_path) {
            tracing::warn!("Path traversal attempt blocked: {}", safe_log_path(path));
            return WebrootServeResult::UnsafePath;
        }

        let mut candidates = default_file_candidates(clean_path);
        if candidates.is_empty() {
            return WebrootServeResult::NotFound;
        }

        for candidate in candidates.drain(..) {
            match read_limited_file_beneath_root(default_root, &candidate, MAX_FILE_RESPONSE_BYTES)
            {
                Ok(LimitedFileRead::Content(content)) => {
                    return WebrootServeResult::Found {
                        mime: self.mime_for_path(&candidate),
                        content,
                    };
                }
                Ok(LimitedFileRead::TooLarge) => {
                    tracing::warn!(
                        "Default file {} exceeds response size limit (>{})",
                        safe_log_path_path(&candidate),
                        MAX_FILE_RESPONSE_BYTES
                    );
                    return WebrootServeResult::TooLarge;
                }
                Ok(LimitedFileRead::NotFile) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => {
                    tracing::warn!(
                        "Default file lookup failed for {}: {}",
                        safe_log_path_path(&candidate),
                        err
                    );
                    return WebrootServeResult::ReadError;
                }
            }
        }

        WebrootServeResult::NotFound
    }
}

fn simple_http_response(code: u16, reason: &str, body: &str, server_name: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nDate: {}\r\nServer: {}\r\n\r\n{}",
        code,
        reason,
        body.len(),
        crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT"),
        server_name,
        body
    )
    .into_bytes()
}

fn not_found_response(server_name: &str) -> Vec<u8> {
    let body = b"<html><body><h1>404 Not Found</h1></body></html>";
    format!(
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: {}\r\nDate: {}\r\nServer: {}\r\n\r\n",
        body.len(),
        crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT"),
        server_name
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

fn safe_log_path(path: &str) -> String {
    nettrap_core::sanitize::single_line(path)
        .chars()
        .take(LOG_PATH_PREVIEW_CHARS)
        .collect()
}

fn safe_log_path_path(path: &Path) -> String {
    #[cfg(unix)]
    {
        use std::fmt::Write as _;
        use std::os::unix::ffi::OsStrExt;

        let mut rendered = String::new();
        for byte in path.as_os_str().as_bytes() {
            match byte {
                b if b.is_ascii_control() => break,
                b if b.is_ascii_graphic() || *b == b' ' => rendered.push(*b as char),
                b => {
                    let _ = write!(&mut rendered, "\\x{:02x}", b);
                }
            }
        }
        safe_log_path(&rendered)
    }

    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        {
            use std::fmt::Write as _;
            use std::os::windows::ffi::OsStrExt;

            let mut rendered = String::from("hex:");
            let mut chars_written = rendered.len();
            for unit in path.as_os_str().encode_wide() {
                if chars_written + 4 > LOG_PATH_PREVIEW_CHARS {
                    break;
                }
                let _ = write!(&mut rendered, "{:04x}", unit);
                chars_written += 4;
            }
            rendered
        }

        #[cfg(all(not(unix), not(windows)))]
        {
            let mut rendered = String::new();
            for ch in path.to_string_lossy().chars() {
                if ch.is_control() || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}') {
                    break;
                }
                rendered.push(ch);
            }
            safe_log_path(&rendered)
        }
    }
}

fn validate_http_header_value(value: &str, field: &str) -> crate::Result<Option<String>> {
    if value.is_empty() {
        return Ok(None);
    }

    if value.trim_matches([' ', '\t']) != value {
        return Err(crate::Error::Config(format!(
            "Webroot {} header value cannot be padded",
            field
        )));
    }

    if value.chars().any(|ch| {
        matches!(ch, '\r' | '\n')
            || (ch.is_control() && ch != '\t')
            || (ch.is_whitespace() && ch != ' ')
    }) {
        return Err(crate::Error::Config(format!(
            "Webroot {} header value contains unsafe characters",
            field
        )));
    }

    Ok(Some(value.to_string()))
}

fn is_unsafe_webroot_path(path: &str) -> bool {
    if path.contains('\\') || path.contains(':') {
        return true;
    }

    if percent_encoded_path_is_unsafe(path) {
        return true;
    }

    Path::new(path)
        .components()
        .any(|component| match component {
            Component::ParentDir => true,
            #[cfg(windows)]
            Component::Prefix(_) | Component::RootDir => true,
            #[cfg(not(windows))]
            Component::RootDir => true,
            _ => false,
        })
}

pub(crate) fn percent_encoded_path_is_unsafe(path: &str) -> bool {
    let mut decoded = Vec::with_capacity(path.len());
    let bytes = path.as_bytes();
    let mut pos = 0usize;
    while pos < bytes.len() {
        if bytes[pos] == b'%'
            && pos + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex_value(bytes[pos + 1]), hex_value(bytes[pos + 2]))
        {
            decoded.push((high << 4) | low);
            pos += 3;
            continue;
        }
        decoded.push(bytes[pos]);
        pos += 1;
    }

    decoded.iter().any(|byte| matches!(*byte, b'\\' | b':' | 0))
        || decoded
            .split(|byte| *byte == b'/')
            .any(|segment| segment == b"..")
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn default_file_candidates(path: &str) -> Vec<PathBuf> {
    let relative_path = Path::new(path);
    let mut candidates = Vec::new();

    if !relative_path.as_os_str().is_empty() {
        candidates.push(relative_path.to_path_buf());
        if let Some(file_name) = relative_path.file_name() {
            let file_name_path = PathBuf::from(file_name);
            if file_name_path != relative_path {
                candidates.push(file_name_path);
            }
            if file_name.eq_ignore_ascii_case("ncsi.txt") {
                candidates.push(PathBuf::from("NCSI.txt"));
            }
        }
    }

    let extension = relative_path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase());
    let mapped_name = match extension.as_deref() {
        Some("htm") | Some("html") => Some("NetTrap.html"),
        Some("json") => Some("NetTrap.json"),
        Some("txt") => Some("NetTrap.txt"),
        Some("xml") => Some("NetTrap.xml"),
        _ if relative_path.as_os_str().is_empty() => Some("NetTrap.html"),
        _ => None,
    };
    if let Some(mapped_name) = mapped_name {
        candidates.push(PathBuf::from(mapped_name));
    }

    candidates
        .into_iter()
        .fold(Vec::new(), |mut unique, candidate| {
            if !unique.iter().any(|existing| existing == &candidate) {
                unique.push(candidate);
            }
            unique
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logged_webroot_paths_are_single_line_and_bounded() {
        assert_eq!(
            safe_log_path("/../../etc/passwd\u{2028}next"),
            "/../../etc/passwd next"
        );

        let long = "a".repeat(LOG_PATH_PREVIEW_CHARS + 128);
        assert_eq!(safe_log_path(&long).len(), LOG_PATH_PREVIEW_CHARS);
    }

    #[test]
    fn new_rejects_empty_webroot_path() {
        let err = WebrootServer::new(PathBuf::new()).expect_err("empty webroot should fail");

        assert!(
            matches!(err, crate::Error::Config(message) if message.contains("must not be empty"))
        );
    }

    #[test]
    fn build_http_response_rejects_large_webroot_file() {
        let root = unique_temp_dir("nettrap-webroot-limit");
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("large.bin");
        let file = std::fs::File::create(&path).expect("create sparse file");
        file.set_len(MAX_FILE_RESPONSE_BYTES + 1)
            .expect("extend sparse file");

        let response = WebrootServer::new(&root)
            .expect("valid webroot")
            .with_server_version(Some("Apache/2.4.99 (Unix)"))
            .expect("valid server version should be accepted")
            .build_http_response("/large.bin");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 413 Payload Too Large"));
        assert!(text.contains("\r\nServer: Apache/2.4.99 (Unix)\r\n"));
        assert!(!text.contains("\r\nServer: NetTrap\r\n"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[cfg(windows)]
    #[test]
    fn build_http_response_rejects_windows_drive_prefixed_path() {
        let root = unique_temp_dir("nettrap-webroot-drive-prefix");
        std::fs::create_dir_all(&root).expect("create temp root");

        let response = WebrootServer::new(&root)
            .expect("valid webroot")
            .build_http_response("C:/Windows/win.ini");

        assert!(response.starts_with(b"HTTP/1.1 404 Not Found"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[cfg(unix)]
    #[test]
    fn safe_log_path_path_preserves_non_utf8_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = PathBuf::from(OsString::from_vec(b"/tmp/webroot-\xff.bin".to_vec()));
        let rendered = safe_log_path_path(&path);

        assert!(rendered.contains("\\xff"));
        assert!(!rendered.contains('\u{fffd}'));
    }

    #[cfg(unix)]
    #[test]
    fn safe_log_path_path_stops_at_control_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = PathBuf::from(OsString::from_vec(
            b"/tmp/webroot-\x1b[31minjected".to_vec(),
        ));
        let rendered = safe_log_path_path(&path);

        assert_eq!(rendered, "/tmp/webroot-");
        assert!(!rendered.contains("injected"));
    }

    #[cfg(windows)]
    #[test]
    fn safe_log_path_path_preserves_non_utf16_units_reversibly() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        let raw = OsString::from_wide(&[
            b'c' as u16,
            b':' as u16,
            b'\\' as u16,
            b't' as u16,
            b'm' as u16,
            b'p' as u16,
            b'\\' as u16,
            0xD800,
        ]);
        let path = PathBuf::from(raw);
        let rendered = safe_log_path_path(&path);

        assert_eq!(rendered, "hex:0063003a005c0074006d0070005cd800");
    }

    #[test]
    fn build_http_response_allows_webroot_file_at_size_limit() {
        let root = unique_temp_dir("nettrap-webroot-limit-ok");
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("limit.bin");
        let file = std::fs::File::create(&path).expect("create sparse file");
        file.set_len(MAX_FILE_RESPONSE_BYTES)
            .expect("extend sparse file");

        let response = WebrootServer::new(&root)
            .expect("valid webroot")
            .build_http_response("/limit.bin");

        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(String::from_utf8_lossy(&response[..128]).contains("Content-Length: 10485760"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn build_http_response_allows_double_dot_filename() {
        let root = unique_temp_dir("nettrap-webroot-dotdot-file");
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(root.join("version..txt"), b"dotdot").expect("write fixture");

        let response = WebrootServer::new(&root)
            .expect("valid webroot")
            .build_http_response("/version..txt");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("dotdot"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn build_http_response_ignores_query_and_fragment_suffixes_for_webroot_files() {
        let root = unique_temp_dir("nettrap-webroot-query-fragment");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(root.join("payload.exe"), b"MZpayload").expect("write fixture");

        let response = WebrootServer::new(&root)
            .expect("valid webroot")
            .build_http_response("/payload.exe?dl=1#frag");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("Content-Type: application/octet-stream"));
        assert!(text.contains("MZpayload"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn build_http_response_ignores_path_parameters_for_webroot_files() {
        let root = unique_temp_dir("nettrap-webroot-path-params");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(root.join("payload.exe"), b"MZpayload").expect("write fixture");

        let response = WebrootServer::new(&root)
            .expect("valid webroot")
            .build_http_response("/payload.exe;download=1");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("Content-Type: application/octet-stream"));
        assert!(text.contains("MZpayload"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn build_http_response_serves_literal_semicolon_filename_when_present() {
        let root = unique_temp_dir("nettrap-webroot-semicolon-file");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(root.join("payload.exe;download=1"), b"literal-semicolon")
            .expect("write fixture");

        let response = WebrootServer::new(&root)
            .expect("valid webroot")
            .build_http_response("/payload.exe;download=1");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("literal-semicolon"), "got: {text:?}");
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn build_http_response_rejects_unsafe_stripped_lookup_path() {
        let root = unique_temp_dir("nettrap-webroot-unsafe-stripped");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");

        let response = WebrootServer::new(&root)
            .expect("valid webroot")
            .build_http_response("/safe/..;x/payload.exe");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 404 Not Found"), "got: {text:?}");
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn unsafe_webroot_path_does_not_fall_back_to_fake_file() {
        let root = unique_temp_dir("nettrap-webroot-unsafe-fake-fallback");
        std::fs::create_dir_all(&root).expect("create temp root");

        for path in [
            "/../../secret.exe",
            "/%2e%2e/secret.exe",
            "/..%2fsecret.exe",
            "/safe%5csecret.exe",
            "/safe:secret.exe",
            "/safe%3asecret.exe",
        ] {
            let response = WebrootServer::new(&root)
                .expect("valid webroot")
                .build_http_response(path);
            let text = String::from_utf8_lossy(&response);

            assert!(text.starts_with("HTTP/1.1 404 Not Found"), "{path}: {text}");
            assert!(!text.contains("application/octet-stream"), "{path}: {text}");
        }
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[cfg(unix)]
    #[test]
    fn build_http_response_reports_webroot_read_errors() {
        let root_file = std::env::temp_dir().join(format!(
            "nettrap-webroot-file-root-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&root_file, b"not a directory").expect("write temp root file");

        let response = WebrootServer::new(&root_file)
            .expect("valid webroot")
            .with_server_version(Some("Apache/2.4.99 (Unix)"))
            .expect("valid server version should be accepted")
            .build_http_response("/index.html");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 500 Internal Server Error"));
        assert!(text.contains("\r\nServer: Apache/2.4.99 (Unix)\r\n"));
        assert!(!text.contains("\r\nServer: NetTrap\r\n"));
        std::fs::remove_file(root_file).expect("cleanup temp root file");
    }

    #[cfg(unix)]
    #[test]
    fn build_http_response_rejects_final_symlink_inside_root() {
        use std::os::unix::fs::symlink;

        let root = unique_temp_dir("nettrap-webroot-symlink");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(root.join("real.html"), b"<html>secret</html>").expect("write fixture");
        symlink("real.html", root.join("link.html")).expect("create symlink");

        let response = WebrootServer::new(&root)
            .expect("valid webroot")
            .build_http_response("/link.html");

        assert!(!String::from_utf8_lossy(&response).contains("secret"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[cfg(unix)]
    #[test]
    fn build_http_response_rejects_intermediate_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = unique_temp_dir("nettrap-webroot-intermediate-symlink");
        let outside = unique_temp_dir("nettrap-webroot-intermediate-outside");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::create_dir_all(&outside).expect("create outside dir");
        std::fs::write(outside.join("secret.html"), b"<html>secret</html>")
            .expect("write outside fixture");
        symlink(&outside, root.join("dir")).expect("create intermediate symlink");

        let response = WebrootServer::new(&root)
            .expect("valid webroot")
            .build_http_response("/dir/secret.html");

        assert!(!String::from_utf8_lossy(&response).contains("secret"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
        std::fs::remove_dir_all(outside).expect("cleanup outside dir");
    }

    #[test]
    fn served_file_uses_configured_server_version_in_header() {
        let root = unique_temp_dir("nettrap-webroot-server-version");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(root.join("index.html"), b"<html>ok</html>").expect("write fixture");

        let response = WebrootServer::new(&root)
            .expect("valid webroot")
            .with_server_version(Some("Apache/2.4.99 (Unix)"))
            .expect("valid server version should be accepted")
            .build_http_response("/index.html");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(
            text.contains("\r\nServer: Apache/2.4.99 (Unix)\r\n"),
            "served file should honor server_version, got: {text:?}"
        );
        assert!(!text.contains("Server: NetTrap"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn missing_file_uses_configured_server_version_in_404_response() {
        let root = unique_temp_dir("nettrap-webroot-404-server-version");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");

        let response = WebrootServer::new(&root)
            .expect("valid webroot")
            .with_server_version(Some("Apache/2.4.99 (Unix)"))
            .expect("valid server version should be accepted")
            .build_http_response("/missing");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 404 Not Found"));
        assert!(text.contains("\r\nServer: Apache/2.4.99 (Unix)\r\n"));
        assert!(!text.contains("\r\nServer: NetTrap\r\n"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn default_files_fallback_serves_stock_asset_before_fakefile_generation() {
        let workspace = unique_temp_dir("nettrap-webroot-default-files");
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(workspace.join("defaultFiles")).expect("create defaultFiles dir");
        std::fs::create_dir_all(workspace.join("webroot")).expect("create temp webroot");
        std::fs::write(
            workspace.join("defaultFiles").join("NetTrap.html"),
            b"<html><body><h1>default-files-hit</h1></body></html>",
        )
        .expect("write default file");

        let _guard = current_dir_guard(&workspace);
        let response = WebrootServer::new(workspace.join("webroot"))
            .expect("valid webroot")
            .build_http_response("/missing.html");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("default-files-hit"), "got: {text:?}");
        assert!(!text.contains("Welcome to the server."), "got: {text:?}");
        drop(_guard);
        std::fs::remove_dir_all(workspace).expect("cleanup temp workspace");
    }

    #[test]
    fn fakefile_fallback_uses_configured_server_version() {
        let root = unique_temp_dir("nettrap-webroot-server-version-fake");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");

        let response = WebrootServer::new(&root)
            .expect("valid webroot")
            .with_server_version(Some("nginx/1.25.0"))
            .expect("valid server version should be accepted")
            .build_http_response("/missing.html");
        let text = String::from_utf8_lossy(&response);

        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(
            text.contains("\r\nServer: nginx/1.25.0\r\n"),
            "fakefile fallback should honor server_version, got: {text:?}"
        );
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn server_version_defaults_to_nettrap_when_unset() {
        let root = unique_temp_dir("nettrap-webroot-server-version-default");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(root.join("index.html"), b"<html>ok</html>").expect("write fixture");

        for version in [None, Some("")] {
            let response = WebrootServer::new(&root)
                .expect("valid webroot")
                .with_server_version(version)
                .expect("server version should be accepted")
                .build_http_response("/index.html");
            let text = String::from_utf8_lossy(&response);
            assert!(text.contains("\r\nServer: NetTrap\r\n"), "got: {text:?}");
        }
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn server_version_cannot_inject_headers() {
        let root = unique_temp_dir("nettrap-webroot-server-version-injection");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(root.join("index.html"), b"<html>ok</html>").expect("write fixture");

        let err = WebrootServer::new(&root)
            .expect("valid webroot")
            .with_server_version(Some("Apache\r\nX-Injected: yes"))
            .expect_err("invalid server version should fail");

        assert!(
            err.to_string()
                .contains("Webroot server_version header value contains unsafe characters")
        );
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn server_version_rejects_unicode_whitespace_padding() {
        let root = unique_temp_dir("nettrap-webroot-server-version-unicode");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(root.join("index.html"), b"<html>ok</html>").expect("write fixture");

        let err = WebrootServer::new(&root)
            .expect("valid webroot")
            .with_server_version(Some("NetTrap\u{00a0}X-Injected: yes"))
            .expect_err("invalid server version should fail");

        assert!(
            err.to_string()
                .contains("Webroot server_version header value contains unsafe characters")
        );
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn server_version_rejects_ascii_whitespace_padding() {
        let root = unique_temp_dir("nettrap-webroot-server-version-ascii");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(root.join("index.html"), b"<html>ok</html>").expect("write fixture");

        let err = WebrootServer::new(&root)
            .expect("valid webroot")
            .with_server_version(Some(" Apache/2.4.99 "))
            .expect_err("padded server version should be rejected");

        assert!(err.to_string().contains("cannot be padded"));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        static TEMP_COUNTER: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);
        let seq = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("{prefix}-{}-{seq}", std::process::id()))
    }

    fn current_dir_guard(new_dir: &Path) -> CurrentDirGuard {
        let lock = crate::test_util::lock_current_dir();
        let previous = std::env::current_dir().expect("capture current dir");
        std::env::set_current_dir(new_dir).expect("set current dir");
        CurrentDirGuard {
            previous,
            _lock: lock,
        }
    }

    struct CurrentDirGuard {
        previous: PathBuf,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for CurrentDirGuard {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.previous).expect("restore current dir");
        }
    }
}
