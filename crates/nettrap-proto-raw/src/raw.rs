use nettrap_core::error::{Error, Result};
use nettrap_fsutil::{LimitedFileRead, read_limited_file};

const MAX_RAW_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
const MAX_RAW_BASE64_CONFIG_BYTES: usize = MAX_RAW_RESPONSE_BYTES.div_ceil(3) * 4;

/// Raw protocol handler supporting multiple response modes
#[derive(Debug)]
pub struct RawHandler {
    mode: RawResponseMode,
}

#[derive(Debug, Clone)]
pub enum RawResponseMode {
    /// Echo received data back (default)
    Echo,
    /// Return static string
    StaticString(Vec<u8>),
    /// Return contents of a file
    RawFile(std::path::PathBuf),
    /// Return base64-decoded data
    StaticBase64(Vec<u8>), // already decoded
    /// No response
    Silent,
}

pub struct RawResponse {
    pub data: Vec<u8>,
}

impl RawResponse {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl RawHandler {
    pub fn new() -> Self {
        Self {
            mode: RawResponseMode::Echo,
        }
    }

    pub fn with_echo(mut self) -> Self {
        self.mode = RawResponseMode::Echo;
        self
    }

    pub fn with_static_string(mut self, data: impl Into<String>) -> Result<Self> {
        let data = data.into();
        if data.len() > MAX_RAW_RESPONSE_BYTES {
            return Err(Error::Config(format!(
                "Raw static response config exceeds size limit ({} > {} bytes)",
                data.len(),
                MAX_RAW_RESPONSE_BYTES
            )));
        }
        self.mode = RawResponseMode::StaticString(data.into_bytes());
        Ok(self)
    }

    pub fn with_raw_file(mut self, path: impl Into<std::path::PathBuf>) -> Result<Self> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(Error::Config(
                "Raw file response config requires a non-empty path".to_string(),
            ));
        }
        self.mode = RawResponseMode::RawFile(path);
        Ok(self)
    }

    pub fn with_static_base64(mut self, b64: &str) -> Result<Self> {
        use base64::Engine as _;
        if b64.len() > MAX_RAW_BASE64_CONFIG_BYTES {
            return Err(Error::Config(format!(
                "Raw base64 response config exceeds size limit ({} > {} bytes)",
                b64.len(),
                MAX_RAW_BASE64_CONFIG_BYTES
            )));
        }
        match base64::engine::general_purpose::STANDARD.decode(b64) {
            Ok(decoded) if decoded.len() <= MAX_RAW_RESPONSE_BYTES => {
                self.mode = RawResponseMode::StaticBase64(decoded);
            }
            Ok(decoded) => {
                return Err(Error::Config(format!(
                    "Raw base64 response config decoded to {} bytes, exceeding size limit {} bytes",
                    decoded.len(),
                    MAX_RAW_RESPONSE_BYTES
                )));
            }
            Err(e) => {
                return Err(Error::Config(format!(
                    "Invalid base64 in raw handler config: {}",
                    e
                )));
            }
        }
        Ok(self)
    }

    pub fn with_silent(mut self) -> Self {
        self.mode = RawResponseMode::Silent;
        self
    }

    /// Configure from a custom_response string. Format:
    /// "echo" - echo mode (default)
    /// "static:Hello World" - static string
    /// "base64:SGVsbG8=" - base64 decoded response
    /// "file:/path/to/response.bin" - raw file response
    /// "silent" - no response
    pub fn from_custom_response(custom: &str) -> Result<Self> {
        let handler = Self::new();
        if custom.is_empty() || custom == "echo" {
            Ok(handler.with_echo())
        } else if let Some(text) = custom.strip_prefix("static:") {
            handler.with_static_string(text)
        } else if let Some(b64) = custom.strip_prefix("base64:") {
            handler.with_static_base64(b64)
        } else if let Some(path) = custom.strip_prefix("file:") {
            handler.with_raw_file(path)
        } else if custom == "silent" {
            Ok(handler.with_silent())
        } else {
            handler.with_static_string(custom)
        }
    }

    pub fn handle(&self, data: &[u8]) -> RawResponse {
        match &self.mode {
            RawResponseMode::Echo => {
                tracing::debug!("Raw echo: {} bytes", data.len());
                if data.len() > MAX_RAW_RESPONSE_BYTES {
                    tracing::warn!(
                        "Raw echo payload exceeds response size limit ({} > {} bytes)",
                        data.len(),
                        MAX_RAW_RESPONSE_BYTES
                    );
                    return RawResponse::new(b"ERROR\n".to_vec());
                }
                RawResponse::new(data.to_vec())
            }
            RawResponseMode::StaticString(response) => RawResponse::new(response.clone()),
            RawResponseMode::RawFile(path) => {
                // Limit file reads to 10MB to prevent OOM
                match read_limited_file(path, MAX_RAW_RESPONSE_BYTES as u64) {
                    Ok(LimitedFileRead::Content(content)) => RawResponse::new(content),
                    Ok(LimitedFileRead::TooLarge) => {
                        tracing::warn!(
                            "Raw file {} exceeds size limit (>{} bytes)",
                            path.display(),
                            MAX_RAW_RESPONSE_BYTES,
                        );
                        RawResponse::new(b"ERROR\n".to_vec())
                    }
                    Ok(LimitedFileRead::NotFile) => RawResponse::new(b"ERROR\n".to_vec()),
                    Err(e) => {
                        tracing::warn!("Failed to read raw file {}: {}", path.display(), e);
                        RawResponse::new(b"ERROR\n".to_vec())
                    }
                }
            }
            RawResponseMode::StaticBase64(decoded) => RawResponse::new(decoded.clone()),
            RawResponseMode::Silent => RawResponse::empty(),
        }
    }

    /// Log data as hex dump for raw protocol analysis
    pub fn hexdump(data: &[u8], max_bytes: usize) -> String {
        let len = data.len().min(max_bytes);
        let mut output = String::new();
        for offset in (0..len).step_by(16) {
            let end = (offset + 16).min(len);
            let chunk = data.get(offset..end).unwrap_or_default();
            output.push_str(&format!("{:08x}  ", offset));
            for (i, byte) in chunk.iter().enumerate() {
                output.push_str(&format!("{:02x} ", byte));
                if i == 7 {
                    output.push(' ');
                }
            }
            for i in 0..(16 - chunk.len()) {
                output.push_str("   ");
                if chunk.len() + i == 7 {
                    output.push(' ');
                }
            }
            output.push_str(" |");
            for byte in chunk {
                if byte.is_ascii_graphic() || *byte == b' ' {
                    output.push(*byte as char);
                } else {
                    output.push('.');
                }
            }
            output.push_str("|\n");
        }
        if data.len() > max_bytes {
            output.push_str(&format!("... ({} more bytes)\n", data.len() - max_bytes));
        }
        output
    }
}

impl Default for RawHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_RAW_BASE64_CONFIG_BYTES, MAX_RAW_RESPONSE_BYTES, RawHandler};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    const MAX_RAW_FILE_SIZE: u64 = MAX_RAW_RESPONSE_BYTES as u64;

    #[test]
    fn raw_file_response_rejects_oversized_file() {
        let root = unique_temp_dir("nettrap-raw-limit");
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("large.bin");
        let file = std::fs::File::create(&path).expect("create sparse file");
        file.set_len(MAX_RAW_FILE_SIZE + 1)
            .expect("extend sparse file");

        let response = RawHandler::new()
            .with_raw_file(&path)
            .expect("valid raw file config")
            .handle(b"ignored");

        assert_eq!(response.to_bytes(), b"ERROR\n");
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn raw_file_response_allows_file_at_size_limit() {
        let root = unique_temp_dir("nettrap-raw-limit-ok");
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("limit.bin");
        let file = std::fs::File::create(&path).expect("create sparse file");
        file.set_len(MAX_RAW_FILE_SIZE).expect("extend sparse file");

        let response = RawHandler::new()
            .with_raw_file(&path)
            .expect("valid raw file config")
            .handle(b"ignored");

        assert_eq!(response.to_bytes().len() as u64, MAX_RAW_FILE_SIZE);
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn raw_base64_response_rejects_oversized_config() {
        let oversized = "A".repeat(MAX_RAW_BASE64_CONFIG_BYTES + 1);
        let err = RawHandler::new()
            .with_static_base64(&oversized)
            .expect_err("oversized base64 config should be rejected");

        assert!(err.to_string().contains("exceeds size limit"));
    }

    #[test]
    fn raw_base64_response_rejects_invalid_config() {
        let err = RawHandler::new()
            .with_static_base64("not-valid-base64")
            .expect_err("invalid base64 config should be rejected");

        assert!(err.to_string().contains("Invalid base64"));
    }

    #[test]
    fn raw_custom_response_rejects_invalid_base64_config() {
        let err = RawHandler::from_custom_response("base64:not-valid-base64")
            .expect_err("invalid base64 custom response should be rejected");

        assert!(err.to_string().contains("Invalid base64"));
    }

    #[test]
    fn raw_custom_response_rejects_empty_file_path() {
        let err = RawHandler::from_custom_response("file:")
            .expect_err("empty file path custom response should be rejected");

        assert!(err.to_string().contains("non-empty path"));
    }

    #[test]
    fn raw_static_response_rejects_oversized_config() {
        let oversized = "A".repeat(MAX_RAW_RESPONSE_BYTES + 1);
        let err = RawHandler::new()
            .with_static_string(oversized)
            .expect_err("oversized static config should be rejected");

        assert!(err.to_string().contains("exceeds size limit"));
    }

    #[test]
    fn raw_echo_rejects_oversized_payload() {
        let payload = vec![b'a'; MAX_RAW_RESPONSE_BYTES + 1];

        let response = RawHandler::new().handle(&payload);

        assert_eq!(response.to_bytes(), b"ERROR\n");
    }

    #[cfg(unix)]
    #[test]
    fn raw_file_response_rejects_final_symlink() {
        let root = unique_temp_dir("nettrap-raw-symlink");
        std::fs::create_dir_all(&root).expect("create temp root");
        let target = root.join("target.bin");
        let link = root.join("linked.bin");
        std::fs::write(&target, b"secret").expect("write target");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let response = RawHandler::new()
            .with_raw_file(&link)
            .expect("valid raw file config")
            .handle(b"ignored");

        assert_eq!(response.to_bytes(), b"ERROR\n");
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[cfg(unix)]
    #[test]
    fn raw_file_response_rejects_symlink_in_parent_directory() {
        let root = unique_temp_dir("nettrap-raw-parent-symlink");
        let real_parent = root.join("real");
        let symlink_parent = root.join("linked");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        std::fs::write(real_parent.join("payload.bin"), b"secret").expect("write payload");
        std::os::unix::fs::symlink(&real_parent, &symlink_parent).expect("create symlink parent");

        let path = symlink_parent.join("payload.bin");
        let response = RawHandler::new()
            .with_raw_file(&path)
            .expect("valid raw file config")
            .handle(b"ignored");

        assert_eq!(response.to_bytes(), b"ERROR\n");
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[cfg(unix)]
    #[test]
    fn raw_file_response_rejects_fifo_without_blocking() {
        let root = unique_temp_dir("nettrap-raw-fifo");
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("payload.bin");
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo should succeed");

        assert!(matches!(
            super::read_limited_file(&path, MAX_RAW_FILE_SIZE),
            Ok(super::LimitedFileRead::NotFile)
        ));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn raw_file_response_accepts_trailing_current_dir_component() {
        let root = unique_temp_dir("nettrap-raw-curdir");
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("payload.bin");
        std::fs::write(&path, b"secret").expect("write payload");

        let response = RawHandler::new()
            .with_raw_file(path.join("."))
            .expect("valid raw file config")
            .handle(b"ignored");

        assert_eq!(response.to_bytes(), b"secret");
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("{prefix}-{}-{seq}", std::process::id()))
    }
}
