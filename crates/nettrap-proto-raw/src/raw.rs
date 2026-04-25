use std::fs::{File, OpenOptions};
use std::io::{self, Read};

/// Raw protocol handler supporting multiple response modes
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

enum LimitedFileRead {
    Content(Vec<u8>),
    TooLarge,
    NotFile,
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

    pub fn with_static_string(mut self, data: impl Into<String>) -> Self {
        self.mode = RawResponseMode::StaticString(data.into().into_bytes());
        self
    }

    pub fn with_raw_file(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.mode = RawResponseMode::RawFile(path.into());
        self
    }

    pub fn with_static_base64(mut self, b64: &str) -> Self {
        use base64::Engine as _;
        match base64::engine::general_purpose::STANDARD.decode(b64) {
            Ok(decoded) => self.mode = RawResponseMode::StaticBase64(decoded),
            Err(e) => {
                tracing::warn!("Invalid base64 in raw handler config: {}", e);
                self.mode = RawResponseMode::Echo;
            }
        }
        self
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
    pub fn from_custom_response(custom: &str) -> Self {
        let handler = Self::new();
        if custom.is_empty() || custom == "echo" {
            handler.with_echo()
        } else if let Some(text) = custom.strip_prefix("static:") {
            handler.with_static_string(text)
        } else if let Some(b64) = custom.strip_prefix("base64:") {
            handler.with_static_base64(b64)
        } else if let Some(path) = custom.strip_prefix("file:") {
            handler.with_raw_file(path)
        } else if custom == "silent" {
            handler.with_silent()
        } else {
            // Treat as static string by default
            handler.with_static_string(custom)
        }
    }

    pub fn handle(&self, data: &[u8]) -> RawResponse {
        match &self.mode {
            RawResponseMode::Echo => {
                tracing::debug!("Raw echo: {} bytes", data.len());
                RawResponse::new(data.to_vec())
            }
            RawResponseMode::StaticString(response) => RawResponse::new(response.clone()),
            RawResponseMode::RawFile(path) => {
                // Limit file reads to 10MB to prevent OOM
                const MAX_RAW_FILE_SIZE: u64 = 10 * 1024 * 1024;
                match read_limited_file(path, MAX_RAW_FILE_SIZE) {
                    Ok(LimitedFileRead::Content(content)) => RawResponse::new(content),
                    Ok(LimitedFileRead::TooLarge) => {
                        tracing::warn!(
                            "Raw file {} exceeds size limit (>{} bytes)",
                            path.display(),
                            MAX_RAW_FILE_SIZE,
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
            let chunk = &data[offset..end];
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

fn read_limited_file(path: &std::path::Path, max_bytes: u64) -> std::io::Result<LimitedFileRead> {
    let file = match open_regular_file_no_final_symlink(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::InvalidInput => {
            return Ok(LimitedFileRead::NotFile);
        }
        Err(err) => return Err(err),
    };
    let metadata = file.metadata()?;
    if metadata.len() > max_bytes {
        return Ok(LimitedFileRead::TooLarge);
    }

    let mut limited = file.take(max_bytes + 1);
    let mut content = Vec::new();
    limited.read_to_end(&mut content)?;
    if content.len() as u64 > max_bytes {
        return Ok(LimitedFileRead::TooLarge);
    }

    Ok(LimitedFileRead::Content(content))
}

#[cfg(unix)]
fn open_regular_file_no_final_symlink(path: &std::path::Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure_regular_file(file)
}

#[cfg(windows)]
fn open_regular_file_no_final_symlink(path: &std::path::Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    ensure_regular_file(file)
}

#[cfg(not(any(unix, windows)))]
fn open_regular_file_no_final_symlink(path: &std::path::Path) -> io::Result<File> {
    ensure_regular_file(File::open(path)?)
}

fn ensure_regular_file(file: File) -> io::Result<File> {
    if file.metadata()?.is_file() {
        Ok(file)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::RawHandler;

    const MAX_RAW_FILE_SIZE: u64 = 10 * 1024 * 1024;

    #[test]
    fn raw_file_response_rejects_oversized_file() {
        let root = unique_temp_dir("nettrap-raw-limit");
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("large.bin");
        let file = std::fs::File::create(&path).expect("create sparse file");
        file.set_len(MAX_RAW_FILE_SIZE + 1)
            .expect("extend sparse file");

        let response = RawHandler::new().with_raw_file(&path).handle(b"ignored");

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

        let response = RawHandler::new().with_raw_file(&path).handle(b"ignored");

        assert_eq!(response.to_bytes().len() as u64, MAX_RAW_FILE_SIZE);
        std::fs::remove_dir_all(root).expect("cleanup temp root");
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

        let response = RawHandler::new().with_raw_file(&link).handle(b"ignored");

        assert_eq!(response.to_bytes(), b"ERROR\n");
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("{}-{}", prefix, std::process::id()))
    }
}
