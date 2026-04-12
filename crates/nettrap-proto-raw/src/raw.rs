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
                match std::fs::metadata(path) {
                    Ok(meta) if meta.len() > MAX_RAW_FILE_SIZE => {
                        tracing::warn!(
                            "Raw file {} exceeds size limit ({} bytes > {})",
                            path.display(),
                            meta.len(),
                            MAX_RAW_FILE_SIZE,
                        );
                        RawResponse::new(b"ERROR\n".to_vec())
                    }
                    _ => match std::fs::read(path) {
                        Ok(content) => RawResponse::new(content),
                        Err(e) => {
                            tracing::warn!("Failed to read raw file {}: {}", path.display(), e);
                            RawResponse::new(b"ERROR\n".to_vec())
                        }
                    },
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
