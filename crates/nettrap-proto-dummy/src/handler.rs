/// Dummy protocol handler (any port, INetSim-compatible)
///
/// Sends a configurable banner, then logs all received data.
/// Similar to Raw but designed for INetSim compatibility.
pub struct DummyHandler {
    banner: String,
    banner_delay_ms: u64,
    max_bytes: usize,
}

impl DummyHandler {
    pub fn new() -> Self {
        Self {
            banner: String::new(),
            banner_delay_ms: 0,
            max_bytes: 65536,
        }
    }

    pub fn with_banner(mut self, banner: impl Into<String>) -> Self {
        self.banner = banner.into();
        self
    }

    pub fn with_banner_delay(mut self, delay_ms: u64) -> Self {
        self.banner_delay_ms = delay_ms;
        self
    }

    pub fn with_max_bytes(mut self, max: usize) -> Self {
        self.max_bytes = max;
        self
    }

    /// Returns the banner string to send on connect.
    pub fn get_banner(&self) -> &str {
        &self.banner
    }

    /// Returns the configured banner delay in milliseconds.
    pub fn get_banner_delay_ms(&self) -> u64 {
        self.banner_delay_ms
    }

    /// Log received data and return an empty response (sink mode).
    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        let len = data.len().min(self.max_bytes);
        let preview: String = data[..len.min(64)]
            .iter()
            .map(|b| if b.is_ascii_graphic() || *b == b' ' { *b as char } else { '.' })
            .collect();
        tracing::info!("Dummy received {} bytes: {}", data.len(), preview);
        Vec::new() // Sink: no response
    }
}

impl Default for DummyHandler {
    fn default() -> Self {
        Self::new()
    }
}
