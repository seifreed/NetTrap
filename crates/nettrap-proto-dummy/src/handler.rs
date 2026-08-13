/// Dummy protocol handler (any port, INetSim-compatible)
///
/// Logs received data and returns an empty response.
/// Similar to Raw but designed for INetSim compatibility.
pub struct DummyHandler {
    max_bytes: usize,
}

impl DummyHandler {
    pub fn new() -> Self {
        Self { max_bytes: 65536 }
    }

    /// Log received data and return an empty response (sink mode).
    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        let (visible_len, preview, truncated) = self.preview_received_data(data);
        tracing::info!(
            "Dummy received {} bytes{}: {}",
            visible_len,
            if truncated { " (truncated)" } else { "" },
            preview
        );
        Vec::new() // Sink: no response
    }

    fn preview_received_data(&self, data: &[u8]) -> (usize, String, bool) {
        let visible_len = data.len().min(self.max_bytes);
        let preview: String = data
            .get(..visible_len.min(64))
            .unwrap_or(data)
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        (visible_len, preview, data.len() > self.max_bytes)
    }
}

impl Default for DummyHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::DummyHandler;

    #[test]
    fn preview_received_data_respects_max_bytes_and_sanitizes_control_bytes() {
        let handler = DummyHandler { max_bytes: 6 };

        let (visible_len, preview, truncated) = handler.preview_received_data(b"ab\ncdeFGH");

        assert_eq!(visible_len, 6);
        assert_eq!(preview, "ab.cde");
        assert!(truncated);
    }
}
