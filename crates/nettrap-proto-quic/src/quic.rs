pub struct QuicHandler {
    version: u32,
}

impl QuicHandler {
    pub fn new() -> Self {
        Self { version: 1 }
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn detect_quic(&self, data: &[u8]) -> bool {
        if data.len() < 5 {
            return false;
        }

        let first_byte = data[0];
        let is_long_header = (first_byte & 0x80) != 0;
        is_long_header && data.len() >= 9
    }

    pub fn extract_sni(&self, data: &[u8]) -> Option<String> {
        if !self.detect_quic(data) {
            return None;
        }

        None
    }
}

impl Default for QuicHandler {
    fn default() -> Self {
        Self::new()
    }
}

pub fn detect_quic(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }

    let first_byte = data[0];
    let is_long_header = (first_byte & 0x80) != 0;
    is_long_header && data.len() >= 9
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_sni_does_not_guess_from_quic_initial_payload() {
        let handler = QuicHandler::new();
        let mut packet = vec![0xc3, 0, 0, 0, 1, 0, 0, 0, 0];
        packet.extend_from_slice(b"\x00\x00\x00\x11\x00\x0f\x00\x0cexample.com");

        assert!(handler.detect_quic(&packet));
        assert_eq!(handler.extract_sni(&packet), None);
    }

    #[test]
    fn detect_quic_requires_long_header_shape() {
        let handler = QuicHandler::new();

        assert!(!handler.detect_quic(&[0x43, 0, 0, 0, 1, 0, 0, 0, 0]));
        assert!(handler.detect_quic(&[0xc3, 0, 0, 0, 1, 0, 0, 0, 0]));
    }
}
