
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

        if data.len() < 20 {
            return None;
        }

        let first_byte = data[0];
        if (first_byte & 0x80) == 0 {
            return None;
        }

        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        if version != 0 && version != 0xff000016 && version != 0xff000017
            && data.len() > 20 {
                let dcid_len = data[5] as usize;
                let offset = 6 + dcid_len;
                if offset + 1 < data.len() {
                    let scid_len = data[offset] as usize;
                    let token_offset = offset + 1 + scid_len;
                    if token_offset + 1 < data.len() {
                        let _token_len = u64::from_be_bytes({
                            let mut arr = [0u8; 8];
                            let len = std::cmp::min(8, data.len() - token_offset);
                            arr[..len].copy_from_slice(&data[token_offset..token_offset + len]);
                            arr
                        }) as usize;
                        return None;
                    }
                }
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
