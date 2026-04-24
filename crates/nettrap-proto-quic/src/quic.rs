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
        if !self.detect_quic(data) || data.len() < 20 {
            return None;
        }

        if (data[0] & 0x80) == 0 {
            return None; // Short header, no SNI
        }

        // Parse QUIC Long Header: version(4) + DCID len(1) + DCID + SCID len(1) + SCID
        let dcid_len = data[5] as usize;
        let mut pos = 6 + dcid_len;
        if pos >= data.len() {
            return None;
        }
        let scid_len = data[pos] as usize;
        pos += 1 + scid_len;

        // Token length (QUIC variable-length integer encoding)
        let (token_len, vi_len) = Self::read_varint(data, pos)?;
        pos += vi_len + token_len;

        // Packet length (also variable-length integer)
        let (_pkt_len, vi_len) = Self::read_varint(data, pos)?;
        pos += vi_len;

        // Skip packet number (assume 1 byte for Initial packets)
        pos += 1;

        // Now we're in the CRYPTO frame payload area.
        // Search for TLS ClientHello SNI extension pattern.
        // SNI is inside the TLS ClientHello within the CRYPTO frame.
        Self::find_sni_in_payload(&data[pos.min(data.len())..])
    }

    /// Read a QUIC variable-length integer. Returns (value, bytes_consumed).
    fn read_varint(data: &[u8], pos: usize) -> Option<(usize, usize)> {
        if pos >= data.len() {
            return None;
        }
        let first = data[pos];
        let len = 1 << ((first >> 6) & 0x03);
        if pos + len > data.len() {
            return None;
        }
        let val = match len {
            1 => (first & 0x3F) as usize,
            2 => {
                let v = u16::from_be_bytes([data[pos], data[pos + 1]]);
                (v & 0x3FFF) as usize
            }
            4 => {
                let v =
                    u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
                (v & 0x3FFFFFFF) as usize
            }
            _ => return None, // 8-byte varints unlikely for our use
        };
        Some((val, len))
    }

    /// Search for SNI (server_name extension) in a TLS ClientHello payload.
    fn find_sni_in_payload(data: &[u8]) -> Option<String> {
        // Look for SNI extension type (0x0000) followed by SNI list
        // Pattern: 0x00 0x00 <ext_len:2> <sni_list_len:2> 0x00 <name_len:2> <hostname>
        for i in 0..data.len().saturating_sub(8) {
            if data[i] == 0x00 && data[i + 1] == 0x00 {
                let ext_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
                // Need at least 5 bytes: 2 (sni_list_len) + 1 (type) + 2 (name_len)
                // and must fit within bounds
                if ext_len >= 5 && i + 4 + ext_len <= data.len() {
                    let sni_type = data[i + 6]; // 0x00 = hostname
                    if sni_type == 0x00 {
                        let name_len = u16::from_be_bytes([data[i + 7], data[i + 8]]) as usize;
                        if name_len > 0 && i + 9 + name_len <= data.len() {
                            let hostname = std::str::from_utf8(&data[i + 9..i + 9 + name_len]);
                            if let Ok(h) = hostname {
                                if h.contains('.') && h.is_ascii() {
                                    return Some(h.to_string());
                                }
                            }
                        }
                    }
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
