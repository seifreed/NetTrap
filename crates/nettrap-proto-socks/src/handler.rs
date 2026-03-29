pub struct SocksHandler;

impl SocksHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }

        match data[0] {
            0x04 => self.handle_socks4(data),
            0x05 => self.handle_socks5(data),
            _ => Vec::new(),
        }
    }

    fn handle_socks4(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 9 {
            return Vec::new();
        }
        let cmd = data[1];
        let port = u16::from_be_bytes([data[2], data[3]]);
        let ip = format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]);
        let user_end = data[8..].iter().position(|&b| b == 0).unwrap_or(0);
        let user = String::from_utf8_lossy(&data[8..8 + user_end]);

        tracing::warn!(
            "SOCKS4 request: cmd={}, dest={}:{}, user={}",
            cmd,
            ip,
            port,
            user
        );

        // Reply: granted
        vec![
            0x00, 0x5A, data[2], data[3], data[4], data[5], data[6], data[7],
        ]
    }

    fn handle_socks5(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 3 {
            return Vec::new();
        }

        // Check if this is the initial handshake (version + nmethods + methods)
        let nmethods = data[1] as usize;
        if data.len() == 2 + nmethods {
            tracing::info!("SOCKS5 handshake: {} auth methods", nmethods);
            // Accept no authentication
            return vec![0x05, 0x00];
        }

        // This might be a connect request
        if data.len() >= 7 && data[1] == 0x01 {
            // CONNECT
            let atyp = data[3];
            let (dest, port_offset) = match atyp {
                0x01 => {
                    // IPv4
                    if data.len() < 10 {
                        return Vec::new();
                    }
                    (
                        format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]),
                        8,
                    )
                }
                0x03 => {
                    // Domain
                    let dlen = data[4] as usize;
                    if data.len() < 5 + dlen + 2 {
                        return Vec::new();
                    }
                    (
                        String::from_utf8_lossy(&data[5..5 + dlen]).to_string(),
                        5 + dlen,
                    )
                }
                0x04 => {
                    // IPv6
                    if data.len() < 22 {
                        return Vec::new();
                    }
                    ("IPv6".to_string(), 20)
                }
                _ => return Vec::new(),
            };

            if port_offset + 2 <= data.len() {
                let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);
                tracing::warn!("SOCKS5 CONNECT: dest={}:{}", dest, port);
            }

            // Reply: success
            return vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        }

        Vec::new()
    }
}

impl Default for SocksHandler {
    fn default() -> Self {
        Self::new()
    }
}
