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

        let user_data = &data[8..];
        let Some(user_end) = user_data.iter().position(|&b| b == 0) else {
            return Vec::new();
        };
        let user = String::from_utf8_lossy(&user_data[..user_end]);

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
        // Use >= to handle cases where handshake and connect arrive in one TCP read
        let nmethods = data[1] as usize;
        if nmethods > 0 && data.len() >= 2 + nmethods {
            // Either exact handshake length, or next byte is another SOCKS5 message (0x05)
            if data.len() == 2 + nmethods
                || (data.len() > 2 + nmethods && data[2 + nmethods] == 0x05)
            {
                tracing::info!("SOCKS5 handshake: {} auth methods", nmethods);
                // Accept no authentication
                return vec![0x05, 0x00];
            }
        }

        // This might be a connect request
        if data.len() >= 7 && data[1] == 0x01 && data[2] == 0x00 {
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
                    if dlen == 0 || data.len() < 5 + dlen + 2 {
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

#[cfg(test)]
mod tests {
    use super::SocksHandler;

    #[test]
    fn socks4_requires_null_terminated_user() {
        let handler = SocksHandler::new();
        let unterminated = [0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, b'u', b's', b'e', b'r'];

        assert!(handler.handle(&unterminated).is_empty());
    }

    #[test]
    fn socks4_accepts_null_terminated_user() {
        let handler = SocksHandler::new();
        let request = [
            0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, b'u', b's', b'e', b'r', 0x00,
        ];

        assert_eq!(
            handler.handle(&request),
            vec![0x00, 0x5A, 0x00, 0x50, 127, 0, 0, 1]
        );
    }

    #[test]
    fn socks5_connect_rejects_nonzero_reserved_byte() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x01, 0x01, 0x01, 127, 0, 0, 1, 0x00, 0x50];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks5_connect_accepts_complete_domain_request() {
        let handler = SocksHandler::new();
        let request = [
            0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b't',
            b'e', b's', b't', 0x00, 0x50,
        ];

        assert_eq!(
            handler.handle(&request),
            vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn socks5_connect_rejects_empty_domain() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50];

        assert!(handler.handle(&request).is_empty());
    }
}
