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
        let ip_octets = [data[4], data[5], data[6], data[7]];
        let ip = format!(
            "{}.{}.{}.{}",
            ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]
        );

        let user_data = &data[8..];
        let Some(user_end) = user_data.iter().position(|&b| b == 0) else {
            return Vec::new();
        };
        let user = String::from_utf8_lossy(&user_data[..user_end]);
        let mut dest = ip;
        if ip_octets[0] == 0 && ip_octets[1] == 0 && ip_octets[2] == 0 && ip_octets[3] != 0 {
            let domain_data = &user_data[user_end + 1..];
            let Some(domain_end) = domain_data.iter().position(|&b| b == 0) else {
                return Vec::new();
            };
            let domain = &domain_data[..domain_end];
            if domain.is_empty() || domain.iter().any(|byte| byte.is_ascii_control()) {
                return Vec::new();
            }
            dest = String::from_utf8_lossy(domain).to_string();
        }

        tracing::warn!(
            "SOCKS4 request: cmd={}, dest={}:{}, user={}",
            cmd,
            dest,
            port,
            user
        );

        if cmd != 0x01 {
            tracing::info!("SOCKS4 unsupported command: {}", cmd);
            return Self::socks4_reply(0x5B, data);
        }

        Self::socks4_reply(0x5A, data)
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
                let methods = &data[2..2 + nmethods];
                return if methods.contains(&0x00) {
                    vec![0x05, 0x00]
                } else {
                    vec![0x05, 0xFF]
                };
            }
        }

        if data.len() >= 7 && data[2] == 0x00 {
            let cmd = data[1];
            let Some((dest, port_offset, reply_atyp)) = Self::parse_socks5_address(data) else {
                return Vec::new();
            };
            if port_offset.checked_add(2) != Some(data.len()) {
                return Vec::new();
            }
            let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);

            match cmd {
                0x01 => {
                    tracing::warn!("SOCKS5 CONNECT: dest={}:{}", dest, port);
                    return Self::socks5_reply(0x00, reply_atyp);
                }
                0x02 | 0x03 => {
                    tracing::info!(
                        "SOCKS5 unsupported command: cmd={}, dest={}:{}",
                        cmd,
                        dest,
                        port
                    );
                    return Self::socks5_reply(0x07, reply_atyp);
                }
                _ => {
                    tracing::info!("SOCKS5 unsupported command: {}", cmd);
                    return Self::socks5_reply(0x07, reply_atyp);
                }
            }
        }

        Vec::new()
    }

    fn parse_socks5_address(data: &[u8]) -> Option<(String, usize, u8)> {
        match data[3] {
            0x01 => {
                if data.len() < 10 {
                    return None;
                }
                Some((
                    format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]),
                    8,
                    0x01,
                ))
            }
            0x03 => {
                let dlen = data[4] as usize;
                if dlen == 0 || data.len() < 5 + dlen + 2 {
                    return None;
                }
                let domain = &data[5..5 + dlen];
                if domain.iter().any(|byte| byte.is_ascii_control()) {
                    return None;
                }
                Some((String::from_utf8_lossy(domain).to_string(), 5 + dlen, 0x01))
            }
            0x04 => {
                if data.len() < 22 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[4..20]);
                Some((std::net::Ipv6Addr::from(octets).to_string(), 20, 0x04))
            }
            _ => None,
        }
    }

    fn socks4_reply(status: u8, data: &[u8]) -> Vec<u8> {
        vec![
            0x00, status, data[2], data[3], data[4], data[5], data[6], data[7],
        ]
    }

    fn socks5_reply(status: u8, atyp: u8) -> Vec<u8> {
        if atyp == 0x04 {
            let mut response = vec![0x05, status, 0x00, 0x04];
            response.extend_from_slice(&[0u8; 16]);
            response.extend_from_slice(&[0x00, 0x00]);
            response
        } else {
            vec![0x05, status, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        }
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
    fn socks4_rejects_unsupported_commands() {
        let handler = SocksHandler::new();
        let request = [
            0x04, 0x02, 0x00, 0x50, 127, 0, 0, 1, b'u', b's', b'e', b'r', 0x00,
        ];

        assert_eq!(
            handler.handle(&request),
            vec![0x00, 0x5B, 0x00, 0x50, 127, 0, 0, 1]
        );
    }

    #[test]
    fn socks4a_requires_null_terminated_domain() {
        let handler = SocksHandler::new();
        let request = [
            0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, b'u', b's', b'e', b'r', 0x00, b'e', b'x', b'a',
        ];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks4a_accepts_domain_form() {
        let handler = SocksHandler::new();
        let request = [
            0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, b'u', b's', b'e', b'r', 0x00, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 0x00,
        ];

        assert_eq!(
            handler.handle(&request),
            vec![0x00, 0x5A, 0x00, 0x50, 0, 0, 0, 1]
        );
    }

    #[test]
    fn socks5_handshake_rejects_when_no_no_auth_method_is_offered() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x01, 0x02];

        assert_eq!(handler.handle(&request), vec![0x05, 0xFF]);
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
            0x05, 0x01, 0x00, 0x03, 0x0c, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b't',
            b'e', b's', b't', 0x00, 0x50,
        ];

        assert_eq!(
            handler.handle(&request),
            vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn socks5_connect_rejects_trailing_bytes_after_declared_address() {
        let handler = SocksHandler::new();
        let request = [
            0x05, 0x01, 0x00, 0x03, 0x0c, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b't',
            b'e', b's', b't', 0x00, 0x50, 0x05,
        ];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks5_connect_rejects_empty_domain() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks5_connect_rejects_control_bytes_in_domain() {
        let handler = SocksHandler::new();
        let request = [
            0x05, 0x01, 0x00, 0x03, 0x08, b'e', b'x', b'a', 0x00, b'p', b'l', b'e', b'.', 0x00,
            0x50,
        ];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks5_unsupported_commands_return_command_not_supported() {
        let handler = SocksHandler::new();
        let bind = [0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];
        let udp_associate = [0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];

        assert_eq!(
            handler.handle(&bind),
            vec![0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            handler.handle(&udp_associate),
            vec![0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn socks5_ipv6_connect_uses_ipv6_reply_address_type() {
        let handler = SocksHandler::new();
        let request = [
            0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0x00, 0x50,
        ];

        let response = handler.handle(&request);

        assert_eq!(response.len(), 22);
        assert_eq!(&response[..4], &[0x05, 0x00, 0x00, 0x04]);
    }
}
