pub struct SocksHandler;

const REDACTED_SOCKS_FIELD: &str = "***REDACTED***";

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
        let ip = std::net::Ipv4Addr::new(ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3]);

        let user_data = &data[8..];
        let Some(user_end) = user_data.iter().position(|&b| b == 0) else {
            return Vec::new();
        };
        let user = nettrap_core::sanitize::single_line_bytes(&user_data[..user_end]);
        let after_user = &user_data[user_end + 1..];
        let is_socks4a_domain =
            ip_octets[0] == 0 && ip_octets[1] == 0 && ip_octets[2] == 0 && ip_octets[3] != 0;
        let mut dest = ip.to_string();
        if is_socks4a_domain {
            let Some(domain_end) = after_user.iter().position(|&b| b == 0) else {
                return Vec::new();
            };
            if domain_end + 1 != after_user.len() {
                return Vec::new();
            }
            let Some(domain) = safe_log_domain(&after_user[..domain_end]) else {
                return Vec::new();
            };
            dest = domain;
        } else if !after_user.is_empty() {
            return Vec::new();
        }

        if !is_socks4a_domain && !is_usable_socks5_ipv4(ip) {
            return Vec::new();
        }

        tracing::debug!(
            "SOCKS4 request: cmd={}, dest={}:{}, user={}",
            cmd,
            dest,
            port,
            user
        );
        tracing::warn!(
            "SOCKS4 request: cmd={}, dest={}, user={}",
            cmd,
            REDACTED_SOCKS_FIELD,
            REDACTED_SOCKS_FIELD
        );

        if port == 0 {
            return Self::socks4_reply(0x5B, data);
        }

        if cmd != 0x01 {
            tracing::info!("SOCKS4 unsupported command: {}", cmd);
            return Self::socks4_reply(0x5B, data);
        }

        Self::socks4_reply(0x5A, data)
    }

    fn handle_socks5(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 2 {
            return Vec::new();
        }

        // Exact-length greetings must be recognized before request decoding.
        let nmethods = data[1] as usize;
        if data.len() == 2 + nmethods {
            if nmethods == 0 {
                return vec![0x05, 0xFF];
            }

            tracing::info!("SOCKS5 handshake: {} auth methods", nmethods);
            let methods = &data[2..2 + nmethods];
            return if methods.contains(&0x00) {
                vec![0x05, 0x00]
            } else {
                vec![0x05, 0xFF]
            };
        }

        if nmethods == 0 && data.len() > 2 {
            return Vec::new();
        }
        let looks_like_request =
            matches!(data[1], 0x01..=0x03) && data.len() >= 7 && data[2] == 0x00;
        if data.len() < 2 + nmethods && !looks_like_request {
            return Vec::new();
        }

        if data.len() >= 7 && data[2] == 0x00 {
            let cmd = data[1];
            let request_atyp = data[3];
            let Some((dest, port_offset, reply_atyp)) = Self::parse_socks5_address(data) else {
                return if matches!(request_atyp, 0x01 | 0x03 | 0x04) {
                    Vec::new()
                } else if data.len() >= 10 {
                    Self::socks5_reply(0x08, 0x01)
                } else {
                    Vec::new()
                };
            };
            if port_offset.checked_add(2) != Some(data.len()) {
                return Vec::new();
            }
            let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);
            if port == 0 {
                return Self::socks5_reply(0x01, reply_atyp);
            }

            match cmd {
                0x01 => {
                    tracing::debug!("SOCKS5 CONNECT: dest={}:{}", dest, port);
                    tracing::warn!("SOCKS5 CONNECT: dest={}", REDACTED_SOCKS_FIELD);
                    return Self::socks5_reply(0x00, reply_atyp);
                }
                0x02 | 0x03 => {
                    tracing::debug!(
                        "SOCKS5 unsupported command: cmd={}, dest={}:{}",
                        cmd,
                        dest,
                        port
                    );
                    tracing::info!(
                        "SOCKS5 unsupported command: cmd={}, dest={}",
                        cmd,
                        REDACTED_SOCKS_FIELD
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
                let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                if !is_usable_socks5_ipv4(ip) {
                    return None;
                }
                Some((ip.to_string(), 8, 0x01))
            }
            0x03 => {
                let dlen = data[4] as usize;
                if dlen == 0 || data.len() < 5 + dlen + 2 {
                    return None;
                }
                Some((safe_log_domain(&data[5..5 + dlen])?, 5 + dlen, 0x03))
            }
            0x04 => {
                if data.len() < 22 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[4..20]);
                let ip = std::net::Ipv6Addr::from(octets);
                if !is_usable_socks5_ipv6(ip) {
                    return None;
                }
                Some((canonicalize_socks5_ip(ip.into()), 20, 0x04))
            }
            _ => None,
        }
    }

    fn domain_name_is_valid(domain: &[u8]) -> bool {
        let Ok(domain) = std::str::from_utf8(domain) else {
            return false;
        };
        let domain = domain.strip_suffix('.').unwrap_or(domain);
        !domain.is_empty()
            && domain.len() <= 253
            && domain
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            && domain.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            })
            && !domain
                .split('.')
                .all(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
    }

    fn socks4_reply(status: u8, data: &[u8]) -> Vec<u8> {
        vec![
            0x00, status, data[2], data[3], data[4], data[5], data[6], data[7],
        ]
    }

    fn socks5_reply(status: u8, atyp: u8) -> Vec<u8> {
        match atyp {
            0x04 => {
                let mut response = vec![0x05, status, 0x00, 0x04];
                response.extend_from_slice(&[0u8; 16]);
                response.extend_from_slice(&[0x00, 0x00]);
                response
            }
            _ => vec![0x05, status, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        }
    }
}

impl Default for SocksHandler {
    fn default() -> Self {
        Self::new()
    }
}

fn safe_log_domain(data: &[u8]) -> Option<String> {
    if !SocksHandler::domain_name_is_valid(data) {
        return None;
    }
    let domain = std::str::from_utf8(data).ok()?;
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    Some(nettrap_core::sanitize::single_line(domain).to_ascii_lowercase())
}

fn is_usable_socks5_ipv4(ip: std::net::Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
}

fn is_usable_socks5_ipv6(ip: std::net::Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_usable_socks5_ipv4(mapped);
    }
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
}

fn canonicalize_socks5_ip(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or_else(|| ip.to_string(), |mapped| mapped.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{SocksHandler, is_usable_socks5_ipv4, is_usable_socks5_ipv6, safe_log_domain};

    const LOG_FIELD_PREVIEW_CHARS: usize = 240;

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
            0x04, 0x01, 0x00, 0x50, 192, 0, 2, 10, b'u', b's', b'e', b'r', 0x00,
        ];

        assert_eq!(
            handler.handle(&request),
            vec![0x00, 0x5A, 0x00, 0x50, 192, 0, 2, 10]
        );
    }

    #[test]
    fn logged_socks4_user_is_single_line() {
        assert_eq!(
            nettrap_core::sanitize::single_line_bytes(b"alice\r\nadmin\x1b"),
            "alice  admin "
        );

        let long = vec![b'a'; LOG_FIELD_PREVIEW_CHARS + 1];
        assert_eq!(
            nettrap_core::sanitize::single_line_bytes(&long).len(),
            LOG_FIELD_PREVIEW_CHARS
        );
    }

    #[test]
    fn logged_socks_domain_is_bounded() {
        let long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(58)
        );

        assert_eq!(
            safe_log_domain(long.as_bytes())
                .expect("printable domain should be logged")
                .len(),
            LOG_FIELD_PREVIEW_CHARS
        );
        assert!(safe_log_domain(b"bad\nname").is_none());
    }

    #[test]
    fn socks4_rejects_trailing_bytes_after_user() {
        let handler = SocksHandler::new();
        let request = [
            0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, b'u', b's', b'e', b'r', 0x00, b'x',
        ];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks4_rejects_unsupported_commands() {
        let handler = SocksHandler::new();
        let request = [
            0x04, 0x02, 0x00, 0x50, 192, 0, 2, 10, b'u', b's', b'e', b'r', 0x00,
        ];

        assert_eq!(
            handler.handle(&request),
            vec![0x00, 0x5B, 0x00, 0x50, 192, 0, 2, 10]
        );
    }

    #[test]
    fn socks4_rejects_zero_destination_port() {
        let handler = SocksHandler::new();
        let request = [
            0x04, 0x01, 0x00, 0x00, 192, 0, 2, 10, b'u', b's', b'e', b'r', 0x00,
        ];

        assert_eq!(
            handler.handle(&request),
            vec![0x00, 0x5B, 0x00, 0x00, 192, 0, 2, 10]
        );
    }

    #[test]
    fn socks4_rejects_unspecified_destination_address() {
        let handler = SocksHandler::new();
        let request = [
            0x04, 0x01, 0x00, 0x50, 0, 0, 0, 0, b'u', b's', b'e', b'r', 0x00,
        ];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks4_rejects_unusable_literal_destinations() {
        let handler = SocksHandler::new();
        for ip in [
            std::net::Ipv4Addr::LOCALHOST,
            std::net::Ipv4Addr::new(224, 0, 0, 1),
            std::net::Ipv4Addr::new(255, 255, 255, 255),
        ] {
            let octets = ip.octets();
            let request = [
                0x04, 0x01, 0x00, 0x50, octets[0], octets[1], octets[2], octets[3], b'u', 0x00,
            ];

            assert!(handler.handle(&request).is_empty(), "{ip}");
        }
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
    fn socks4a_canonicalizes_domain_case() {
        let handler = SocksHandler::new();
        let upper = [
            0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, b'u', b's', b'e', b'r', 0x00, b'E', b'X', b'A',
            b'M', b'P', b'L', b'E', 0x00,
        ];
        let lower = [
            0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, b'u', b's', b'e', b'r', 0x00, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 0x00,
        ];

        assert_eq!(handler.handle(&upper), handler.handle(&lower));
    }

    #[test]
    fn socks4a_rejects_trailing_bytes_after_domain() {
        let handler = SocksHandler::new();
        let request = [
            0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, b'u', b's', b'e', b'r', 0x00, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 0x00, b'x',
        ];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks4a_rejects_non_ascii_domain() {
        let handler = SocksHandler::new();
        let request = [
            0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, b'u', b's', b'e', b'r', 0x00, b'e', 0xff, 0x00,
        ];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks4a_rejects_invalid_domain_names() {
        let handler = SocksHandler::new();

        for domain in [
            b"bad/name".as_slice(),
            b"bad:80".as_slice(),
            b"bad..name".as_slice(),
            b"-bad.name".as_slice(),
            b"127.0.0.1".as_slice(),
        ] {
            let mut request = vec![0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, b'u', 0x00];
            request.extend_from_slice(domain);
            request.push(0x00);

            assert!(handler.handle(&request).is_empty(), "{domain:?}");
        }
    }

    #[test]
    fn socks5_handshake_rejects_when_no_no_auth_method_is_offered() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x01, 0x02];

        assert_eq!(handler.handle(&request), vec![0x05, 0xFF]);
    }

    #[test]
    fn socks5_handshake_rejects_zero_advertised_methods() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x00];

        assert_eq!(handler.handle(&request), vec![0x05, 0xFF]);
    }

    #[test]
    fn socks5_handshake_rejects_zero_methods_with_trailing_bytes() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks5_handshake_rejects_trailing_bytes_after_zero_methods() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x00, 0x00];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks5_handshake_with_noauth_method_in_later_slot_is_not_misread_as_request() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x05, 0x02, 0x00, 0x01, 0x03, 0x80];

        assert_eq!(handler.handle(&request), vec![0x05, 0x00]);
    }

    #[test]
    fn socks5_handshake_with_request_like_bytes_prefers_handshake_parsing() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x08, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50];

        assert_eq!(handler.handle(&request), vec![0x05, 0x00]);
    }

    #[test]
    fn socks5_incomplete_large_method_list_is_not_misread_as_request() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x09, 0x00, 0x01, 192, 0, 2, 10, 0x00, 0x50];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks5_handshake_rejects_non_socks_trailing_bytes() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x01, 0x00, 0x99, 0x88, 0x77];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks5_handshake_rejects_coalesced_follow_on_bytes() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x00];

        assert!(handler.handle(&request).is_empty());
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
    fn socks5_connect_canonicalizes_domain_case() {
        let handler = SocksHandler::new();
        let upper = [
            0x05, 0x01, 0x00, 0x03, 0x0c, b'E', b'X', b'A', b'M', b'P', b'L', b'E', b'.', b'T',
            b'E', b'S', b'T', 0x00, 0x50,
        ];
        let lower = [
            0x05, 0x01, 0x00, 0x03, 0x0c, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b't',
            b'e', b's', b't', 0x00, 0x50,
        ];

        assert_eq!(handler.handle(&upper), handler.handle(&lower));
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
    fn socks5_connect_rejects_zero_destination_port() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x01, 0x00, 0x01, 192, 0, 2, 10, 0x00, 0x00];

        assert_eq!(
            handler.handle(&request),
            vec![0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn socks5_connect_rejects_unspecified_ipv4_destination() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x50];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks5_connect_rejects_unusable_ipv4_destination() {
        let handler = SocksHandler::new();
        for ip in [
            std::net::Ipv4Addr::LOCALHOST,
            std::net::Ipv4Addr::new(224, 0, 0, 1),
            std::net::Ipv4Addr::new(255, 255, 255, 255),
        ] {
            assert!(!is_usable_socks5_ipv4(ip));

            let octets = ip.octets();
            let request = [
                0x05, 0x01, 0x00, 0x01, octets[0], octets[1], octets[2], octets[3], 0x00, 0x50,
            ];
            assert!(handler.handle(&request).is_empty());
        }
    }

    #[test]
    fn socks5_connect_rejects_unspecified_ipv6_destination() {
        let handler = SocksHandler::new();
        let request = [
            0x05, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x50,
        ];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks5_connect_rejects_unusable_ipv6_destination() {
        let handler = SocksHandler::new();
        for ip in [
            std::net::Ipv6Addr::LOCALHOST,
            std::net::Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1]),
        ] {
            assert!(!is_usable_socks5_ipv6(ip));

            let request_ip = ip.octets();
            let mut request = vec![0x05, 0x01, 0x00, 0x04];
            request.extend_from_slice(&request_ip);
            request.extend_from_slice(&[0x00, 0x50]);
            assert!(handler.handle(&request).is_empty());
        }
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
    fn socks5_connect_rejects_non_ascii_domain() {
        let handler = SocksHandler::new();
        let request = [0x05, 0x01, 0x00, 0x03, 0x02, b'e', 0xff, 0x00, 0x50];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks5_connect_rejects_invalid_domain_names() {
        let handler = SocksHandler::new();

        for domain in [
            b"bad/name".as_slice(),
            b"bad:80".as_slice(),
            b"bad..name".as_slice(),
            b"-bad.name".as_slice(),
            b"127.0.0.1".as_slice(),
        ] {
            let mut request = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
            request.extend_from_slice(domain);
            request.extend_from_slice(&[0x00, 0x50]);

            assert!(handler.handle(&request).is_empty(), "{domain:?}");
        }
    }

    #[test]
    fn socks5_connect_accepts_absolute_domain_hostnames_with_trailing_dots() {
        let handler = SocksHandler::new();
        let request = [
            0x05, 0x01, 0x00, 0x03, 0x0d, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b't',
            b'e', b's', b't', b'.', 0x00, 0x50,
        ];

        assert_eq!(
            handler.handle(&request),
            vec![0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn socks5_connect_rejects_multiple_trailing_dots() {
        let handler = SocksHandler::new();
        let request = [
            0x05, 0x01, 0x00, 0x03, 0x0e, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b't',
            b'e', b's', b't', b'.', b'.', 0x00, 0x50,
        ];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks4a_accepts_absolute_domain_hostnames_with_trailing_dots() {
        let handler = SocksHandler::new();
        let request = [
            0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, b'u', b's', b'e', b'r', 0x00, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', b'.', b't', b'e', b's', b't', b'.', 0x00,
        ];

        assert_eq!(
            handler.handle(&request),
            vec![0x00, 0x5A, 0x00, 0x50, 0, 0, 0, 1]
        );
    }

    #[test]
    fn socks4a_rejects_multiple_trailing_dots() {
        let handler = SocksHandler::new();
        let request = [
            0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, b'u', b's', b'e', b'r', 0x00, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', b'.', b't', b'e', b's', b't', b'.', b'.', 0x00,
        ];

        assert!(handler.handle(&request).is_empty());
    }

    #[test]
    fn socks5_unsupported_commands_return_command_not_supported() {
        let handler = SocksHandler::new();
        let bind = [0x05, 0x02, 0x00, 0x01, 192, 0, 2, 10, 0x00, 0x50];
        let udp_associate = [0x05, 0x03, 0x00, 0x01, 192, 0, 2, 10, 0x00, 0x50];
        let unsupported_atyp = [0x05, 0x01, 0x00, 0x05, 0, 0, 0, 0, 0, 0];

        assert_eq!(
            handler.handle(&bind),
            vec![0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            handler.handle(&udp_associate),
            vec![0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            handler.handle(&unsupported_atyp),
            vec![0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
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

    #[test]
    fn socks5_ipv6_mapped_connect_canonicalizes_destination_text() {
        let mut request = vec![0x05, 0x01, 0x00, 0x04];
        request.extend_from_slice(&[0; 10]);
        request.extend_from_slice(&[0xff, 0xff, 192, 0, 2, 7]);
        request.extend_from_slice(&[0x00, 0x50]);

        let (dest, port_offset, atyp) =
            SocksHandler::parse_socks5_address(&request).expect("mapped address should parse");

        assert_eq!(dest, "192.0.2.7");
        assert_eq!(port_offset, 20);
        assert_eq!(atyp, 0x04);
    }
}
