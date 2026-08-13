pub struct RdpHandler {
    // X.224 Connection Confirm + RDP Negotiation Response
}

const REDACTED_LOGIN_FIELD: &str = "***REDACTED***";

impl RdpHandler {
    pub fn new() -> Self {
        Self {}
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 7 {
            return Vec::new();
        }

        // TPKT header: version(1) + reserved(1) + length(2)
        if data[0] != 0x03 || data[1] != 0x00 {
            // Not TPKT
            return Vec::new();
        }
        let tpkt_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if tpkt_len < 7 || tpkt_len != data.len() {
            return Vec::new();
        }
        let frame = &data[..tpkt_len];
        let x224_len = frame[4] as usize;
        if x224_len < 2 || 5 + x224_len != frame.len() {
            return Vec::new();
        }

        // X.224: length(1) + type(1)
        let x224_type = frame[5] >> 4;

        match x224_type {
            0x0E => {
                if frame.get(10).copied() != Some(0x00) {
                    return Vec::new();
                }
                tracing::info!("RDP Connection Request received");
                // Extract cookie/username if present
                if let Some(cookie) = Self::extract_cookie(frame) {
                    tracing::debug!("RDP login cookie: {}", cookie);
                    tracing::warn!("RDP login cookie: {}", REDACTED_LOGIN_FIELD);
                }
                self.build_connection_confirm(frame)
            }
            0x0F => {
                tracing::info!("RDP X.224 data transfer received");
                self.build_mcs_disconnect()
            }
            _ => {
                tracing::info!("RDP X.224 type: 0x{:x}", x224_type);
                Vec::new()
            }
        }
    }

    fn extract_cookie(data: &[u8]) -> Option<String> {
        // Limit search to first 1KB to prevent ReDoS with large payloads.
        // Cookie/username in RDP handshake appears early in the connection.
        let search_limit = data.len().min(1024);
        let search_data = &data[..search_limit];
        let text = std::str::from_utf8(search_data).ok();

        if let Some(text) = text {
            if let Some(start) = text.find("Cookie: mstshash=") {
                let rest = &text[start + 17..];
                let end = rest.find('\r').unwrap_or(rest.len());
                // Limit extracted value to reasonable length
                let value = truncate_utf8(&rest[..end], 256);
                return Some(safe_log_text(value));
            } else if let Some(start) = text.find("Cookie:") {
                let rest = &text[start + 7..];
                let end = rest.find('\r').unwrap_or(rest.len());
                // Limit extracted value to reasonable length
                let value = truncate_utf8(&rest[..end], 256);
                return Some(safe_log_text(value));
            }
        }

        let marker = b"Cookie:";
        let start = search_data
            .windows(marker.len())
            .position(|window| window == marker)?;
        let rest = &search_data[start + marker.len()..];
        let rest = rest.strip_prefix(b" mstshash=").unwrap_or(rest);
        let end = rest
            .iter()
            .position(|&byte| byte == b'\r')
            .unwrap_or(rest.len());
        let value = std::str::from_utf8(&rest[..end]).ok()?;
        let value = truncate_utf8(value, 256);
        Some(safe_log_text(value))
    }

    /// Build X.224 Connection Confirm
    fn build_connection_confirm(&self, req: &[u8]) -> Vec<u8> {
        // The X.224 Connection Request carries the client's SRC-REF at offset
        // 8..10 (TPKT(4) + LI(1) + CR code(1) + DST-REF(2)). Per X.224 §13.4
        // the Connection Confirm echoes it as the DST-REF so the client can
        // match the confirm to its request. `handle` guarantees the frame is
        // at least 11 bytes, but guard defensively regardless.
        let dst_ref = req.get(8..10).unwrap_or(&[0x00, 0x00]);

        let mut resp = Vec::new();
        // TPKT header
        resp.push(0x03); // Version
        resp.push(0x00); // Reserved
        // Length placeholder
        resp.extend_from_slice(&[0x00, 0x00]);
        // X.224 CC
        resp.push(14); // Length indicator
        resp.push(0xD0); // CC type (1101 0000)
        resp.extend_from_slice(dst_ref); // Dst ref (echoes CR src-ref)
        resp.extend_from_slice(&[0x00, 0x00]); // Src ref
        resp.push(0x00); // Class 0
        // RDP Negotiation Response
        resp.push(0x02); // TYPE_RDP_NEG_RSP
        resp.push(0x00); // Flags
        resp.extend_from_slice(&8u16.to_le_bytes()); // Length
        resp.extend_from_slice(&0u32.to_le_bytes()); // Selected protocol: PROTOCOL_RDP
        // Fix TPKT length
        let Ok(len) = u16::try_from(resp.len()) else {
            return Vec::new();
        };
        let len_bytes = len.to_be_bytes();
        resp[2] = len_bytes[0];
        resp[3] = len_bytes[1];
        resp
    }

    fn build_mcs_disconnect(&self) -> Vec<u8> {
        // Send a simple TPKT with X.224 Disconnect Request
        vec![
            0x03, 0x00, 0x00, 0x0B, // TPKT: v3, len=11
            0x06, // X.224 length
            0x80, // DR type
            0x00, 0x00, // Dst ref
            0x00, 0x00, // Src ref
            0x00, // Reason: not specified
        ]
    }
}

fn safe_log_text(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_control() || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}') {
                ' '
            } else {
                ch
            }
        })
        .collect()
}

/// Truncate a string to at most `max_bytes`, snapping down to the nearest
/// UTF-8 char boundary so slicing never panics on valid UTF-8 input.
fn truncate_utf8(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }

    let mut end = max_bytes;
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    &input[..end]
}

impl Default for RdpHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection_request() -> Vec<u8> {
        vec![
            0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    #[test]
    fn connection_request_gets_confirm() {
        let response = RdpHandler::new().handle(&connection_request());

        assert!(!response.is_empty());
        assert_eq!(response[0], 0x03);
    }

    #[test]
    fn confirm_echoes_request_src_ref_as_dst_ref() {
        // X.224 §13.4: the Connection Confirm's DST-REF (resp[6..8]) must echo
        // the Connection Request's SRC-REF (req[8..10]).
        let mut request = connection_request();
        request[8] = 0x12;
        request[9] = 0x34;

        let response = RdpHandler::new().handle(&request);

        assert!(response.len() >= 8);
        assert_eq!(&response[6..8], &[0x12, 0x34]);
    }

    #[test]
    fn rejects_truncated_tpkt_length() {
        let mut request = connection_request();
        request[3] = 0x0c;

        let response = RdpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_invalid_x224_length() {
        let mut request = connection_request();
        request[4] = 0x20;

        let response = RdpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_x224_length_off_by_one_truncation() {
        let mut request = connection_request();
        request[4] = 0x07;

        let response = RdpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_short_x224_length_with_trailing_bytes() {
        let mut request = connection_request();
        request[4] = 0x05;

        let response = RdpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_connection_request_with_nonzero_class() {
        let mut request = connection_request();
        request[10] = 0x01;

        let response = RdpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_trailing_bytes_after_declared_tpkt_length() {
        let mut request = connection_request();
        request.extend_from_slice(b"extra");

        let response = RdpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_non_connection_request_control_frames() {
        let disconnect_request = vec![
            0x03, 0x00, 0x00, 0x0b, 0x06, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let response = RdpHandler::new().handle(&disconnect_request);

        assert!(response.is_empty());
    }

    #[test]
    fn data_transfer_gets_disconnect() {
        let data_transfer = [0x03, 0x00, 0x00, 0x07, 0x02, 0xf0, 0x80];

        let response = RdpHandler::new().handle(&data_transfer);

        assert_eq!(
            response,
            [
                0x03, 0x00, 0x00, 0x0b, 0x06, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn extracted_cookie_is_single_line() {
        let mut request = connection_request();
        request.extend_from_slice(b"Cookie: mstshash=alice\nadmin\x1b\r\n");

        let cookie = RdpHandler::extract_cookie(&request).expect("cookie");

        assert_eq!(cookie, "alice admin ");
        assert!(!cookie.chars().any(char::is_control));
    }

    #[test]
    fn extracted_cookie_rejects_unicode_line_separators_in_logs() {
        let mut request = connection_request();
        request.extend_from_slice("Cookie: mstshash=alice\u{2028}admin\r\n".as_bytes());

        let cookie = RdpHandler::extract_cookie(&request).expect("cookie");

        assert_eq!(cookie, "alice admin");
        assert!(!cookie.contains('\u{2028}'));
    }

    #[test]
    fn extract_cookie_does_not_panic_on_non_ascii_overflow() {
        let mut request = connection_request();
        request.extend_from_slice(b"Cookie: mstshash=");
        request.extend(std::iter::repeat_n(0xFF, 300));

        assert!(RdpHandler::extract_cookie(&request).is_none());
    }

    #[test]
    fn extract_cookie_rejects_invalid_utf8_in_cookie_value() {
        let mut request = connection_request();
        request.extend_from_slice(b"Cookie: mstshash=ali\xffce\r\n");

        assert!(RdpHandler::extract_cookie(&request).is_none());
    }

    #[test]
    fn extracted_cookie_preserves_leading_whitespace() {
        let mut request = connection_request();
        request.extend_from_slice(b"Cookie: mstshash= alice\r\n");

        let cookie = RdpHandler::extract_cookie(&request).expect("cookie");

        assert_eq!(cookie, " alice");
    }
}
