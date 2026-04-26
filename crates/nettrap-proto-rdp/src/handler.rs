pub struct RdpHandler {
    // X.224 Connection Confirm + RDP Negotiation Response
}

impl RdpHandler {
    pub fn new() -> Self {
        Self {}
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 11 {
            return Vec::new();
        }

        // TPKT header: version(1) + reserved(1) + length(2)
        if data[0] != 0x03 || data[1] != 0x00 {
            // Not TPKT
            return Vec::new();
        }
        let tpkt_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if tpkt_len < 7 || tpkt_len > data.len() {
            return Vec::new();
        }
        let frame = &data[..tpkt_len];
        let x224_len = frame[4] as usize;
        if x224_len < 2 || 4 + x224_len > frame.len() {
            return Vec::new();
        }

        // X.224: length(1) + type(1)
        let x224_type = frame[5] >> 4;

        match x224_type {
            0x0E => {
                // Connection Request (CR)
                tracing::info!("RDP Connection Request received");
                // Extract cookie/username if present
                if let Some(cookie) = Self::extract_cookie(frame) {
                    tracing::warn!("RDP login cookie: {}", cookie);
                }
                self.build_connection_confirm(frame)
            }
            _ => {
                tracing::info!("RDP X.224 type: 0x{:x}", x224_type);
                // After CC, client sends MCS Connect Initial
                // Log it but respond with error to capture credentials
                self.build_mcs_disconnect()
            }
        }
    }

    fn extract_cookie(data: &[u8]) -> Option<String> {
        // Limit search to first 1KB to prevent ReDoS with large payloads.
        // Cookie/username in RDP handshake appears early in the connection.
        let search_limit = data.len().min(1024);
        let search_data = &data[..search_limit];
        let text = String::from_utf8_lossy(search_data);

        if let Some(start) = text.find("Cookie: mstshash=") {
            let rest = &text[start + 17..];
            let end = rest.find('\r').unwrap_or(rest.len());
            // Limit extracted value to reasonable length
            let value = &rest[..end.min(256)];
            Some(value.to_string())
        } else if let Some(start) = text.find("Cookie:") {
            let rest = &text[start + 7..];
            let end = rest.find('\r').unwrap_or(rest.len());
            // Limit extracted value to reasonable length
            let value = &rest[..end.min(256)];
            Some(value.trim().to_string())
        } else {
            None
        }
    }

    /// Build X.224 Connection Confirm
    fn build_connection_confirm(&self, _req: &[u8]) -> Vec<u8> {
        let mut resp = Vec::new();
        // TPKT header
        resp.push(0x03); // Version
        resp.push(0x00); // Reserved
        // Length placeholder
        resp.extend_from_slice(&[0x00, 0x00]);
        // X.224 CC
        resp.push(14); // Length indicator
        resp.push(0xD0); // CC type (1101 0000)
        resp.extend_from_slice(&[0x00, 0x00]); // Dst ref
        resp.extend_from_slice(&[0x00, 0x00]); // Src ref
        resp.push(0x00); // Class 0
        // RDP Negotiation Response
        resp.push(0x02); // TYPE_RDP_NEG_RSP
        resp.push(0x00); // Flags
        resp.extend_from_slice(&8u16.to_le_bytes()); // Length
        resp.extend_from_slice(&0u32.to_le_bytes()); // Selected protocol: PROTOCOL_RDP
        // Fix TPKT length
        let len = resp.len() as u16;
        resp[2] = (len >> 8) as u8;
        resp[3] = (len & 0xFF) as u8;
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
}
