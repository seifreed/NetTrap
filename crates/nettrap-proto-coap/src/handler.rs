pub struct CoapHandler;

impl CoapHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 4 {
            return Vec::new();
        }

        let version = (data[0] >> 6) & 0x03;
        let msg_type = (data[0] >> 4) & 0x03;
        let tkl = (data[0] & 0x0F) as usize;
        let code = data[1];
        let msg_id = u16::from_be_bytes([data[2], data[3]]);
        if version != 1 || tkl > 8 || data.len() < 4 + tkl {
            tracing::debug!(
                "Ignoring invalid CoAP header (version={}, tkl={}, len={})",
                version,
                tkl,
                data.len()
            );
            return Vec::new();
        }

        // Only respond to request methods (codes 0.01-0.31)
        // 0.00 = empty (ping), 0.01 = GET, 0.02 = POST, 0.03 = PUT, 0.04 = DELETE
        let method_class = code >> 5;
        let method_detail = code & 0x1F;
        if method_class != 0 || method_detail == 0 {
            tracing::debug!(
                "Ignoring non-request CoAP code {}.{:02}",
                method_class,
                method_detail
            );
            return Vec::new();
        }

        tracing::info!(
            "CoAP: version={}, type={}, code={}.{:02}, id={}",
            version,
            msg_type,
            method_class,
            method_detail,
            msg_id
        );

        // Extract token from request (TKL is lower 4 bits of first byte)
        let token = &data[4..4 + tkl];

        // Handle different message types
        match msg_type {
            0 => {
                // CON (Confirmable) - must respond with ACK
                self.handle_request(method_detail, msg_id, true, token)
            }
            1 => {
                // NON (Non-confirmable) - respond without ACK
                self.handle_request(method_detail, msg_id, false, token)
            }
            2 => {
                // ACK - no response needed
                Vec::new()
            }
            3 => {
                // RST (Reset) - no response needed
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn handle_request(&self, method: u8, msg_id: u16, confirmable: bool, token: &[u8]) -> Vec<u8> {
        // Only respond to valid request methods
        match method {
            1 => {
                // GET
                self.build_response(msg_id, confirmable, 0x45, token, b"{\"status\":\"ok\"}")
            }
            2 => {
                // POST
                self.build_response(msg_id, confirmable, 0x41, token, b"{\"created\":true}")
            }
            3 => {
                // PUT
                self.build_response(msg_id, confirmable, 0x44, token, b"{\"changed\":true}")
            }
            4 => {
                // DELETE
                self.build_response(msg_id, confirmable, 0x42, token, b"{\"deleted\":true}")
            }
            _ => {
                // Unknown method - respond with 4.00 Bad Request
                self.build_response(
                    msg_id,
                    confirmable,
                    0x80,
                    token,
                    b"{\"error\":\"bad request\"}",
                )
            }
        }
    }

    fn build_response(
        &self,
        msg_id: u16,
        confirmable: bool,
        response_code: u8,
        token: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut resp = Vec::new();

        // Header: Version 1, Type depends on confirmable flag, TKL = token length
        let msg_type = if confirmable { 2u8 } else { 1u8 }; // ACK or NON
        let tkl = (token.len() as u8) & 0x0F;
        resp.push((1 << 6) | (msg_type << 4) | tkl);
        resp.push(response_code);
        resp.extend_from_slice(&msg_id.to_be_bytes());

        // Token (must match request token per RFC 7252)
        resp.extend_from_slice(token);

        // Payload marker and content (RFC 7252: omit marker if no payload)
        if !payload.is_empty() {
            resp.push(0xFF);
            resp.extend_from_slice(payload);
        }

        resp
    }
}

impl Default for CoapHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_get_request_gets_content_response() {
        let request = [0x41, 0x01, 0x12, 0x34, 0xAA];

        let response = CoapHandler::new().handle(&request);

        assert!(!response.is_empty());
        assert_eq!(response[0] >> 6, 1);
        assert_eq!((response[0] >> 4) & 0x03, 2);
        assert_eq!(response[1], 0x45);
        assert_eq!(&response[2..4], &[0x12, 0x34]);
        assert_eq!(response[4], 0xAA);
    }

    #[test]
    fn response_code_is_not_treated_as_request() {
        let response_packet = [0x60, 0x41, 0x12, 0x34];

        assert!(CoapHandler::new().handle(&response_packet).is_empty());
    }

    #[test]
    fn malformed_header_is_not_answered() {
        let invalid_version = [0x01, 0x01, 0x12, 0x34];
        let invalid_token_len = [0x49, 0x01, 0x12, 0x34];

        assert!(CoapHandler::new().handle(&invalid_version).is_empty());
        assert!(CoapHandler::new().handle(&invalid_token_len).is_empty());
    }
}
