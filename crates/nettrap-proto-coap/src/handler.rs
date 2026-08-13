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

        if code == 0 {
            return self.handle_empty_message(msg_type, msg_id, tkl, data.len());
        }

        let method_class = code >> 5;
        let method_detail = code & 0x1F;
        if method_class != 0 {
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
        if !Self::options_are_well_formed(&data[4 + tkl..]) {
            tracing::debug!("Ignoring malformed CoAP options");
            return Vec::new();
        }

        match msg_type {
            0 => self.handle_request(method_detail, msg_id, true, token),
            1 => self.handle_request(method_detail, msg_id, false, token),
            2 => Vec::new(),
            3 => Vec::new(),
            _ => Vec::new(),
        }
    }

    fn handle_request(&self, method: u8, msg_id: u16, confirmable: bool, token: &[u8]) -> Vec<u8> {
        match method {
            1 => self.build_response(msg_id, confirmable, 0x45, token, b"{\"status\":\"ok\"}"),
            2 => self.build_response(msg_id, confirmable, 0x41, token, b"{\"created\":true}"),
            3 => self.build_response(msg_id, confirmable, 0x44, token, b"{\"changed\":true}"),
            4 => self.build_response(msg_id, confirmable, 0x42, token, b"{\"deleted\":true}"),
            _ => self.build_response(
                msg_id,
                confirmable,
                0x85,
                token,
                b"{\"error\":\"method not allowed\"}",
            ),
        }
    }

    fn handle_empty_message(
        &self,
        msg_type: u8,
        msg_id: u16,
        token_len: usize,
        data_len: usize,
    ) -> Vec<u8> {
        if token_len != 0 || data_len != 4 {
            return Vec::new();
        }

        if msg_type == 0 {
            let msg_id_bytes = msg_id.to_be_bytes();
            return vec![(1 << 6) | (2 << 4), 0x00, msg_id_bytes[0], msg_id_bytes[1]];
        }

        Vec::new()
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
        if token.len() > 8 {
            return Vec::new();
        }
        let Ok(tkl) = u8::try_from(token.len()) else {
            return Vec::new();
        };
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

    fn options_are_well_formed(data: &[u8]) -> bool {
        let mut pos = 0usize;
        while pos < data.len() {
            let header = data[pos];
            pos += 1;
            if header == 0xff {
                return pos < data.len();
            }

            let delta = header >> 4;
            let option_len = header & 0x0f;
            if Self::read_option_component(delta, data, &mut pos).is_none() {
                return false;
            }
            let Some(option_len) = Self::read_option_component(option_len, data, &mut pos) else {
                return false;
            };
            let Some(next_pos) = pos.checked_add(option_len) else {
                return false;
            };
            if next_pos > data.len() {
                return false;
            }
            pos = next_pos;
        }
        true
    }

    fn read_option_component(nibble: u8, data: &[u8], pos: &mut usize) -> Option<usize> {
        match nibble {
            0..=12 => Some(nibble as usize),
            13 => {
                let value = *data.get(*pos)? as usize;
                *pos += 1;
                Some(13 + value)
            }
            14 => {
                let bytes = data.get(*pos..(*pos).checked_add(2)?)?;
                *pos += 2;
                Some(269 + u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
            }
            _ => None,
        }
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
    fn confirmable_empty_message_gets_ack() {
        let request = [0x40, 0x00, 0x12, 0x34];

        let response = CoapHandler::new().handle(&request);

        assert_eq!(response, [0x60, 0x00, 0x12, 0x34]);
    }

    #[test]
    fn malformed_empty_messages_are_not_answered() {
        let empty_with_token = [0x41, 0x00, 0x12, 0x34, 0xaa];
        let empty_with_payload_marker = [0x40, 0x00, 0x12, 0x34, 0xff, b'x'];

        assert!(CoapHandler::new().handle(&empty_with_token).is_empty());
        assert!(
            CoapHandler::new()
                .handle(&empty_with_payload_marker)
                .is_empty()
        );
    }

    #[test]
    fn valid_options_are_answered() {
        let request = [0x40, 0x01, 0x12, 0x34, 0xb1, b'x'];

        assert!(!CoapHandler::new().handle(&request).is_empty());
    }

    #[test]
    fn malformed_header_is_not_answered() {
        let invalid_version = [0x01, 0x01, 0x12, 0x34];
        let invalid_token_len = [0x49, 0x01, 0x12, 0x34];

        assert!(CoapHandler::new().handle(&invalid_version).is_empty());
        assert!(CoapHandler::new().handle(&invalid_token_len).is_empty());
    }

    #[test]
    fn malformed_options_are_not_answered() {
        let reserved_option_delta = [0x40, 0x01, 0x12, 0x34, 0xf0];
        let truncated_extended_length = [0x40, 0x01, 0x12, 0x34, 0x0d];

        assert!(CoapHandler::new().handle(&reserved_option_delta).is_empty());
        assert!(
            CoapHandler::new()
                .handle(&truncated_extended_length)
                .is_empty()
        );
    }

    #[test]
    fn unsupported_request_methods_get_method_not_allowed() {
        let request = [0x40, 0x05, 0x12, 0x34];

        let response = CoapHandler::new().handle(&request);

        assert_eq!(response.get(1), Some(&0x85));
    }

    #[test]
    fn payload_marker_requires_payload() {
        let empty_payload_marker = [0x40, 0x01, 0x12, 0x34, 0xff];

        assert!(CoapHandler::new().handle(&empty_payload_marker).is_empty());
    }
}
