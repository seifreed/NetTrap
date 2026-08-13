mod parsing;
use parsing::*;

const MAX_LDAP_MATCHED_DN_BYTES: usize = 4096;
const REDACTED_LDAP_FIELD: &str = "***REDACTED***";

pub struct LdapHandler {
    base_dn: String,
}

impl LdapHandler {
    pub fn new() -> Self {
        Self {
            base_dn: "dc=nettrap,dc=local".to_string(),
        }
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        // LDAP uses BER/DER encoding (ASN.1)
        // Minimal parsing: extract message ID and operation
        if data.len() < 7 {
            return Vec::new();
        }

        if data[0] != 0x30 {
            return Vec::new();
        }

        let Some((msg_id, op_offset, seq_end)) = parse_message_id(data) else {
            return Vec::new();
        };
        if seq_end != data.len() {
            return Vec::new();
        }
        if op_offset >= seq_end {
            return Vec::new();
        }
        let Some(op_end) = operation_end(data, op_offset, seq_end) else {
            return Vec::new();
        };
        if !message_tail_is_valid(data, op_end, seq_end) {
            return Vec::new();
        }

        let op_byte = data[op_offset];
        let op_tag = op_byte & 0x1F; // Application tag number
        let op_class = (data[op_offset] >> 6) & 0x03; // Class (should be Application = 1)

        tracing::info!(
            "LDAP message_id={}, op_tag={}, class={}",
            msg_id,
            op_tag,
            op_class
        );

        match op_byte {
            0x60 => {
                // BindRequest (tag 0, Application class)
                if !bind_request_is_well_formed(data, op_offset, op_end) {
                    return Vec::new();
                }
                tracing::warn!("LDAP BIND request");
                if let Some(dn) = extract_bind_dn(data, op_offset, op_end) {
                    tracing::debug!("LDAP BIND DN: {}", dn);
                    tracing::warn!("LDAP BIND DN: {}", REDACTED_LDAP_FIELD);
                }
                self.build_bind_response(msg_id)
            }
            0x63 => {
                if !search_request_is_well_formed(data, op_offset, op_end) {
                    return Vec::new();
                }
                tracing::warn!("LDAP SEARCH request - potential recon/Log4Shell");
                self.build_search_result_done(msg_id)
            }
            0x42 => {
                Vec::new() // No response needed
            }
            _ => {
                tracing::info!("LDAP unsupported operation byte=0x{:02x}", op_byte);
                Vec::new()
            }
        }
    }

    fn build_bind_response(&self, msg_id: u32) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&[0x0A, 0x01, 0x00]); // ENUM, len=1, value=0 (success)
        result.extend_from_slice(&[0x04, 0x00]);
        result.extend_from_slice(&[0x04, 0x00]);

        // Wrap in Application[1] (BindResponse)
        let mut bind_resp = vec![0x61]; // Application[1] constructed
        if !encode_ber_length(&mut bind_resp, result.len()) {
            return Vec::new();
        }
        bind_resp.extend_from_slice(&result);

        self.wrap_ldap_message(msg_id, &bind_resp)
    }

    fn build_search_result_done(&self, msg_id: u32) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&[0x0A, 0x01, 0x00]); // success
        let matched_dn = self.base_dn.as_bytes();
        if matched_dn.len() > MAX_LDAP_MATCHED_DN_BYTES {
            tracing::warn!(
                matched_dn_len = matched_dn.len(),
                max = MAX_LDAP_MATCHED_DN_BYTES,
                "LDAP matched DN exceeds response limit"
            );
            return Vec::new();
        }
        result.push(0x04); // matched DN
        if !encode_ber_length(&mut result, matched_dn.len()) {
            return Vec::new();
        }
        result.extend_from_slice(matched_dn);
        result.extend_from_slice(&[0x04, 0x00]); // diagnostic

        let mut search_done = vec![0x65]; // Application[5] SearchResultDone
        if !encode_ber_length(&mut search_done, result.len()) {
            return Vec::new();
        }
        search_done.extend_from_slice(&result);

        let packet = self.wrap_ldap_message(msg_id, &search_done);
        if packet.len() > MAX_LDAP_MATCHED_DN_BYTES {
            tracing::warn!(
                packet_len = packet.len(),
                max = MAX_LDAP_MATCHED_DN_BYTES,
                "LDAP search result exceeds response limit"
            );
            return Vec::new();
        }

        packet
    }

    fn wrap_ldap_message(&self, msg_id: u32, op_data: &[u8]) -> Vec<u8> {
        let mut msg_id_bytes = vec![0x02]; // INTEGER tag
        let msg_id_be = msg_id.to_be_bytes();
        if msg_id <= 0x7F {
            msg_id_bytes.push(1);
            msg_id_bytes.push(msg_id_be[3]);
        } else if msg_id <= 0xFF {
            msg_id_bytes.push(2);
            msg_id_bytes.push(0x00);
            msg_id_bytes.push(msg_id_be[3]);
        } else if msg_id <= 0x7FFF {
            msg_id_bytes.push(2);
            msg_id_bytes.extend_from_slice(&msg_id_be[2..]);
        } else if msg_id <= 0xFFFF {
            // High bit set in 2-byte form — need leading zero to stay positive
            msg_id_bytes.push(3);
            msg_id_bytes.push(0x00);
            msg_id_bytes.extend_from_slice(&msg_id_be[2..]);
        } else if msg_id <= 0x7FFFFF {
            msg_id_bytes.push(3);
            msg_id_bytes.extend_from_slice(&msg_id_be[1..]);
        } else if msg_id <= 0xFFFFFF {
            msg_id_bytes.push(4);
            msg_id_bytes.push(0x00);
            msg_id_bytes.extend_from_slice(&msg_id_be[1..]);
        } else if msg_id <= 0x7FFFFFFF {
            msg_id_bytes.push(4);
            msg_id_bytes.extend_from_slice(&msg_id_be);
        } else {
            msg_id_bytes.push(5);
            msg_id_bytes.push(0x00);
            msg_id_bytes.extend_from_slice(&msg_id_be);
        }

        let inner_len = msg_id_bytes.len() + op_data.len();
        let mut packet = vec![0x30]; // SEQUENCE
        if !encode_ber_length(&mut packet, inner_len) {
            return Vec::new();
        }
        packet.extend_from_slice(&msg_id_bytes);
        packet.extend_from_slice(op_data);
        packet
    }
}

impl Default for LdapHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG_FIELD_PREVIEW_CHARS: usize = 240;

    fn bind_request_with_dn(dn: &[u8]) -> Vec<u8> {
        let mut bind = vec![0x02, 0x01, 0x03, 0x04, dn.len() as u8];
        bind.extend_from_slice(dn);
        bind.extend_from_slice(&[0x80, 0x00]);

        let mut operation = vec![0x60, bind.len() as u8];
        operation.extend_from_slice(&bind);

        let mut request = vec![0x30, (3 + operation.len()) as u8, 0x02, 0x01, 0x01];
        request.extend_from_slice(&operation);
        request
    }

    fn sasl_bind_request(sasl: &[u8]) -> Vec<u8> {
        let mut bind = vec![0x02, 0x01, 0x03, 0x04, 0x00];
        bind.extend_from_slice(&tlv(0xa3, sasl));

        let mut operation = tlv(0x60, &bind);
        let mut request = vec![0x30, (3 + operation.len()) as u8, 0x02, 0x01, 0x01];
        request.append(&mut operation);
        request
    }

    fn search_request() -> Vec<u8> {
        let mut search = Vec::new();
        search.extend_from_slice(&[0x04, 0x00]); // baseObject
        search.extend_from_slice(&[0x0a, 0x01, 0x00]); // scope: baseObject
        search.extend_from_slice(&[0x0a, 0x01, 0x00]); // derefAliases: neverDerefAliases
        search.extend_from_slice(&[0x02, 0x01, 0x00]); // sizeLimit
        search.extend_from_slice(&[0x02, 0x01, 0x00]); // timeLimit
        search.extend_from_slice(&[0x01, 0x01, 0x00]); // typesOnly: false
        search.extend_from_slice(&[0x87, 0x0b]); // present filter
        search.extend_from_slice(b"objectClass");
        search.extend_from_slice(&[0x30, 0x00]); // attributes

        let mut operation = vec![0x63, search.len() as u8];
        operation.extend_from_slice(&search);

        let mut request = vec![0x30, (3 + operation.len()) as u8, 0x02, 0x01, 0x01];
        request.extend_from_slice(&operation);
        request
    }

    fn replace_nth_tlv(
        request: &mut Vec<u8>,
        expected: &[u8],
        occurrence: usize,
        replacement: &[u8],
    ) {
        let Some(position) = request
            .windows(expected.len())
            .enumerate()
            .filter_map(|(index, window)| (window == expected).then_some(index))
            .nth(occurrence)
        else {
            panic!("TLV occurrence {occurrence} not found");
        };
        request.splice(
            position..position + expected.len(),
            replacement.iter().copied(),
        );

        request[1] = adjusted_len(request[1], expected.len(), replacement.len());
        request[6] = adjusted_len(request[6], expected.len(), replacement.len());
    }

    fn adjusted_len(current: u8, old_len: usize, new_len: usize) -> u8 {
        let adjusted = usize::from(current) + new_len - old_len;
        adjusted.try_into().expect("test packet length fits in u8")
    }

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        assert!(encode_ber_length(&mut encoded, value.len()));
        encoded.extend_from_slice(value);
        encoded
    }

    #[test]
    fn bind_request_application_tag_gets_response() {
        let request = bind_request_with_dn(b"cn=admin,dc=nettrap,dc=local");

        let response = LdapHandler::new().handle(&request);

        assert!(!response.is_empty());
        assert_eq!(response[0], 0x30);
    }

    #[test]
    fn bind_request_rejects_empty_operation_body() {
        let request = [0x30, 0x05, 0x02, 0x01, 0x01, 0x60, 0x00];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn bind_request_rejects_missing_authentication_choice() {
        let request = [
            0x30, 0x0a, 0x02, 0x01, 0x01, 0x60, 0x05, 0x02, 0x01, 0x03, 0x04, 0x00,
        ];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn bind_request_rejects_empty_sasl_auth_choice() {
        let handler = LdapHandler::new();
        let mut request = bind_request_with_dn(b"");
        replace_nth_tlv(&mut request, &[0x80, 0x00], 0, &[0xa3, 0x00]);

        let response = handler.handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn bind_request_accepts_well_formed_sasl_auth_choice() {
        let handler = LdapHandler::new();
        let mut sasl = tlv(0x04, b"PLAIN");
        sasl.extend_from_slice(&tlv(0x04, b"\0user\0pass"));

        let response = handler.handle(&sasl_bind_request(&sasl));

        assert!(!response.is_empty());
    }

    #[test]
    fn bind_request_rejects_malformed_sasl_auth_choice() {
        let handler = LdapHandler::new();

        let response = handler.handle(&sasl_bind_request(b"PLAIN"));

        assert!(response.is_empty());
    }

    #[test]
    fn bind_request_rejects_non_minimal_version_integer() {
        let request = [
            0x30, 0x0d, 0x02, 0x01, 0x01, 0x60, 0x08, 0x02, 0x02, 0x00, 0x03, 0x04, 0x00, 0x80,
            0x00,
        ];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn universal_tag_with_bind_low_bits_is_rejected() {
        let request = [0x30, 0x05, 0x02, 0x01, 0x01, 0x20, 0x00];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn context_tag_with_search_low_bits_is_rejected() {
        let request = [0x30, 0x05, 0x02, 0x01, 0x01, 0xa3, 0x00];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn search_request_rejects_empty_operation_body() {
        let request = [0x30, 0x05, 0x02, 0x01, 0x01, 0x63, 0x00];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn declared_sequence_length_above_limit_is_rejected() {
        let request = [
            0x30, 0x84, 0x01, 0x00, 0x00, 0x01, 0x02, 0x01, 0x01, 0x60, 0x00,
        ];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn zero_length_message_id_is_rejected() {
        let request = [0x30, 0x05, 0x02, 0x00, 0x60, 0x01, 0x00];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn oversize_message_id_is_rejected() {
        let request = [
            0x30, 0x09, 0x02, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x60, 0x00,
        ];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn negative_message_id_is_rejected() {
        let request = [0x30, 0x05, 0x02, 0x01, 0x80, 0x60, 0x00];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn non_minimal_positive_message_id_is_rejected() {
        let request = [0x30, 0x06, 0x02, 0x02, 0x00, 0x7f, 0x60, 0x00];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn message_id_above_max_int_is_rejected() {
        let request = [0x30, 0x08, 0x02, 0x04, 0x80, 0x00, 0x00, 0x00, 0x60, 0x00];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn operation_outside_declared_sequence_is_rejected() {
        let request = [0x30, 0x03, 0x02, 0x01, 0x01, 0x60, 0x00];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn operation_length_must_fit_declared_sequence() {
        let request = [0x30, 0x05, 0x02, 0x01, 0x01, 0x60, 0x02];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn trailing_bytes_after_operation_must_be_controls() {
        let request = [0x30, 0x06, 0x02, 0x01, 0x01, 0x60, 0x00, 0x00];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn trailing_bytes_after_declared_sequence_are_rejected() {
        let request = [0x30, 0x05, 0x02, 0x01, 0x01, 0x60, 0x00, 0x30, 0x00];

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn optional_controls_tail_is_allowed_when_well_formed() {
        let mut request = bind_request_with_dn(b"");
        request[1] += 2;
        request.extend_from_slice(&[0xa0, 0x00]);

        let response = LdapHandler::new().handle(&request);

        assert!(!response.is_empty());
    }

    #[test]
    fn optional_controls_tail_accepts_well_formed_control_sequence() {
        let mut request = bind_request_with_dn(b"");
        let controls = [
            0xa0, 0x09, 0x30, 0x07, 0x04, 0x05, b'1', b'.', b'2', b'.', b'3',
        ];
        request[1] += controls.len() as u8;
        request.extend_from_slice(&controls);

        let response = LdapHandler::new().handle(&request);

        assert!(!response.is_empty());
    }

    #[test]
    fn optional_controls_tail_rejects_malformed_control_payload() {
        let mut request = bind_request_with_dn(b"");
        request[1] += 3;
        request.extend_from_slice(&[0xa0, 0x01, 0x00]);

        let response = LdapHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn extracted_bind_dn_is_single_line() {
        let request = bind_request_with_dn(b"cn=evil\r\nadmin\x1b");
        let (_, op_offset, seq_end) = parse_message_id(&request).expect("message id");
        let op_end = operation_end(&request, op_offset, seq_end).expect("operation");

        let dn = extract_bind_dn(&request, op_offset, op_end).expect("bind dn");

        assert_eq!(dn, "cn=evil  admin ");
        assert!(!dn.chars().any(char::is_control));

        let long = vec![b'a'; LOG_FIELD_PREVIEW_CHARS + 1];
        assert_eq!(
            nettrap_core::sanitize::single_line_bytes(&long).len(),
            LOG_FIELD_PREVIEW_CHARS
        );
    }

    #[test]
    fn search_result_done_accepts_approx_match_filter() {
        let handler = LdapHandler::new();
        let mut request = search_request();
        let Some(filter_tag) = request.iter_mut().find(|byte| **byte == 0x87) else {
            panic!("present filter tag not found");
        };
        *filter_tag = 0xa8;
        replace_nth_tlv(
            &mut request,
            &[
                0xa8, 0x0b, b'o', b'b', b'j', b'e', b'c', b't', b'C', b'l', b'a', b's', b's',
            ],
            0,
            &[
                0xa8, 0x14, 0x30, 0x12, 0x04, 0x0b, b'o', b'b', b'j', b'e', b'c', b't', b'C', b'l',
                b'a', b's', b's', 0x04, 0x03, b't', b'o', b'p',
            ],
        );

        let response = handler.handle(&request);

        assert!(!response.is_empty());
    }

    #[test]
    fn search_request_rejects_malformed_approx_match_filter() {
        let handler = LdapHandler::new();
        let mut request = search_request();
        replace_nth_tlv(
            &mut request,
            &[
                0x87, 0x0b, b'o', b'b', b'j', b'e', b'c', b't', b'C', b'l', b'a', b's', b's',
            ],
            0,
            &[
                0xa8, 0x0b, b'o', b'b', b'j', b'e', b'c', b't', b'C', b'l', b'a', b's', b's',
            ],
        );

        let response = handler.handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn search_request_rejects_malformed_equality_filter() {
        let handler = LdapHandler::new();
        let mut request = search_request();
        replace_nth_tlv(
            &mut request,
            &[
                0x87, 0x0b, b'o', b'b', b'j', b'e', b'c', b't', b'C', b'l', b'a', b's', b's',
            ],
            0,
            &[
                0xa3, 0x0b, b'o', b'b', b'j', b'e', b'c', b't', b'C', b'l', b'a', b's', b's',
            ],
        );

        let response = handler.handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn search_request_rejects_malformed_substring_filter() {
        let handler = LdapHandler::new();
        let mut request = search_request();
        replace_nth_tlv(
            &mut request,
            &[
                0x87, 0x0b, b'o', b'b', b'j', b'e', b'c', b't', b'C', b'l', b'a', b's', b's',
            ],
            0,
            &[
                0xa4, 0x0b, b'o', b'b', b'j', b'e', b'c', b't', b'C', b'l', b'a', b's', b's',
            ],
        );

        let response = handler.handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn search_request_rejects_empty_present_filter() {
        let handler = LdapHandler::new();
        let mut request = search_request();
        replace_nth_tlv(
            &mut request,
            &[
                0x87, 0x0b, b'o', b'b', b'j', b'e', b'c', b't', b'C', b'l', b'a', b's', b's',
            ],
            0,
            &[0x87, 0x00],
        );

        let response = handler.handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn search_request_rejects_empty_and_filter() {
        let handler = LdapHandler::new();
        let mut request = search_request();
        replace_nth_tlv(
            &mut request,
            &[
                0x87, 0x0b, b'o', b'b', b'j', b'e', b'c', b't', b'C', b'l', b'a', b's', b's',
            ],
            0,
            &[0xa0, 0x00],
        );

        let response = handler.handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn search_request_rejects_empty_nested_filter() {
        let handler = LdapHandler::new();
        let mut request = search_request();
        replace_nth_tlv(
            &mut request,
            &[
                0x87, 0x0b, b'o', b'b', b'j', b'e', b'c', b't', b'C', b'l', b'a', b's', b's',
            ],
            0,
            &[0xa2, 0x02, 0x87, 0x00],
        );

        let response = handler.handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn search_request_rejects_overly_deep_nested_filter() {
        let handler = LdapHandler::new();
        let mut request = search_request();
        let mut filter = vec![0x87, 0x01, b'a'];
        for _ in 0..=MAX_LDAP_FILTER_DEPTH {
            filter = tlv(0xa2, &filter);
        }
        replace_nth_tlv(
            &mut request,
            &[
                0x87, 0x0b, b'o', b'b', b'j', b'e', b'c', b't', b'C', b'l', b'a', b's', b's',
            ],
            0,
            &filter,
        );

        let response = handler.handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn search_request_rejects_invalid_enumerated_values() {
        let handler = LdapHandler::new();

        let mut invalid_scope = search_request();
        replace_nth_tlv(
            &mut invalid_scope,
            &[0x0a, 0x01, 0x00],
            0,
            &[0x0a, 0x01, 0x03],
        );
        assert!(handler.handle(&invalid_scope).is_empty());

        let mut invalid_deref = search_request();
        replace_nth_tlv(
            &mut invalid_deref,
            &[0x0a, 0x01, 0x00],
            1,
            &[0x0a, 0x01, 0x04],
        );
        assert!(handler.handle(&invalid_deref).is_empty());
    }

    #[test]
    fn search_request_rejects_malformed_limits_and_boolean() {
        let handler = LdapHandler::new();

        let mut non_minimal_size_limit = search_request();
        replace_nth_tlv(
            &mut non_minimal_size_limit,
            &[0x02, 0x01, 0x00],
            0,
            &[0x02, 0x02, 0x00, 0x00],
        );
        assert!(handler.handle(&non_minimal_size_limit).is_empty());

        let mut malformed_types_only = search_request();
        replace_nth_tlv(
            &mut malformed_types_only,
            &[0x01, 0x01, 0x00],
            0,
            &[0x01, 0x00, 0x87],
        );
        assert!(handler.handle(&malformed_types_only).is_empty());

        let mut invalid_boolean_length = search_request();
        replace_nth_tlv(
            &mut invalid_boolean_length,
            &[0x01, 0x01, 0x00],
            0,
            &[0x01, 0x02, 0x00, 0x01],
        );
        assert!(handler.handle(&invalid_boolean_length).is_empty());
    }

    #[test]
    fn search_request_accepts_boolean_true_encoded_as_one() {
        let handler = LdapHandler::new();
        let mut request = search_request();
        replace_nth_tlv(&mut request, &[0x01, 0x01, 0x00], 0, &[0x01, 0x01, 0x01]);

        let response = handler.handle(&request);

        assert!(!response.is_empty());
    }
}
