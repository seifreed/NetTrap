pub struct SnmpHandler;

const MAX_SNMP_COMMUNITY_BYTES: usize = 1024;
const REDACTED_SNMP_COMMUNITY_FIELD: &str = "***REDACTED***";

impl SnmpHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        // SNMP uses BER encoding. Parse community string and PDU type.
        if data.len() < 10 || data[0] != 0x30 {
            return Vec::new();
        }

        if let Some((community, pdu_type, request_id, version)) = Self::parse_snmp(data) {
            tracing::debug!(
                "SNMP request: community='{}', pdu_type={}",
                nettrap_core::sanitize::single_line_bytes(&community),
                pdu_type
            );
            tracing::warn!(
                "SNMP request: community='{}', pdu_type={}",
                REDACTED_SNMP_COMMUNITY_FIELD,
                pdu_type
            );

            match pdu_type {
                0 => self.build_get_response(&community, request_id, version),
                1 => self.build_get_response(&community, request_id, version),
                5 => self.build_get_response(&community, request_id, version),
                3 => {
                    tracing::debug!(
                        "SNMP SET attempt with community='{}'",
                        nettrap_core::sanitize::single_line_bytes(&community)
                    );
                    tracing::warn!(
                        "SNMP SET attempt with community='{}'",
                        REDACTED_SNMP_COMMUNITY_FIELD
                    );
                    self.build_get_response(&community, request_id, version)
                }
                _ => Vec::new(),
            }
        } else {
            Vec::new()
        }
    }

    fn parse_snmp(data: &[u8]) -> Option<(Vec<u8>, u8, Vec<u8>, u8)> {
        let mut pos = 0;

        let message = Self::read_tlv(data, &mut pos, data.len(), 0x30)?;
        if pos != data.len() {
            return None;
        }

        let mut msg_pos = 0;
        let version = Self::read_tlv(message, &mut msg_pos, message.len(), 0x02)?;
        if !Self::is_supported_version(version) {
            return None;
        }
        // `is_supported_version` only accepts the single-byte values `[0]` (v1)
        // or `[1]` (v2c), so the response can echo the request version verbatim.
        let version_byte = version[0];

        let community = Self::read_tlv(message, &mut msg_pos, message.len(), 0x04)?;
        if community.len() > MAX_SNMP_COMMUNITY_BYTES {
            return None;
        }
        let community = community.to_vec();

        let pdu_tag = *message.get(msg_pos)?;
        if !matches!(pdu_tag, 0xA0 | 0xA1 | 0xA3 | 0xA5) {
            return None;
        }
        let pdu_type = pdu_tag & 0x1F;
        if pdu_type == 0x05 && version_byte == 0x00 {
            return None;
        }
        msg_pos += 1;
        let (pdu_len, lb) = Self::parse_len(&message[msg_pos..]);
        if lb == 0 {
            return None;
        }
        msg_pos += lb;
        let pdu_end = msg_pos.checked_add(pdu_len)?;
        if pdu_end > message.len() {
            return None;
        }
        let pdu = &message[msg_pos..pdu_end];
        msg_pos = pdu_end;
        if msg_pos != message.len() {
            return None;
        }

        let mut pdu_pos = 0;
        let request_id = Self::read_tlv(pdu, &mut pdu_pos, pdu.len(), 0x02)?;
        if !Self::is_canonical_integer(request_id) {
            return None;
        }

        let error_status = Self::read_tlv(pdu, &mut pdu_pos, pdu.len(), 0x02)?;
        let error_index = Self::read_tlv(pdu, &mut pdu_pos, pdu.len(), 0x02)?;
        if pdu_type != 0x05
            && (!Self::is_zero_integer(error_status) || !Self::is_zero_integer(error_index))
        {
            return None;
        }
        if pdu_type == 0x05
            && (!Self::is_nonnegative_canonical_integer(error_status)
                || !Self::is_nonnegative_canonical_integer(error_index))
        {
            return None;
        }

        let _varbind_list = Self::read_tlv(pdu, &mut pdu_pos, pdu.len(), 0x30)?;
        if pdu_pos != pdu.len() {
            return None;
        }

        Some((community, pdu_type, request_id.to_vec(), version_byte))
    }

    fn read_tlv<'a>(
        data: &'a [u8],
        pos: &mut usize,
        limit: usize,
        expected_tag: u8,
    ) -> Option<&'a [u8]> {
        if limit > data.len() || *pos >= limit || data[*pos] != expected_tag {
            return None;
        }
        *pos += 1;
        let (len, lb) = Self::parse_len(&data[*pos..limit]);
        if lb == 0 {
            return None;
        }
        *pos += lb;
        let end = (*pos).checked_add(len)?;
        if end > limit {
            return None;
        }
        let value = &data[*pos..end];
        *pos = end;
        Some(value)
    }

    fn parse_len(data: &[u8]) -> (usize, usize) {
        if data.is_empty() {
            return (0, 0);
        }
        if data[0] & 0x80 == 0 {
            // Short form: length is in the lower 7 bits
            (data[0] as usize, 1)
        } else {
            // Long form: lower 7 bits indicate number of length bytes to follow
            let n = (data[0] & 0x7F) as usize;
            // SNMP uses max 4 bytes for length (32-bit), reject excessive claims
            // Also verify we have enough bytes for the claimed length encoding
            if n == 0 || n > 4 || n + 1 > data.len() {
                return (0, 0);
            }
            if data[1] == 0 {
                return (0, 0);
            }
            let mut l = 0usize;
            for i in 0..n {
                l = (l << 8) | data[i + 1] as usize;
            }
            if l < 128 {
                return (0, 0);
            }
            // Return (length_value, bytes_consumed)
            (l, 1 + n)
        }
    }

    fn is_supported_version(version: &[u8]) -> bool {
        matches!(version, [0] | [1])
    }

    fn is_canonical_integer(value: &[u8]) -> bool {
        if value.is_empty() || value.len() > 4 {
            return false;
        }
        if value.len() == 1 {
            return value[0] & 0x80 == 0;
        }
        if value[0] == 0x00 && value[1] & 0x80 == 0 {
            return false;
        }
        if value[0] == 0xff && value[1] & 0x80 != 0 {
            return false;
        }
        true
    }

    fn is_zero_integer(value: &[u8]) -> bool {
        Self::is_canonical_integer(value) && value.iter().all(|byte| *byte == 0)
    }

    fn is_nonnegative_canonical_integer(value: &[u8]) -> bool {
        Self::is_canonical_integer(value) && value.first().is_some_and(|byte| byte & 0x80 == 0)
    }

    /// Encode BER length in short or long form
    fn ber_encode_length(len: usize) -> Vec<u8> {
        if len < 128 {
            let bytes = len.to_be_bytes();
            vec![bytes[bytes.len() - 1]]
        } else {
            let bytes = len.to_be_bytes();
            let first_nonzero = bytes
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(bytes.len() - 1);
            let payload = &bytes[first_nonzero..];
            let mut encoded = Vec::with_capacity(payload.len() + 1);
            let payload_len_bytes = payload.len().to_be_bytes();
            encoded.push(0x80 | payload_len_bytes[payload_len_bytes.len() - 1]);
            encoded.extend_from_slice(payload);
            encoded
        }
    }

    fn build_get_response(&self, community: &[u8], request_id: Vec<u8>, version: u8) -> Vec<u8> {
        let sys_descr = b"NetTrap SNMP Honeypot";
        let oid = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]; // 1.3.6.1.2.1.1.1.0

        let mut varbind = Vec::new();
        varbind.extend_from_slice(oid);
        varbind.push(0x04); // OCTET STRING
        varbind.extend_from_slice(&Self::ber_encode_length(sys_descr.len()));
        varbind.extend_from_slice(sys_descr);

        let mut varbind_seq = vec![0x30];
        varbind_seq.extend_from_slice(&Self::ber_encode_length(varbind.len()));
        varbind_seq.extend_from_slice(&varbind);

        let mut varbind_list = vec![0x30];
        varbind_list.extend_from_slice(&Self::ber_encode_length(varbind_seq.len()));
        varbind_list.extend_from_slice(&varbind_seq);

        let mut pdu = Vec::new();
        pdu.push(0x02); // Request ID
        pdu.extend_from_slice(&Self::ber_encode_length(request_id.len()));
        pdu.extend_from_slice(&request_id);
        pdu.extend_from_slice(&[0x02, 0x01, 0x00]); // Error status: noError
        pdu.extend_from_slice(&[0x02, 0x01, 0x00]); // Error index: 0
        pdu.extend_from_slice(&varbind_list);

        let mut pdu_wrapped = vec![0xA2]; // GetResponse
        pdu_wrapped.extend_from_slice(&Self::ber_encode_length(pdu.len()));
        pdu_wrapped.extend_from_slice(&pdu);

        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x02, 0x01, version]); // Version (echoed from request)
        msg.push(0x04); // Community
        msg.extend_from_slice(&Self::ber_encode_length(community.len()));
        msg.extend_from_slice(community);
        msg.extend_from_slice(&pdu_wrapped);

        let mut packet = vec![0x30];
        packet.extend_from_slice(&Self::ber_encode_length(msg.len()));
        packet.extend_from_slice(&msg);
        packet
    }
}

impl Default for SnmpHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG_FIELD_PREVIEW_CHARS: usize = 240;

    fn valid_get_request() -> Vec<u8> {
        vec![
            0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0,
            0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c,
            0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
        ]
    }

    fn valid_getbulk_request() -> Vec<u8> {
        let mut request = valid_get_request();
        request[13] = 0xa5;
        request[20] = 0x01;
        request[23] = 0x02;
        request
    }

    fn get_request_with_community(community: &[u8]) -> Vec<u8> {
        let pdu = &[
            0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30,
            0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
        ];

        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x02, 0x01, 0x01]);
        msg.push(0x04);
        msg.extend_from_slice(&SnmpHandler::ber_encode_length(community.len()));
        msg.extend_from_slice(community);
        msg.extend_from_slice(pdu);

        let mut packet = vec![0x30];
        packet.extend_from_slice(&SnmpHandler::ber_encode_length(msg.len()));
        packet.extend_from_slice(&msg);
        packet
    }

    fn encode_test_ber_length(len: usize) -> Vec<u8> {
        match len {
            0..=0x7f => vec![len as u8],
            0x80..=0xff => vec![0x81, len as u8],
            0x100..=0xffff => vec![0x82, (len >> 8) as u8, (len & 0xff) as u8],
            0x1_0000..=0xff_ffff => vec![
                0x83,
                ((len >> 16) & 0xff) as u8,
                ((len >> 8) & 0xff) as u8,
                (len & 0xff) as u8,
            ],
            _ => vec![
                0x84,
                ((len >> 24) & 0xff) as u8,
                ((len >> 16) & 0xff) as u8,
                ((len >> 8) & 0xff) as u8,
                (len & 0xff) as u8,
            ],
        }
    }

    fn get_request_with_test_community_length(community_len: usize) -> Vec<u8> {
        let pdu = &[
            0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30,
            0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
        ];

        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x02, 0x01, 0x01]);
        msg.push(0x04);
        msg.extend_from_slice(&encode_test_ber_length(community_len));
        msg.extend(std::iter::repeat_n(b'a', community_len));
        msg.extend_from_slice(pdu);

        let mut packet = vec![0x30];
        packet.extend_from_slice(&encode_test_ber_length(msg.len()));
        packet.extend_from_slice(&msg);
        packet
    }

    #[test]
    fn valid_get_request_gets_response() {
        let response = SnmpHandler::new().handle(&valid_get_request());

        assert!(!response.is_empty());
    }

    #[test]
    fn valid_getbulk_request_gets_response() {
        let response = SnmpHandler::new().handle(&valid_getbulk_request());

        assert!(!response.is_empty());
    }

    #[test]
    fn response_echoes_request_snmp_version() {
        // Byte index 4 of `valid_get_request` is the SNMP version INTEGER value.
        // The agent must reply with the SAME version (v1=0 / v2c=1) instead of
        // hardcoding v2c, or v1 managers reject the reply and the version
        // mismatch fingerprints the honeypot.
        for version in [0x00u8, 0x01u8] {
            let mut request = valid_get_request();
            request[4] = version;

            let response = SnmpHandler::new().handle(&request);

            assert_eq!(
                &response[2..5],
                &[0x02, 0x01, version],
                "response must echo request version 0x{version:02x}"
            );
        }
    }

    #[test]
    fn response_preserves_non_utf8_community_bytes() {
        let request = get_request_with_community(&[0xff, 0xfe]);

        let response = SnmpHandler::new().handle(&request);
        assert!(!response.is_empty());

        let mut pos = 0;
        let message = SnmpHandler::read_tlv(&response, &mut pos, response.len(), 0x30)
            .expect("response should be an SNMP message");
        assert_eq!(pos, response.len());

        let mut msg_pos = 0;
        let _version =
            SnmpHandler::read_tlv(message, &mut msg_pos, message.len(), 0x02).expect("version TLV");
        let community = SnmpHandler::read_tlv(message, &mut msg_pos, message.len(), 0x04)
            .expect("community TLV");
        assert_eq!(community, &[0xff, 0xfe]);
    }

    #[test]
    fn rejects_oversized_community_before_building_response() {
        let request = get_request_with_test_community_length(65_536);

        let response = SnmpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn logged_community_is_single_line() {
        assert_eq!(
            nettrap_core::sanitize::single_line_bytes(b"public\r\nadmin\x1b"),
            "public  admin "
        );

        let long = "a".repeat(LOG_FIELD_PREVIEW_CHARS + 1);
        assert_eq!(
            nettrap_core::sanitize::single_line_bytes(long.as_bytes()).len(),
            LOG_FIELD_PREVIEW_CHARS
        );
    }

    #[test]
    fn rejects_truncated_top_level_length() {
        let mut request = valid_get_request();
        request[1] += 1;

        let response = SnmpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_non_request_pdu_tag_with_request_low_bits() {
        let mut request = valid_get_request();
        request[13] = 0x80;

        let response = SnmpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_request_id_that_corrupts_following_fields() {
        let mut request = valid_get_request();
        request[16] = 0x02;

        let response = SnmpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_overlong_request_id_integer() {
        let mut request = valid_get_request();
        request[1] += 4;
        request[14] += 4;
        request.splice(15..18, [0x02, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01]);

        let response = SnmpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_non_canonical_request_id_integer_encoding() {
        let mut request = valid_get_request();
        request[15] = 0x02;
        request[16] = 0x02;
        request[17] = 0x00;
        request[18] = 0x01;
        request[1] = 0x27;
        request[14] = 0x1c;

        let response = SnmpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_negative_one_byte_request_id_integer() {
        let mut request = valid_get_request();
        request[17] = 0x80;

        let response = SnmpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_non_minimal_ber_length_encoding() {
        let mut request = valid_get_request();
        request.insert(1, 0x81);

        let response = SnmpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_long_form_length_with_leading_zero() {
        assert_eq!(SnmpHandler::parse_len(&[0x82, 0x00, 0x80]), (0, 0));
        assert_eq!(SnmpHandler::parse_len(&[0x83, 0x00, 0x01, 0x00]), (0, 0));
    }

    #[test]
    fn rejects_nonzero_request_error_fields() {
        let mut error_status = valid_get_request();
        error_status[20] = 0x01;
        let mut error_index = valid_get_request();
        error_index[23] = 0x01;

        assert!(SnmpHandler::new().handle(&error_status).is_empty());
        assert!(SnmpHandler::new().handle(&error_index).is_empty());
    }

    #[test]
    fn rejects_unsupported_snmp_version() {
        let mut request = valid_get_request();
        request[4] = 0x03;

        let response = SnmpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_getbulk_request_on_snmpv1() {
        let mut request = valid_getbulk_request();
        request[4] = 0x00;

        let response = SnmpHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_getbulk_negative_repeat_counts() {
        let mut non_repeaters = valid_getbulk_request();
        non_repeaters[1] += 1;
        non_repeaters[14] += 1;
        non_repeaters.splice(18..21, [0x02, 0x02, 0x80, 0x00]);

        let mut max_repetitions = valid_getbulk_request();
        max_repetitions[1] += 1;
        max_repetitions[14] += 1;
        max_repetitions.splice(21..24, [0x02, 0x02, 0x80, 0x00]);

        assert!(SnmpHandler::new().handle(&non_repeaters).is_empty());
        assert!(SnmpHandler::new().handle(&max_repetitions).is_empty());
    }

    #[test]
    fn ber_encode_length_supports_lengths_above_u16() {
        assert_eq!(SnmpHandler::ber_encode_length(127), vec![127]);
        assert_eq!(SnmpHandler::ber_encode_length(128), vec![0x81, 0x80]);
        assert_eq!(
            SnmpHandler::ber_encode_length(0x1_0000),
            vec![0x83, 0x01, 0x00, 0x00]
        );
    }
}
