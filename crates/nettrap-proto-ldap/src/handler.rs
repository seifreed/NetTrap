pub struct LdapHandler {
    base_dn: String,
}

impl LdapHandler {
    pub fn new() -> Self {
        Self {
            base_dn: "dc=nettrap,dc=local".to_string(),
        }
    }
    pub fn with_base_dn(mut self, dn: impl Into<String>) -> Self {
        self.base_dn = dn.into();
        self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        // LDAP uses BER/DER encoding (ASN.1)
        // Minimal parsing: extract message ID and operation
        if data.len() < 7 {
            return Vec::new();
        }

        // Sequence tag 0x30
        if data[0] != 0x30 {
            return Vec::new();
        }

        let (msg_id, op_offset) = Self::parse_message_id(data);
        if op_offset >= data.len() {
            return Vec::new();
        }

        let op_tag = data[op_offset] & 0x1F; // Application tag number
        let op_class = (data[op_offset] >> 6) & 0x03; // Class (should be Application = 1)

        tracing::info!(
            "LDAP message_id={}, op_tag={}, class={}",
            msg_id,
            op_tag,
            op_class
        );

        match op_tag {
            0 => {
                // BindRequest (tag 0, Application class)
                tracing::warn!("LDAP BIND request");
                // Extract bind DN if possible
                if let Some(dn) = Self::extract_bind_dn(data, op_offset) {
                    tracing::warn!("LDAP BIND DN: {}", dn);
                }
                self.build_bind_response(msg_id)
            }
            3 => {
                // SearchRequest
                tracing::warn!("LDAP SEARCH request - potential recon/Log4Shell");
                // Log the search base and filter
                self.build_search_result_done(msg_id)
            }
            2 => {
                // UnbindRequest
                Vec::new() // No response needed
            }
            _ => {
                tracing::info!("LDAP operation tag={}", op_tag);
                Vec::new()
            }
        }
    }

    fn parse_message_id(data: &[u8]) -> (u32, usize) {
        // Skip sequence tag + length
        let mut pos = 1;
        let (_seq_len, len_bytes) = match Self::parse_ber_length(&data[pos..]) {
            Some(v) => v,
            None => return (0, pos),
        };
        pos += len_bytes;

        // Message ID: INTEGER tag (0x02) + length + value
        if pos >= data.len() || data[pos] != 0x02 {
            return (0, pos);
        }
        pos += 1;
        let (id_len, len_bytes) = match Self::parse_ber_length(&data[pos..]) {
            Some(v) => v,
            None => return (0, pos),
        };
        pos += len_bytes;

        // Validate id_len won't move pos past data boundary
        let safe_id_len = id_len.min(data.len().saturating_sub(pos));
        let mut msg_id = 0u32;
        for i in 0..safe_id_len.min(4) {
            msg_id = (msg_id << 8) | data[pos + i] as u32;
        }
        pos += safe_id_len;

        (msg_id, pos)
    }

    /// Maximum allowed BER length (16MB) to prevent memory exhaustion attacks
    const MAX_BER_LENGTH: usize = 16 * 1024 * 1024;

    fn parse_ber_length(data: &[u8]) -> Option<(usize, usize)> {
        if data.is_empty() {
            return None;
        }
        if data[0] & 0x80 == 0 {
            // Short form: length in lower 7 bits
            let len = data[0] as usize;
            Some((len.min(Self::MAX_BER_LENGTH), 1))
        } else {
            // Long form: lower 7 bits = number of following length bytes
            let num_bytes = (data[0] & 0x7F) as usize;
            // Ensure all length bytes are present and limit to reasonable size
            if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
                return None;
            }
            let mut len = 0usize;
            for i in 0..num_bytes {
                len = (len << 8) | data[i + 1] as usize;
            }
            // Cap length to prevent memory exhaustion
            Some((len.min(Self::MAX_BER_LENGTH), 1 + num_bytes))
        }
    }

    fn extract_bind_dn(data: &[u8], op_offset: usize) -> Option<String> {
        let mut pos = op_offset + 1; // Skip tag
        if pos >= data.len() {
            return None;
        }
        let (_, len_bytes) = Self::parse_ber_length(&data[pos..])?;
        pos += len_bytes;
        // Skip version INTEGER
        if pos >= data.len() || data[pos] != 0x02 {
            return None;
        }
        pos += 1;
        let (ver_len, len_bytes) = Self::parse_ber_length(&data[pos..])?;
        let advance = len_bytes.saturating_add(ver_len);
        if pos + advance > data.len() {
            return None;
        }
        pos += advance;
        // DN is OCTET STRING (0x04)
        if pos >= data.len() || data[pos] != 0x04 {
            return None;
        }
        pos += 1;
        let (dn_len, len_bytes) = Self::parse_ber_length(&data[pos..])?;
        pos += len_bytes;
        if pos + dn_len > data.len() {
            return None;
        }
        Some(String::from_utf8_lossy(&data[pos..pos + dn_len]).to_string())
    }

    fn build_bind_response(&self, msg_id: u32) -> Vec<u8> {
        // BindResponse: success
        let mut result = Vec::new();
        // Result code: success (ENUMERATED 0)
        result.extend_from_slice(&[0x0A, 0x01, 0x00]); // ENUM, len=1, value=0 (success)
        // Matched DN (empty)
        result.extend_from_slice(&[0x04, 0x00]);
        // Diagnostic message (empty)
        result.extend_from_slice(&[0x04, 0x00]);

        // Wrap in Application[1] (BindResponse)
        let mut bind_resp = vec![0x61]; // Application[1] constructed
        Self::encode_ber_length(&mut bind_resp, result.len());
        bind_resp.extend_from_slice(&result);

        // Wrap in SEQUENCE with message ID
        self.wrap_ldap_message(msg_id, &bind_resp)
    }

    fn build_search_result_done(&self, msg_id: u32) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&[0x0A, 0x01, 0x00]); // success
        result.extend_from_slice(&[0x04, 0x00]); // matched DN
        result.extend_from_slice(&[0x04, 0x00]); // diagnostic

        let mut search_done = vec![0x65]; // Application[5] SearchResultDone
        Self::encode_ber_length(&mut search_done, result.len());
        search_done.extend_from_slice(&result);

        self.wrap_ldap_message(msg_id, &search_done)
    }

    fn wrap_ldap_message(&self, msg_id: u32, op_data: &[u8]) -> Vec<u8> {
        let mut msg_id_bytes = vec![0x02]; // INTEGER tag
        if msg_id <= 0x7F {
            msg_id_bytes.push(1);
            msg_id_bytes.push(msg_id as u8);
        } else if msg_id <= 0xFF {
            msg_id_bytes.push(2);
            msg_id_bytes.push(0x00);
            msg_id_bytes.push(msg_id as u8);
        } else if msg_id <= 0x7FFF {
            msg_id_bytes.push(2);
            msg_id_bytes.push((msg_id >> 8) as u8);
            msg_id_bytes.push((msg_id & 0xFF) as u8);
        } else if msg_id <= 0xFFFF {
            // High bit set in 2-byte form — need leading zero to stay positive
            msg_id_bytes.push(3);
            msg_id_bytes.push(0x00);
            msg_id_bytes.push((msg_id >> 8) as u8);
            msg_id_bytes.push((msg_id & 0xFF) as u8);
        } else if msg_id <= 0x7FFFFF {
            msg_id_bytes.push(3);
            msg_id_bytes.push((msg_id >> 16) as u8);
            msg_id_bytes.push((msg_id >> 8) as u8);
            msg_id_bytes.push((msg_id & 0xFF) as u8);
        } else if msg_id <= 0xFFFFFF {
            msg_id_bytes.push(4);
            msg_id_bytes.push(0x00);
            msg_id_bytes.push((msg_id >> 16) as u8);
            msg_id_bytes.push((msg_id >> 8) as u8);
            msg_id_bytes.push((msg_id & 0xFF) as u8);
        } else if msg_id <= 0x7FFFFFFF {
            msg_id_bytes.push(4);
            msg_id_bytes.push((msg_id >> 24) as u8);
            msg_id_bytes.push((msg_id >> 16) as u8);
            msg_id_bytes.push((msg_id >> 8) as u8);
            msg_id_bytes.push((msg_id & 0xFF) as u8);
        } else {
            msg_id_bytes.push(5);
            msg_id_bytes.push(0x00);
            msg_id_bytes.push((msg_id >> 24) as u8);
            msg_id_bytes.push((msg_id >> 16) as u8);
            msg_id_bytes.push((msg_id >> 8) as u8);
            msg_id_bytes.push((msg_id & 0xFF) as u8);
        }

        let inner_len = msg_id_bytes.len() + op_data.len();
        let mut packet = vec![0x30]; // SEQUENCE
        Self::encode_ber_length(&mut packet, inner_len);
        packet.extend_from_slice(&msg_id_bytes);
        packet.extend_from_slice(op_data);
        packet
    }

    fn encode_ber_length(buf: &mut Vec<u8>, len: usize) {
        if len < 128 {
            buf.push(len as u8);
        } else if len < 256 {
            buf.push(0x81);
            buf.push(len as u8);
        } else {
            buf.push(0x82);
            buf.push((len >> 8) as u8);
            buf.push((len & 0xFF) as u8);
        }
    }
}

impl Default for LdapHandler {
    fn default() -> Self {
        Self::new()
    }
}
