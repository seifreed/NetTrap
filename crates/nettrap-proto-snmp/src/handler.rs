pub struct SnmpHandler;

impl SnmpHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        // SNMP uses BER encoding. Parse community string and PDU type.
        if data.len() < 10 || data[0] != 0x30 {
            return Vec::new();
        }

        if let Some((community, pdu_type, request_id)) = Self::parse_snmp(data) {
            tracing::warn!(
                "SNMP request: community='{}', pdu_type={}",
                community,
                pdu_type
            );

            match pdu_type {
                0 => {
                    // GetRequest
                    self.build_get_response(&community, request_id)
                }
                1 => {
                    // GetNextRequest
                    self.build_get_response(&community, request_id)
                }
                3 => {
                    // SetRequest
                    tracing::warn!("SNMP SET attempt with community='{}'", community);
                    self.build_get_response(&community, request_id)
                }
                _ => Vec::new(),
            }
        } else {
            Vec::new()
        }
    }

    fn parse_snmp(data: &[u8]) -> Option<(String, u8, Vec<u8>)> {
        let mut pos = 0;
        // SEQUENCE
        if data[pos] != 0x30 {
            return None;
        }
        pos += 1;
        let (_, lb) = Self::parse_len(&data[pos..]);
        if lb == 0 { return None; }
        pos += lb;
        // Version: INTEGER
        if pos >= data.len() || data[pos] != 0x02 {
            return None;
        }
        pos += 1;
        let (vlen, lb) = Self::parse_len(&data[pos..]);
        if lb == 0 { return None; }
        pos += lb + vlen;
        // Community: OCTET STRING
        if pos >= data.len() || data[pos] != 0x04 {
            return None;
        }
        pos += 1;
        let (clen, lb) = Self::parse_len(&data[pos..]);
        if lb == 0 { return None; }
        pos += lb;
        if pos > data.len() {
            return None;
        }
        let safe_clen = clen.min(data.len().saturating_sub(pos));
        let community = String::from_utf8_lossy(&data[pos..pos + safe_clen]).to_string();
        pos += safe_clen;
        // PDU type
        if pos >= data.len() {
            return None;
        }
        let pdu_type = data[pos] & 0x1F;
        pos += 1;
        let (_, lb) = Self::parse_len(&data[pos..]);
        if lb == 0 { return None; }
        pos += lb;
        // Request ID
        let request_id = if pos + 4 < data.len() && data[pos] == 0x02 {
            pos += 1;
            let (rlen, lb) = Self::parse_len(&data[pos..]);
            if lb == 0 { return None; }
            pos += lb;
            if pos > data.len() {
                return None;
            }
            let safe_rlen = rlen.min(data.len().saturating_sub(pos));
            data[pos..pos + safe_rlen].to_vec()
        } else {
            vec![0x01]
        };

        Some((community, pdu_type, request_id))
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
            let mut l = 0usize;
            for i in 0..n {
                l = (l << 8) | data[i + 1] as usize;
            }
            // Return (length_value, bytes_consumed)
            (l, 1 + n)
        }
    }

    /// Encode BER length in short or long form
    fn ber_encode_length(len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else if len <= 0xFF {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
        }
    }

    fn build_get_response(&self, community: &str, request_id: Vec<u8>) -> Vec<u8> {
        // Minimal GetResponse with sysDescr
        let sys_descr = b"NetTrap SNMP Honeypot";
        let oid = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]; // 1.3.6.1.2.1.1.1.0

        // VarBind: SEQUENCE { OID, OCTET STRING }
        let mut varbind = Vec::new();
        varbind.extend_from_slice(oid);
        varbind.push(0x04); // OCTET STRING
        varbind.extend_from_slice(&Self::ber_encode_length(sys_descr.len()));
        varbind.extend_from_slice(sys_descr);

        let mut varbind_seq = vec![0x30];
        varbind_seq.extend_from_slice(&Self::ber_encode_length(varbind.len()));
        varbind_seq.extend_from_slice(&varbind);

        // VarBindList
        let mut varbind_list = vec![0x30];
        varbind_list.extend_from_slice(&Self::ber_encode_length(varbind_seq.len()));
        varbind_list.extend_from_slice(&varbind_seq);

        // PDU (GetResponse = 0xA2)
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

        // Full SNMP message
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x02, 0x01, 0x01]); // Version: v2c
        msg.push(0x04); // Community
        msg.extend_from_slice(&Self::ber_encode_length(community.len()));
        msg.extend_from_slice(community.as_bytes());
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
