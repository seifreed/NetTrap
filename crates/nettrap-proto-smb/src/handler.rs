pub struct SmbHandler {
    server_name: String,
    domain: String,
}

impl SmbHandler {
    pub fn new() -> Self {
        Self {
            server_name: "NETTRAP".to_string(),
            domain: "WORKGROUP".to_string(),
        }
    }
    pub fn with_server_name(mut self, n: impl Into<String>) -> Self {
        self.server_name = n.into();
        self
    }
    pub fn with_domain(mut self, d: impl Into<String>) -> Self {
        self.domain = d.into();
        self
    }

    /// Handle incoming SMB data, return response
    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 4 {
            return Vec::new();
        }

        // NetBIOS session header: 4 bytes (type + length)
        // SMB header starts with 0xFF 'S' 'M' 'B' (SMB1) or 0xFE 'S' 'M' 'B' (SMB2)
        let smb_offset = if data[0] == 0x00 { 4 } else { 0 }; // Skip NetBIOS header

        if data.len() < smb_offset + 4 {
            return Vec::new();
        }

        let magic = &data[smb_offset..smb_offset + 4];

        if magic == b"\xffSMB" {
            self.handle_smb1(&data[smb_offset..])
        } else if magic == b"\xfeSMB" {
            self.handle_smb2(&data[smb_offset..])
        } else {
            // Try to respond with SMB2 negotiate response anyway
            tracing::debug!("SMB: unknown magic {:?}, sending negotiate response", magic);
            self.build_smb2_negotiate_response()
        }
    }

    fn handle_smb1(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 36 {
            return Vec::new();
        }
        let command = data[4]; // SMB command byte
        tracing::info!("SMB1 command: 0x{:02x}", command);

        match command {
            0x72 => {
                // SMB_COM_NEGOTIATE
                tracing::info!("SMB1 NEGOTIATE received");
                self.build_smb2_negotiate_response() // Upgrade to SMB2
            }
            0x73 => {
                // SMB_COM_SESSION_SETUP_ANDX
                tracing::warn!("SMB1 SESSION_SETUP attempt detected");
                self.build_smb1_error(data, 0xC000006D) // STATUS_LOGON_FAILURE
            }
            0x75 => {
                // SMB_COM_TREE_CONNECT_ANDX
                tracing::warn!("SMB1 TREE_CONNECT attempt");
                self.build_smb1_error(data, 0xC0000022) // STATUS_ACCESS_DENIED
            }
            _ => {
                tracing::info!("SMB1 command 0x{:02x}", command);
                Vec::new()
            }
        }
    }

    fn handle_smb2(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 68 {
            return Vec::new();
        }
        let command = u16::from_le_bytes([data[12], data[13]]);
        tracing::info!("SMB2 command: 0x{:04x}", command);

        match command {
            0x0000 => {
                // NEGOTIATE
                tracing::info!("SMB2 NEGOTIATE received");
                self.build_smb2_negotiate_response()
            }
            0x0001 => {
                // SESSION_SETUP
                tracing::warn!("SMB2 SESSION_SETUP attempt - potential lateral movement");
                // Extract NTLM if present
                if data.len() > 100 {
                    if let Some(ntlm_info) = Self::extract_ntlm_info(data) {
                        tracing::warn!(
                            "SMB NTLM: domain={}, user={}, workstation={}",
                            ntlm_info.0,
                            ntlm_info.1,
                            ntlm_info.2
                        );
                    }
                }
                self.build_smb2_session_setup_response(data)
            }
            0x0003 => {
                // TREE_CONNECT
                tracing::warn!("SMB2 TREE_CONNECT attempt");
                self.build_smb2_error(data, 0xC0000022) // ACCESS_DENIED
            }
            _ => {
                tracing::info!("SMB2 command 0x{:04x}", command);
                self.build_smb2_error(data, 0xC0000022)
            }
        }
    }

    /// Encode NetBIOS session header length (3 bytes: bits 16-0)
    fn set_netbios_length(resp: &mut [u8], payload_len: u32) {
        resp[1] = ((payload_len >> 16) & 0x01) as u8; // bit 16 (max 131071 bytes)
        resp[2] = ((payload_len >> 8) & 0xFF) as u8;
        resp[3] = (payload_len & 0xFF) as u8;
    }

    fn build_smb2_negotiate_response(&self) -> Vec<u8> {
        let mut resp = Vec::new();
        // NetBIOS header (placeholder, fix length after)
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // SMB2 header
        resp.extend_from_slice(b"\xfeSMB"); // Protocol
        resp.extend_from_slice(&64u16.to_le_bytes()); // Header length
        resp.extend_from_slice(&[0; 2]); // Credit charge
        resp.extend_from_slice(&0u32.to_le_bytes()); // Status: SUCCESS
        resp.extend_from_slice(&0u16.to_le_bytes()); // Command: NEGOTIATE
        resp.extend_from_slice(&1u16.to_le_bytes()); // Credits granted
        resp.extend_from_slice(&1u32.to_le_bytes()); // Flags: SMB2_FLAGS_SERVER_TO_REDIR
        resp.extend_from_slice(&[0; 4]); // Next command
        resp.extend_from_slice(&[0; 8]); // Message ID
        resp.extend_from_slice(&[0; 4]); // Reserved
        resp.extend_from_slice(&[0; 4]); // Tree ID
        resp.extend_from_slice(&[0; 8]); // Session ID
        resp.extend_from_slice(&[0; 16]); // Signature
        // Negotiate response body (minimal)
        resp.extend_from_slice(&65u16.to_le_bytes()); // Structure size
        resp.extend_from_slice(&[0; 2]); // Security mode
        resp.extend_from_slice(&0x0311u16.to_le_bytes()); // Dialect: SMB 3.1.1
        resp.extend_from_slice(&[0; 2]); // Reserved
        resp.extend_from_slice(&[0; 16]); // Server GUID
        resp.extend_from_slice(&[0; 4]); // Capabilities
        resp.extend_from_slice(&65535u32.to_le_bytes()); // Max transact size
        resp.extend_from_slice(&65535u32.to_le_bytes()); // Max read size
        resp.extend_from_slice(&65535u32.to_le_bytes()); // Max write size
        resp.extend_from_slice(&[0; 8]); // System time
        resp.extend_from_slice(&[0; 8]); // Server start time
        resp.extend_from_slice(&[0; 2]); // Security buffer offset
        resp.extend_from_slice(&[0; 2]); // Security buffer length
        resp.extend_from_slice(&[0; 4]); // Reserved
        // Fix NetBIOS length
        let smb_len = (resp.len() - 4) as u32;
        Self::set_netbios_length(&mut resp, smb_len);
        resp
    }

    fn build_smb2_session_setup_response(&self, _req: &[u8]) -> Vec<u8> {
        self.build_smb2_error(&[], 0xC000006D) // STATUS_LOGON_FAILURE
    }

    fn build_smb2_error(&self, _req: &[u8], status: u32) -> Vec<u8> {
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NetBIOS
        resp.extend_from_slice(b"\xfeSMB");
        resp.extend_from_slice(&64u16.to_le_bytes());
        resp.extend_from_slice(&[0; 2]); // Credit charge
        resp.extend_from_slice(&status.to_le_bytes());
        resp.extend_from_slice(&[0; 2]); // Command
        resp.extend_from_slice(&1u16.to_le_bytes()); // Credits
        resp.extend_from_slice(&1u32.to_le_bytes()); // Flags: SMB2_FLAGS_SERVER_TO_REDIR
        resp.extend_from_slice(&[0; 60]); // Rest of header + minimal body
        let smb_len = (resp.len() - 4) as u32;
        Self::set_netbios_length(&mut resp, smb_len);
        resp
    }

    fn build_smb1_error(&self, _req: &[u8], status: u32) -> Vec<u8> {
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NetBIOS
        resp.extend_from_slice(b"\xffSMB");
        resp.push(0); // Command
        resp.extend_from_slice(&status.to_le_bytes());
        resp.extend_from_slice(&[0; 23]); // Rest of SMB1 header (32 - magic(4) - cmd(1) - status(4) = 23)
        resp.push(0); // WordCount = 0
        resp.extend_from_slice(&0u16.to_le_bytes()); // ByteCount = 0
        let smb_len = (resp.len() - 4) as u32;
        Self::set_netbios_length(&mut resp, smb_len);
        resp
    }

    /// Parse NTLM Type 3 (AUTHENTICATE) message to extract domain, username, and workstation.
    /// NTLM Type 3 layout (offsets from NTLMSSP signature):
    ///   0-7:  "NTLMSSP\0"
    ///   8-11: MessageType (3)
    ///  12-19: LmChallengeResponseFields
    ///  20-27: NtChallengeResponseFields
    ///  28-35: DomainNameFields (len u16, maxlen u16, offset u32)
    ///  36-43: UserNameFields   (len u16, maxlen u16, offset u32)
    ///  44-51: WorkstationFields(len u16, maxlen u16, offset u32)
    fn extract_ntlm_info(data: &[u8]) -> Option<(String, String, String)> {
        let ntlm_sig = b"NTLMSSP\x00";
        // Limit scan to first 4KB to prevent DoS with large payloads
        let scan_limit = data.len().min(4096);
        let base = data[..scan_limit].windows(8).position(|w| w == ntlm_sig)?;
        let ntlm = &data[base..];

        // Need at least 52 bytes for Type 3 header through WorkstationFields
        if ntlm.len() < 52 {
            return None;
        }

        let msg_type = u32::from_le_bytes([ntlm[8], ntlm[9], ntlm[10], ntlm[11]]);
        if msg_type != 3 {
            return None;
        }

        // Limit total NTLM buffer size to prevent memory exhaustion
        let ntlm_max = ntlm.len().min(8192);
        let ntlm = &ntlm[..ntlm_max];

        let read_field = |offset: usize| -> Option<String> {
            if offset + 8 > ntlm.len() {
                return None;
            }
            let len = u16::from_le_bytes([ntlm[offset], ntlm[offset + 1]]) as usize;
            let field_offset = u32::from_le_bytes([
                ntlm[offset + 4],
                ntlm[offset + 5],
                ntlm[offset + 6],
                ntlm[offset + 7],
            ]) as usize;
            if len == 0 {
                return Some(String::new());
            }
            // Limit field length to prevent excessive memory allocation
            let len = len.min(256);
            if field_offset + len > ntlm.len() {
                return None;
            }
            let raw = &ntlm[field_offset..field_offset + len];
            // NTLM uses UTF-16LE for strings in Type 3
            if len >= 2 && len % 2 == 0 {
                let utf16: Vec<u16> = raw
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                Some(String::from_utf16_lossy(&utf16))
            } else {
                Some(String::from_utf8_lossy(raw).to_string())
            }
        };

        let domain = read_field(28).unwrap_or_default();
        let user = read_field(36).unwrap_or_default();
        let workstation = read_field(44).unwrap_or_default();

        Some((domain, user, workstation))
    }
}

impl Default for SmbHandler {
    fn default() -> Self {
        Self::new()
    }
}
