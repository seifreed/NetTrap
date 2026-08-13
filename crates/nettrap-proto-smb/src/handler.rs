use crate::error::{Error, Result};
use sha2::{Digest, Sha256};

#[inline]
fn le_u16_at(data: &[u8], index: usize) -> Option<u16> {
    let end = index.checked_add(2)?;
    let bytes = data.get(index..end)?;
    let bytes: [u8; 2] = bytes.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

#[inline]
fn le_u32_at(data: &[u8], index: usize) -> Option<u32> {
    let end = index.checked_add(4)?;
    let bytes = data.get(index..end)?;
    let bytes: [u8; 4] = bytes.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

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
    pub fn with_server_name(mut self, n: impl Into<String>) -> Result<Self> {
        self.server_name = validate_smb_identity(&n.into())?;
        Ok(self)
    }
    pub fn with_domain(mut self, d: impl Into<String>) -> Result<Self> {
        self.domain = validate_smb_identity(&d.into())?;
        Ok(self)
    }

    /// Handle incoming SMB data, return response
    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }

        let smb_data = if data.first().is_some_and(|byte| *byte == 0x00) {
            let Some(payload_len) = Self::netbios_payload_len(data) else {
                return Vec::new();
            };
            if payload_len < 4 || data.len() < 4 + payload_len {
                tracing::debug!(
                    "SMB: invalid NetBIOS payload length {}, captured {}",
                    payload_len,
                    data.len().saturating_sub(4)
                );
                return Vec::new();
            }
            if data.len() != 4 + payload_len {
                tracing::debug!(
                    "SMB: trailing bytes after NetBIOS payload: declared={}, captured={}",
                    payload_len,
                    data.len().saturating_sub(4)
                );
                return Vec::new();
            }
            data.get(4..4 + payload_len).unwrap_or_default()
        } else {
            data
        };

        if smb_data.len() < 4 {
            return Vec::new();
        }

        let magic = smb_data.get(..4).unwrap_or_default();

        if magic == b"\xffSMB" {
            self.handle_smb1(smb_data)
        } else if magic == b"\xfeSMB" {
            self.handle_smb2(smb_data)
        } else {
            tracing::debug!("SMB: unknown magic {:?}, ignoring packet", magic);
            Vec::new()
        }
    }

    fn netbios_payload_len(data: &[u8]) -> Option<usize> {
        if data.len() < 4 || data.first().is_none_or(|byte| *byte != 0x00) {
            return None;
        }
        if data.get(1).is_none_or(|byte| (byte & 0xfe) != 0) {
            return None;
        }
        let payload_len = (usize::from(*data.get(1)? & 0x01) << 16)
            | (usize::from(*data.get(2)?) << 8)
            | usize::from(*data.get(3)?);
        Some(payload_len)
    }

    fn handle_smb1(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 36 {
            return Vec::new();
        }
        let Some(command) = data.get(4).copied() else {
            return Vec::new();
        };
        // SMB command byte
        tracing::info!("SMB1 command: 0x{:02x}", command);

        match command {
            0x72 => {
                // SMB_COM_NEGOTIATE
                tracing::info!("SMB1 NEGOTIATE received");
                // SMB1 has no SMB2 MessageId to echo; the upgrade reply uses 0.
                self.build_smb2_negotiate_response(&[]) // Upgrade to SMB2
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
        let Some(structure_size) = le_u16_at(data, 4) else {
            return Vec::new();
        };
        if structure_size != 64 {
            return Vec::new();
        }
        let Some(flags) = le_u32_at(data, 16) else {
            return Vec::new();
        };
        if flags & 0x0000_0001 != 0 {
            tracing::debug!("SMB2: ignoring server-to-client response frame");
            return Vec::new();
        }
        let Some(command) = le_u16_at(data, 12) else {
            return Vec::new();
        };
        tracing::info!("SMB2 command: 0x{:04x}", command);

        match command {
            0x0000 => {
                tracing::info!("SMB2 NEGOTIATE received");
                self.build_smb2_negotiate_response(data)
            }
            0x0001 => {
                tracing::warn!("SMB2 SESSION_SETUP attempt - potential lateral movement");
                // Extract NTLM if present
                if data.len() > 100
                    && let Some(ntlm_info) = Self::extract_ntlm_info(data)
                {
                    tracing::warn!(
                        "SMB NTLM: domain={}, user={}, workstation={}",
                        ntlm_info.0,
                        ntlm_info.1,
                        ntlm_info.2
                    );
                }
                self.build_smb2_session_setup_response(data)
            }
            0x0003 => {
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
        if resp.len() < 4 {
            return;
        }
        if let Some(len_bytes) = resp.get_mut(1..4) {
            let [byte0, byte1, byte2] = match len_bytes {
                [byte0, byte1, byte2] => [byte0, byte1, byte2],
                _ => return,
            };
            *byte0 = ((payload_len >> 16) & 0x01) as u8;
            *byte1 = ((payload_len >> 8) & 0xFF) as u8;
            *byte2 = (payload_len & 0xFF) as u8;
        }
    }

    /// Echo the SMB2 request's Command and MessageId into a freshly-built
    /// response so the client can correlate the reply: SMB2 responses MUST
    /// carry the request's MessageId, and error/command replies echo the
    /// request Command. Offsets are relative to the SMB2 header, which begins
    /// after the 4-byte NetBIOS prefix in `resp` (Command @ +12, MessageId @
    /// +24). `req` is the NetBIOS-stripped SMB2 message handed to `handle_smb2`.
    fn echo_smb2_request_fields(resp: &mut [u8], req: &[u8]) {
        if req.len() >= 14
            && resp.len() >= 4 + 14
            && let (Some(dst), Some(src)) = (resp.get_mut(16..18), req.get(12..14))
        {
            dst.copy_from_slice(src);
        }
        if req.len() >= 32
            && resp.len() >= 4 + 32
            && let (Some(dst), Some(src)) = (resp.get_mut(28..36), req.get(24..32))
        {
            dst.copy_from_slice(src);
        }
    }

    fn build_smb2_negotiate_response(&self, req: &[u8]) -> Vec<u8> {
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
        resp.extend_from_slice(&65u16.to_le_bytes()); // Structure size
        resp.extend_from_slice(&[0; 2]); // Security mode
        resp.extend_from_slice(&0x0210u16.to_le_bytes()); // Dialect: SMB 2.1
        resp.extend_from_slice(&[0; 2]); // Reserved
        resp.extend_from_slice(&self.server_guid()); // Server GUID
        resp.extend_from_slice(&[0; 4]); // Capabilities
        resp.extend_from_slice(&65535u32.to_le_bytes()); // Max transact size
        resp.extend_from_slice(&65535u32.to_le_bytes()); // Max read size
        resp.extend_from_slice(&65535u32.to_le_bytes()); // Max write size
        resp.extend_from_slice(&[0; 8]); // System time
        resp.extend_from_slice(&[0; 8]); // Server start time
        resp.extend_from_slice(&[0; 2]); // Security buffer offset
        resp.extend_from_slice(&[0; 2]); // Security buffer length
        resp.extend_from_slice(&[0; 4]); // Reserved
        Self::echo_smb2_request_fields(&mut resp, req);
        // Fix NetBIOS length
        let Ok(smb_len) = u32::try_from(resp.len() - 4) else {
            return Vec::new();
        };
        Self::set_netbios_length(&mut resp, smb_len);
        resp
    }

    fn build_smb2_session_setup_response(&self, req: &[u8]) -> Vec<u8> {
        self.build_smb2_error(req, 0xC000006D) // STATUS_LOGON_FAILURE
    }

    fn build_smb2_error(&self, req: &[u8], status: u32) -> Vec<u8> {
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
        Self::echo_smb2_request_fields(&mut resp, req);
        let Ok(smb_len) = u32::try_from(resp.len() - 4) else {
            return Vec::new();
        };
        Self::set_netbios_length(&mut resp, smb_len);
        resp
    }

    fn build_smb1_error(&self, req: &[u8], status: u32) -> Vec<u8> {
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NetBIOS
        resp.extend_from_slice(b"\xffSMB");
        resp.push(req.get(4).copied().unwrap_or(0)); // Command
        resp.extend_from_slice(&status.to_le_bytes());
        resp.extend_from_slice(&[0; 23]); // Rest of SMB1 header (32 - magic(4) - cmd(1) - status(4) = 23)
        resp.push(0); // WordCount = 0
        resp.extend_from_slice(&0u16.to_le_bytes()); // ByteCount = 0
        let Ok(smb_len) = u32::try_from(resp.len() - 4) else {
            return Vec::new();
        };
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
        let base = data
            .get(..scan_limit)
            .and_then(|prefix| prefix.windows(8).position(|w| w == ntlm_sig))?;
        let ntlm = data.get(base..)?;

        // Need at least 52 bytes for Type 3 header through WorkstationFields
        if ntlm.len() < 52 {
            return None;
        }

        let msg_type = le_u32_at(ntlm, 8)?;
        if msg_type != 3 {
            return None;
        }

        // Limit total NTLM buffer size to prevent memory exhaustion
        let ntlm_max = ntlm.len().min(8192);
        let ntlm = ntlm.get(..ntlm_max).unwrap_or_default();

        let read_field = |offset: usize| -> Option<String> {
            if offset + 8 > ntlm.len() {
                return None;
            }
            let declared_len =
                u16::from_le_bytes([*ntlm.get(offset)?, *ntlm.get(offset + 1)?]) as usize;
            let field_offset = u32::from_le_bytes([
                *ntlm.get(offset + 4)?,
                *ntlm.get(offset + 5)?,
                *ntlm.get(offset + 6)?,
                *ntlm.get(offset + 7)?,
            ]) as usize;
            if declared_len == 0 {
                return None;
            }
            let field_end = field_offset.checked_add(declared_len)?;
            if field_end > ntlm.len() {
                return None;
            }
            // Limit field length to prevent excessive memory allocation
            let len = declared_len.min(256);
            let raw = ntlm.get(field_offset..)?.get(..len)?;
            // NTLM uses UTF-16LE for strings in Type 3
            if len >= 2 && len.is_multiple_of(2) {
                let utf16: Vec<u16> = raw
                    .chunks_exact(2)
                    .map(|chunk| {
                        let mut utf16_bytes = [0u8; 2];
                        utf16_bytes.copy_from_slice(chunk);
                        u16::from_le_bytes(utf16_bytes)
                    })
                    .collect();
                let text = String::from_utf16(&utf16).ok()?;
                Some(nettrap_core::sanitize::single_line(&text))
            } else {
                Some(nettrap_core::sanitize::single_line_bytes(raw))
            }
        };

        let domain = read_field(28)?;
        let user = read_field(36)?;
        let workstation = read_field(44)?;

        Some((domain, user, workstation))
    }

    fn server_guid(&self) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(self.server_name.as_bytes());
        hasher.update([0]);
        hasher.update(self.domain.as_bytes());

        let digest = hasher.finalize();
        let mut guid = [0u8; 16];
        if let Some(hash_prefix) = digest.get(..16) {
            guid.copy_from_slice(hash_prefix);
        }
        guid
    }
}

fn validate_smb_identity(value: &str) -> Result<String> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty()
        || nettrap_core::sanitize::contains_line_separator(value)
        || value.chars().next().is_some_and(char::is_whitespace)
        || value.chars().last().is_some_and(char::is_whitespace)
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        || !is_valid_smb_identity(value)
    {
        Err(Error::Config("invalid SMB identity".to_string()))
    } else {
        Ok(value.to_ascii_lowercase())
    }
}

fn is_valid_smb_identity(value: &str) -> bool {
    let value = if let Some(value) = value.strip_suffix('.') {
        if value.is_empty() || value.ends_with('.') {
            return false;
        }
        value
    } else {
        value
    };
    !value.is_empty()
        && value.len() <= 253
        && value.parse::<std::net::IpAddr>().is_err()
        && !nettrap_core::sanitize::has_numeric_domain_labels(value)
        && nettrap_core::sanitize::has_valid_domain_labels(value)
}

impl Default for SmbHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG_FIELD_PREVIEW_CHARS: usize = 240;

    fn utf16le(value: &str) -> Vec<u8> {
        value
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect()
    }

    fn set_ntlm_field(message: &mut [u8], field_offset: usize, value_offset: usize, len: usize) {
        if let Some(len_bytes) = message.get_mut(field_offset..field_offset + 2) {
            len_bytes.copy_from_slice(&(len as u16).to_le_bytes());
        } else {
            return;
        }
        if let Some(offset_bytes) = message.get_mut(field_offset + 2..field_offset + 4) {
            offset_bytes.copy_from_slice(&(len as u16).to_le_bytes());
        } else {
            return;
        }
        if let Some(offs) = message.get_mut(field_offset + 4..field_offset + 8) {
            offs.copy_from_slice(&(value_offset as u32).to_le_bytes());
        }
    }

    fn ntlm_type3_message(domain: &[u8], user: &[u8], workstation: &[u8]) -> Vec<u8> {
        let mut message = vec![0; 52];
        let Some(signature) = message.get_mut(..8) else {
            return message;
        };
        signature.copy_from_slice(b"NTLMSSP\0");
        if let Some(header) = message.get_mut(8..12) {
            header.copy_from_slice(&3u32.to_le_bytes());
        } else {
            return message;
        }

        let mut offset = message.len();
        set_ntlm_field(&mut message, 28, offset, domain.len());
        message.extend_from_slice(domain);
        offset = message.len();
        set_ntlm_field(&mut message, 36, offset, user.len());
        message.extend_from_slice(user);
        offset = message.len();
        set_ntlm_field(&mut message, 44, offset, workstation.len());
        message.extend_from_slice(workstation);

        message
    }

    #[test]
    fn ignores_non_smb_payloads() {
        let response = SmbHandler::new().handle(b"GET / HTTP/1.1\r\n\r\n");

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_non_smb_payloads_after_netbios_header() {
        let response = SmbHandler::new().handle(&[0x00, 0x00, 0x00, 0x04, b'B', b'A', b'D', b'!']);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_invalid_netbios_payload_lengths() {
        let short_declared_payload =
            SmbHandler::new().handle(&[0x00, 0x00, 0x00, 0x03, b'\xfe', b'S', b'M', b'B']);
        assert!(short_declared_payload.is_empty());

        let truncated_declared_payload =
            SmbHandler::new().handle(&[0x00, 0x00, 0x00, 0x08, b'\xfe', b'S', b'M', b'B']);
        assert!(truncated_declared_payload.is_empty());
    }

    #[test]
    fn rejects_smb2_header_with_invalid_structure_size() {
        let mut packet = Vec::new();
        packet.extend_from_slice(b"\xfeSMB");
        packet.extend_from_slice(&0u16.to_le_bytes());
        packet.extend_from_slice(&[0; 62]);

        let response = SmbHandler::new().handle(&packet);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_smb2_server_to_client_response_frames() {
        let mut packet = smb2_request(0x0000, 0x2a);
        packet[20..24].copy_from_slice(&1u32.to_le_bytes());

        let response = SmbHandler::new().handle(&packet);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_netbios_header_with_reserved_length_flags() {
        let mut packet = vec![0x00, 0x02, 0x00, 0x24];
        packet.extend_from_slice(b"\xffSMB");
        packet.push(0x72);
        packet.extend_from_slice(&[0; 31]);

        let response = SmbHandler::new().handle(&packet);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_trailing_bytes_after_netbios_payload() {
        let mut packet = vec![0x00, 0x00, 0x00, 0x24];
        packet.extend_from_slice(b"\xffSMB");
        packet.push(0x72);
        packet.extend_from_slice(&[0; 31]);
        packet.push(0);

        let response = SmbHandler::new().handle(&packet);

        assert!(response.is_empty());
    }

    #[test]
    fn extracted_ntlm_identity_fields_are_single_line() {
        let message = ntlm_type3_message(
            &utf16le("DOM\r\nAIN"),
            &utf16le("al\r\nice\x1b"),
            &utf16le("WS\t01"),
        );

        let (domain, user, workstation) =
            SmbHandler::extract_ntlm_info(&message).expect("ntlm info");

        assert_eq!(domain, "DOM  AIN");
        assert_eq!(user, "al  ice ");
        assert_eq!(workstation, "WS 01");
        assert!(!domain.chars().any(char::is_control));
        assert!(!user.chars().any(char::is_control));
        assert!(!workstation.chars().any(char::is_control));

        let long = "a".repeat(LOG_FIELD_PREVIEW_CHARS + 1);
        assert_eq!(
            nettrap_core::sanitize::single_line(&long).len(),
            LOG_FIELD_PREVIEW_CHARS
        );
    }

    #[test]
    fn ntlm_zero_length_identity_fields_are_rejected() {
        let message = ntlm_type3_message(&[], &utf16le("alice"), &utf16le("WS01"));
        assert!(SmbHandler::extract_ntlm_info(&message).is_none());
    }

    fn smb2_request(command: u16, message_id: u64) -> Vec<u8> {
        let mut smb2 = vec![0u8; 68];
        if let Some(magic) = smb2.get_mut(0..4) {
            magic.copy_from_slice(b"\xfeSMB");
        } else {
            return smb2;
        }
        if let Some(structure_size) = smb2.get_mut(4..6) {
            structure_size.copy_from_slice(&64u16.to_le_bytes()); // structure size
        } else {
            return smb2;
        }
        if let Some(command_bytes) = smb2.get_mut(12..14) {
            command_bytes.copy_from_slice(&command.to_le_bytes());
        } else {
            return smb2;
        }
        if let Some(message_id_bytes) = smb2.get_mut(24..32) {
            message_id_bytes.copy_from_slice(&message_id.to_le_bytes());
        } else {
            return smb2;
        }

        let len = smb2.len() as u32;
        let mut packet = vec![
            0x00,
            ((len >> 16) & 0x01) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ];
        packet.extend_from_slice(&smb2);
        packet
    }

    #[test]
    fn smb2_response_echoes_request_message_id_and_command() {
        // The SMB2 header in the response begins after the 4-byte NetBIOS
        // prefix: Command @ +12 (resp[16..18]), MessageId @ +24 (resp[28..36]).
        // Clients correlate replies by MessageId, so it must be echoed.
        let handler = SmbHandler::new();

        let response = handler.handle(&smb2_request(0x0003, 0x0102_0304_0506_0708));
        assert!(response.len() >= 36);
        assert_eq!(response.get(4..8), Some(b"\xfeSMB".as_ref()));
        let command = response
            .get(16..18)
            .and_then(|bytes| bytes.try_into().ok())
            .expect("command echoed in response");
        let command = u16::from_le_bytes(command);
        assert_eq!(command, 0x0003, "error reply must echo request command");
        let message_id = response
            .get(28..36)
            .and_then(|bytes| bytes.try_into().ok())
            .expect("message id echoed in response");
        let message_id = u64::from_le_bytes(message_id);
        assert_eq!(
            message_id, 0x0102_0304_0506_0708,
            "reply must echo request MessageId"
        );

        let negotiate = handler.handle(&smb2_request(0x0000, 0x0000_0000_0000_002a));
        assert!(negotiate.len() >= 36);
        let negotiated_message_id = negotiate
            .get(28..36)
            .and_then(|bytes| bytes.try_into().ok())
            .expect("message id echoed in negotiate response");
        assert_eq!(
            u64::from_le_bytes(negotiated_message_id),
            0x2a,
            "negotiate reply must echo request MessageId"
        );
        let dialect = negotiate
            .get(72..74)
            .and_then(|bytes| bytes.try_into().ok())
            .expect("dialect echoed in negotiate response");
        assert_eq!(
            u16::from_le_bytes(dialect),
            0x0210,
            "negotiate reply must advertise a response shape it actually emits"
        );
    }

    #[test]
    fn smb1_error_response_echoes_request_command() {
        let handler = SmbHandler::new();
        for command in [0x73, 0x75] {
            let mut packet = Vec::new();
            packet.extend_from_slice(b"\xffSMB");
            packet.push(command);
            packet.extend_from_slice(&[0; 31]);

            let response = handler.handle(&packet);

            assert_eq!(response.get(4..8), Some(b"\xffSMB".as_ref()));
            assert_eq!(
                response.get(8).copied(),
                Some(command),
                "SMB1 error response must echo request command"
            );
        }
    }

    #[test]
    fn ntlm_field_offset_overflow_is_rejected() {
        let mut message = vec![0; 52];
        if let Some(signature) = message.get_mut(..8) {
            signature.copy_from_slice(b"NTLMSSP\0");
        }
        if let Some(msg_type) = message.get_mut(8..12) {
            msg_type.copy_from_slice(&3u32.to_le_bytes());
        }
        if let Some(len) = message.get_mut(28..30) {
            len.copy_from_slice(&2u16.to_le_bytes());
        }
        if let Some(offset) = message.get_mut(32..36) {
            offset.copy_from_slice(&u32::MAX.to_le_bytes());
        }

        assert!(SmbHandler::extract_ntlm_info(&message).is_none());
    }

    #[test]
    fn little_endian_u16_reader_rejects_overflowing_offset() {
        assert_eq!(le_u16_at(&[0, 1], usize::MAX), None);
    }

    #[test]
    fn little_endian_u32_reader_rejects_overflowing_offset() {
        assert_eq!(le_u32_at(&[0, 1, 2, 3], usize::MAX), None);
    }

    #[test]
    fn ntlm_fields_reject_declared_length_beyond_message() {
        let mut message = ntlm_type3_message(&vec![b'A'; 256], &utf16le("alice"), &utf16le("WS01"));
        if let Some(len) = message.get_mut(28..30) {
            len.copy_from_slice(&300u16.to_le_bytes());
        }
        if let Some(max_len) = message.get_mut(30..32) {
            max_len.copy_from_slice(&300u16.to_le_bytes());
        }

        assert!(SmbHandler::extract_ntlm_info(&message).is_none());
    }

    #[test]
    fn ntlm_fields_reject_invalid_utf16() {
        let mut message = ntlm_type3_message(&[0xff, 0xd8], &[0x61, 0x00], &[0x62, 0x00]);
        if let Some(field) = message.get_mut(36..38) {
            field.copy_from_slice(&[0x61, 0xd8]);
        }

        assert!(SmbHandler::extract_ntlm_info(&message).is_none());
    }

    #[test]
    fn configured_server_identity_changes_negotiate_guid() {
        let request = smb2_request(0x0000, 0x1234_5678_9abc_def0);
        let default_guid = SmbHandler::new().handle(&request);
        let custom_guid = SmbHandler::new()
            .with_server_name("atlas")
            .expect("valid SMB server name")
            .with_domain("lab")
            .expect("valid SMB domain")
            .handle(&request);

        assert_eq!(default_guid.get(4..8), Some(b"\xfeSMB".as_ref()));
        assert_eq!(custom_guid.get(4..8), Some(b"\xfeSMB".as_ref()));
        let default_signature = default_guid
            .get(76..92)
            .expect("default GUID has identity bytes");
        let custom_signature = custom_guid
            .get(76..92)
            .expect("custom GUID has identity bytes");
        assert_ne!(default_signature, custom_signature);
    }

    #[test]
    fn configured_server_identity_rejects_invalid_punctuation() {
        assert!(
            SmbHandler::new()
                .with_server_name("atlas><injected")
                .is_err()
        );
        assert!(SmbHandler::new().with_domain("lab><injected").is_err());
        assert!(SmbHandler::new().with_server_name("atlas_example").is_err());
        assert!(SmbHandler::new().with_domain("lab_example").is_err());
    }

    #[test]
    fn configured_server_identity_rejects_empty_labels() {
        assert!(SmbHandler::new().with_server_name("mail..example").is_err());
        assert!(SmbHandler::new().with_domain("lab..example").is_err());
    }

    #[test]
    fn configured_server_identity_rejects_dashed_label_edges() {
        assert!(
            SmbHandler::new()
                .with_server_name("-atlas.example")
                .is_err()
        );
        assert!(SmbHandler::new().with_domain("lab-.example").is_err());
    }

    #[test]
    fn configured_server_identity_rejects_leading_whitespace() {
        assert!(SmbHandler::new().with_server_name(" atlas").is_err());
        assert!(SmbHandler::new().with_domain(" workgroup").is_err());
    }

    #[test]
    fn configured_server_identity_rejects_unicode_line_separators() {
        assert!(
            SmbHandler::new()
                .with_server_name("atlas\u{2028}owned")
                .is_err()
        );
        assert!(SmbHandler::new().with_domain("lab\u{2029}owned").is_err());
    }

    #[test]
    fn configured_server_identity_accepts_absolute_hostnames_with_trailing_dots() {
        let request = smb2_request(0x0000, 0x1234_5678_9abc_def0);
        let handler = SmbHandler::new()
            .with_server_name("atlas.example.")
            .expect("valid SMB server name")
            .with_domain("lab.example.")
            .expect("valid SMB domain");
        let response = handler.handle(&request);

        assert_eq!(response.get(4..8), Some(b"\xfeSMB".as_ref()));
        assert_ne!(
            response.get(76..92),
            SmbHandler::new().handle(&request).get(76..92)
        );
    }

    #[test]
    fn configured_server_identity_canonicalizes_hostname_case() {
        let request = smb2_request(0x0000, 0x1234_5678_9abc_def0);
        let upper = SmbHandler::new()
            .with_server_name("ATLAS.EXAMPLE.")
            .expect("valid SMB server name")
            .with_domain("LAB.EXAMPLE.")
            .expect("valid SMB domain")
            .handle(&request);
        let lower = SmbHandler::new()
            .with_server_name("atlas.example")
            .expect("valid SMB server name")
            .with_domain("lab.example")
            .expect("valid SMB domain")
            .handle(&request);

        assert_eq!(upper, lower);
    }

    #[test]
    fn configured_server_identity_rejects_overlong_host_labels() {
        let hostname = format!("{}.example.test", "a".repeat(64));

        assert!(validate_smb_identity(&hostname).is_err());
    }

    #[test]
    fn configured_server_identity_rejects_overlong_absolute_hostnames() {
        let hostname = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );

        assert_eq!(hostname.len(), 255);
        assert!(validate_smb_identity(&hostname).is_err());
    }

    #[test]
    fn configured_server_identity_rejects_multiple_trailing_dots() {
        assert!(validate_smb_identity("atlas.example...").is_err());
    }

    #[test]
    fn configured_server_identity_rejects_numeric_hostnames() {
        for hostname in ["12345", "192.0.2.10", "0.0.0.0"] {
            assert!(validate_smb_identity(hostname).is_err(), "{hostname}");
        }
    }

    #[test]
    fn configured_server_identity_rejects_c1_controls() {
        assert!(validate_smb_identity("nettrap\u{009f}.example").is_err());
    }
}
