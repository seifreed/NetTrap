pub struct MysqlHandler {
    version: String,
    server_id: u32,
}

const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SSL: u32 = 0x0000_0800;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const SERVER_CAPABILITIES: u32 = CLIENT_LONG_PASSWORD
    | CLIENT_LONG_FLAG
    | CLIENT_PROTOCOL_41
    | CLIENT_SECURE_CONNECTION
    | CLIENT_PLUGIN_AUTH;

impl MysqlHandler {
    pub fn new() -> Self {
        Self {
            version: "8.0.36-0ubuntu0.22.04.1".to_string(),
            server_id: 1,
        }
    }
    pub fn with_version(mut self, v: impl Into<String>) -> Self {
        self.version = v.into();
        self
    }

    /// Build MySQL initial handshake packet (sent on connect)
    pub fn get_handshake(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(10); // Protocol version 10
        payload.extend_from_slice(self.version.as_bytes());
        payload.push(0); // null terminator
        payload.extend_from_slice(&self.server_id.to_le_bytes()); // Connection ID
        payload.extend_from_slice(b"nettrap!"); // Auth plugin data part 1 (8 bytes)
        payload.push(0); // Filler
        payload.extend_from_slice(&(SERVER_CAPABILITIES as u16).to_le_bytes());
        payload.push(0x21); // Character set (utf8)
        payload.extend_from_slice(&0x0002u16.to_le_bytes()); // Status flags
        payload.extend_from_slice(&((SERVER_CAPABILITIES >> 16) as u16).to_le_bytes());
        payload.push(20); // Length of auth plugin data (8 + 12 = 20 bytes)
        payload.extend_from_slice(&[0; 10]); // Reserved
        payload.extend_from_slice(b"nettrap!!!!!"); // Auth plugin data part 2 (12 bytes)
        payload.push(0); // null
        payload.extend_from_slice(b"mysql_native_password");
        payload.push(0); // null

        Self::wrap_packet(&payload, 0)
    }

    /// Handle client response (auth or command)
    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 5 {
            return Vec::new();
        }
        let declared_payload_len =
            data[0] as usize | ((data[1] as usize) << 8) | ((data[2] as usize) << 16);
        if declared_payload_len != data.len() - 4 {
            tracing::debug!(
                "MySQL packet length mismatch: declared={}, actual={}",
                declared_payload_len,
                data.len().saturating_sub(4)
            );
            return Vec::new();
        }

        let seq = data[3];
        let payload = &data[4..];

        if seq == 1 {
            // Handshake response (seq=1 follows server handshake seq=0)
            self.handle_login(payload, seq)
        } else {
            // Post-auth command
            self.handle_command(payload, seq)
        }
    }

    fn handle_login(&self, data: &[u8], seq: u8) -> Vec<u8> {
        // MySQL HandshakeResponse41 layout:
        //   capability_flags(4) + max_packet_size(4) + charset(1) + reserved(23) = 32 bytes
        //   Then: username (null-terminated)
        // HandshakeResponse320 (older):
        //   capability_flags(2) + max_packet_size(3) = 5 bytes
        //   Then: username (null-terminated)
        if data.len() < 4 {
            return Vec::new();
        }

        let cap_flags = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let response_seq = seq.wrapping_add(1);

        if cap_flags & CLIENT_SSL != 0 {
            tracing::warn!("MySQL client requested SSL, but MySQL-over-TLS is not implemented");
            return Self::build_error_packet(response_seq, 2026, "SSL is not supported");
        }

        let is_41 = cap_flags & CLIENT_PROTOCOL_41 != 0;

        // Calculate username start offset with proper bounds checking
        let username_start = if is_41 {
            // Protocol 4.1: 4-byte flags + 4-byte max_packet + 1-byte charset + 23-byte reserved
            if data.len() > 32 {
                if data[9..32].iter().any(|&byte| byte != 0) {
                    return Self::build_error_packet(
                        response_seq,
                        1043,
                        "Malformed handshake response",
                    );
                }
                32
            } else {
                return Self::build_error_packet(
                    response_seq,
                    1043,
                    "Malformed handshake response",
                );
            }
        } else {
            // Protocol 3.20: 2-byte flags + 3-byte max_packet
            if data.len() > 5 {
                5
            } else {
                return Self::build_error_packet(
                    response_seq,
                    1043,
                    "Malformed handshake response",
                );
            }
        };

        // Additional safety check (should never fail due to above logic)
        if username_start >= data.len() {
            return Self::build_error_packet(response_seq, 1043, "Malformed handshake response");
        }

        // Extract username (null-terminated string)
        let username_end = data[username_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| username_start + p);
        let Some(username_end) = username_end else {
            return Self::build_error_packet(response_seq, 1043, "Malformed handshake response");
        };

        // Sanity check: limit username length to prevent log injection
        let max_username_len = (username_end - username_start).min(256);
        let username =
            String::from_utf8_lossy(&data[username_start..username_start + max_username_len]);
        tracing::warn!("MySQL LOGIN attempt: user={}", username);

        // Return OK packet (let them "in" to capture more commands)
        Self::build_ok_packet(response_seq)
    }

    fn handle_command(&self, data: &[u8], seq: u8) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        let cmd = data[0];
        let response_seq = seq.wrapping_add(1);

        match cmd {
            0x03 => {
                // COM_QUERY
                if data.len() == 1 {
                    return Self::build_error_packet(response_seq, 1065, "Query was empty");
                }
                let query = String::from_utf8_lossy(&data[1..]);
                tracing::warn!("MySQL QUERY: {}", query);
                // Return empty result set
                Self::build_ok_packet(response_seq)
            }
            0x01 => {
                // COM_QUIT
                Vec::new()
            }
            0x02 => {
                // COM_INIT_DB
                if data.len() == 1 {
                    return Self::build_error_packet(response_seq, 1049, "Unknown database");
                }
                let db = String::from_utf8_lossy(&data[1..]);
                tracing::info!("MySQL USE {}", db);
                Self::build_ok_packet(response_seq)
            }
            0x04 => {
                // COM_FIELD_LIST
                Self::build_ok_packet(response_seq)
            }
            _ => {
                tracing::info!("MySQL command: 0x{:02x}", cmd);
                Self::build_ok_packet(response_seq)
            }
        }
    }

    fn build_ok_packet(seq: u8) -> Vec<u8> {
        let payload = vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]; // OK packet
        Self::wrap_packet(&payload, seq)
    }

    fn build_error_packet(seq: u8, code: u16, msg: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(0xFF); // Error marker
        payload.extend_from_slice(&code.to_le_bytes());
        payload.push(b'#');
        payload.extend_from_slice(b"28000"); // SQL state
        payload.extend_from_slice(msg.as_bytes());
        Self::wrap_packet(&payload, seq)
    }

    fn wrap_packet(payload: &[u8], seq: u8) -> Vec<u8> {
        // MySQL protocol max packet size is 16MB - 1 (0xFFFFFF)
        let max_len = 0xFFFFFF_usize;
        if payload.len() > max_len {
            tracing::warn!(
                "MySQL packet payload ({} bytes) exceeds max size ({}), truncating",
                payload.len(),
                max_len
            );
        }
        let len = payload.len().min(max_len);
        let mut packet = Vec::with_capacity(4 + len);
        packet.push((len & 0xFF) as u8);
        packet.push(((len >> 8) & 0xFF) as u8);
        packet.push(((len >> 16) & 0xFF) as u8);
        packet.push(seq);
        packet.extend_from_slice(&payload[..len]);
        packet
    }
}

impl Default for MysqlHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake_capabilities(packet: &[u8]) -> u32 {
        let payload = &packet[4..];
        let version_end = payload
            .iter()
            .position(|&byte| byte == 0)
            .expect("server version should be null-terminated");
        let lower_offset = version_end + 1 + 4 + 8 + 1;
        let lower = u16::from_le_bytes([payload[lower_offset], payload[lower_offset + 1]]) as u32;
        let upper_offset = lower_offset + 2 + 1 + 2;
        let upper = u16::from_le_bytes([payload[upper_offset], payload[upper_offset + 1]]) as u32;
        lower | (upper << 16)
    }

    fn wrap_client_packet(payload: &[u8], seq: u8) -> Vec<u8> {
        let mut packet = Vec::with_capacity(4 + payload.len());
        packet.push((payload.len() & 0xff) as u8);
        packet.push(((payload.len() >> 8) & 0xff) as u8);
        packet.push(((payload.len() >> 16) & 0xff) as u8);
        packet.push(seq);
        packet.extend_from_slice(payload);
        packet
    }

    #[test]
    fn handshake_only_advertises_supported_capabilities() {
        let handshake = MysqlHandler::new().get_handshake();
        let capabilities = handshake_capabilities(&handshake);

        assert_eq!(capabilities & CLIENT_SSL, 0);
        assert_eq!(capabilities & 0x0000_0020, 0); // CLIENT_COMPRESS
        assert_eq!(capabilities & 0x0000_0080, 0); // CLIENT_LOCAL_FILES
        assert_ne!(capabilities & CLIENT_PROTOCOL_41, 0);
        assert_ne!(capabilities & CLIENT_SECURE_CONNECTION, 0);
        assert_ne!(capabilities & CLIENT_PLUGIN_AUTH, 0);
    }

    #[test]
    fn ssl_request_is_rejected_instead_of_accepted_as_login() {
        let handler = MysqlHandler::new();
        let mut ssl_request = vec![0; 32];
        let capabilities = CLIENT_PROTOCOL_41 | CLIENT_SSL | CLIENT_SECURE_CONNECTION;
        ssl_request[..4].copy_from_slice(&capabilities.to_le_bytes());
        let response = handler.handle(&wrap_client_packet(&ssl_request, 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("SSL is not supported"));
    }

    #[test]
    fn short_malformed_login_is_not_accepted_as_ok() {
        let handler = MysqlHandler::new();
        let response = handler.handle(&wrap_client_packet(&[0x01, 0x00, 0x00], 1));

        assert!(response.is_empty());
    }

    #[test]
    fn four_byte_ssl_request_is_rejected_before_short_login_handling() {
        let handler = MysqlHandler::new();
        let response = handler.handle(&wrap_client_packet(&CLIENT_SSL.to_le_bytes(), 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("SSL is not supported"));
    }

    #[test]
    fn malformed_protocol_41_login_is_not_accepted_as_ok() {
        let handler = MysqlHandler::new();
        let response = handler.handle(&wrap_client_packet(&CLIENT_PROTOCOL_41.to_le_bytes(), 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Malformed handshake response"));
    }

    #[test]
    fn valid_non_ssl_protocol_41_login_still_gets_ok() {
        let handler = MysqlHandler::new();
        let mut login = vec![0; 32];
        let capabilities = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION;
        login[..4].copy_from_slice(&capabilities.to_le_bytes());
        login.extend_from_slice(b"root\0");

        let response = handler.handle(&wrap_client_packet(&login, 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0x00);
    }

    #[test]
    fn response_sequence_wraps_without_panic() {
        let handler = MysqlHandler::new();
        let response = handler.handle(&wrap_client_packet(&[0x03, b'S', b'E', b'L'], 255));

        assert_eq!(response[3], 0);
        assert_eq!(response[4], 0x00);
    }

    #[test]
    fn packet_header_length_must_match_captured_payload() {
        let handler = MysqlHandler::new();
        let mut packet = wrap_client_packet(&[0x03, b'S'], 2);
        packet[0] = 3;

        assert!(handler.handle(&packet).is_empty());

        let mut packet = wrap_client_packet(&[0x03, b'S'], 2);
        packet.push(b'E');

        assert!(handler.handle(&packet).is_empty());
    }

    #[test]
    fn protocol_41_login_rejects_nonzero_reserved_bytes() {
        let handler = MysqlHandler::new();
        let mut login = vec![0; 32];
        let capabilities = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION;
        login[..4].copy_from_slice(&capabilities.to_le_bytes());
        login[9] = 1;
        login.extend_from_slice(b"root\0");

        let response = handler.handle(&wrap_client_packet(&login, 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Malformed handshake response"));
    }

    #[test]
    fn login_username_must_be_null_terminated() {
        let handler = MysqlHandler::new();
        let mut login = vec![0; 32];
        let capabilities = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION;
        login[..4].copy_from_slice(&capabilities.to_le_bytes());
        login.extend_from_slice(b"root");

        let response = handler.handle(&wrap_client_packet(&login, 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Malformed handshake response"));
    }

    #[test]
    fn empty_query_and_init_db_are_rejected() {
        let handler = MysqlHandler::new();

        let empty_query = handler.handle(&wrap_client_packet(&[0x03], 2));
        assert_eq!(empty_query[3], 3);
        assert_eq!(empty_query[4], 0xff);
        assert!(String::from_utf8_lossy(&empty_query).contains("Query was empty"));

        let empty_db = handler.handle(&wrap_client_packet(&[0x02], 2));
        assert_eq!(empty_db[3], 3);
        assert_eq!(empty_db[4], 0xff);
        assert!(String::from_utf8_lossy(&empty_db).contains("Unknown database"));
    }
}
