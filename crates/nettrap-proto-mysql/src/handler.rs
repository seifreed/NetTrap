pub struct MysqlHandler {
    version: String,
    server_id: u32,
}

const DEFAULT_MYSQL_VERSION: &str = "8.0.36-0ubuntu0.22.04.1";

const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SSL: u32 = 0x0000_0800;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_CONNECT_ATTRS: u32 = 0x0010_0000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;
const SERVER_CAPABILITIES: u32 = CLIENT_LONG_PASSWORD
    | CLIENT_LONG_FLAG
    | CLIENT_CONNECT_WITH_DB
    | CLIENT_PROTOCOL_41
    | CLIENT_SECURE_CONNECTION
    | CLIENT_PLUGIN_AUTH
    | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
    | CLIENT_CONNECT_ATTRS;
const REDACTED_LOGIN_FIELD: &str = "***REDACTED***";
const REDACTED_QUERY_FIELD: &str = "***REDACTED***";

mod helpers;
pub(crate) use helpers::*;

impl MysqlHandler {
    pub fn new() -> Self {
        Self {
            version: DEFAULT_MYSQL_VERSION.to_string(),
            server_id: 1,
        }
    }

    /// Build MySQL initial handshake packet (sent on connect).
    pub fn get_handshake(&self) -> Vec<u8> {
        self.get_handshake_with_tls(false)
    }

    /// Build the initial handshake, optionally advertising `CLIENT_SSL` so a
    /// client may request a STARTTLS-style upgrade. Plain (non-TLS) MySQL
    /// listeners must keep `offer_tls = false` so behaviour is unchanged.
    pub fn get_handshake_with_tls(&self, offer_tls: bool) -> Vec<u8> {
        let caps = if offer_tls {
            SERVER_CAPABILITIES | CLIENT_SSL
        } else {
            SERVER_CAPABILITIES
        };

        let mut payload = Vec::new();
        payload.push(10); // Protocol version 10
        payload.extend_from_slice(self.version.as_bytes());
        payload.push(0); // null terminator
        payload.extend_from_slice(&self.server_id.to_le_bytes()); // Connection ID
        payload.extend_from_slice(b"nettrap!"); // Auth plugin data part 1 (8 bytes)
        payload.push(0); // Filler
        let cap_bytes = caps.to_le_bytes();
        payload.extend_from_slice(&cap_bytes[..2]);
        payload.push(0x21); // Character set (utf8)
        payload.extend_from_slice(&0x0002u16.to_le_bytes()); // Status flags
        payload.extend_from_slice(&cap_bytes[2..]);
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

        // CLIENT_SSL is no longer rejected here: a bare SSLRequest is
        // intercepted by the TCP listener and upgraded to TLS before any
        // HandshakeResponse reaches this handler, so the response we do see
        // (post-TLS) still has CLIENT_SSL set and must be parsed normally.
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

        let username_end = data[username_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| username_start + p);
        let Some(username_end) = username_end else {
            return Self::build_error_packet(response_seq, 1043, "Malformed handshake response");
        };
        if username_end == username_start {
            return Self::build_error_packet(response_seq, 1043, "Malformed handshake response");
        }
        let after_username = &data[username_end + 1..];
        if is_41 {
            if !Self::handshake_response_41_tail_is_valid(after_username, cap_flags) {
                return Self::build_error_packet(
                    response_seq,
                    1043,
                    "Malformed handshake response",
                );
            }
        } else if !after_username.is_empty() {
            return Self::build_error_packet(response_seq, 1043, "Malformed handshake response");
        }

        // Sanity check: limit username length and strip controls before logging.
        let max_username_len = (username_end - username_start).min(256);
        let username = nettrap_core::sanitize::single_line_bytes(
            &data[username_start..username_start + max_username_len],
        );
        tracing::debug!("MySQL LOGIN attempt: user={}", username);
        tracing::warn!("MySQL LOGIN attempt: user={}", REDACTED_LOGIN_FIELD);

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
                if data.len() == 1 {
                    return Self::build_error_packet(response_seq, 1065, "Query was empty");
                }
                let Some(query) = std::str::from_utf8(&data[1..]).ok() else {
                    return Self::build_error_packet(response_seq, 1064, "Malformed query");
                };
                if query.contains('\0') {
                    return Self::build_error_packet(response_seq, 1064, "Malformed query");
                }
                tracing::debug!(
                    "MySQL QUERY: {}",
                    nettrap_core::sanitize::single_line(query)
                );
                tracing::warn!("MySQL QUERY: {}", REDACTED_QUERY_FIELD);
                if query_produces_resultset(query) {
                    Self::build_single_value_resultset(response_seq, "1", "1")
                } else {
                    Self::build_ok_packet(response_seq)
                }
            }
            0x01 => {
                if data.len() != 1 {
                    return Self::build_error_packet_with_state(
                        response_seq,
                        1047,
                        "08S01",
                        "Malformed command",
                    );
                }
                Vec::new()
            }
            0x02 => {
                if data.len() == 1 {
                    return Self::build_error_packet(response_seq, 1049, "Unknown database");
                }
                let Some(db) = std::str::from_utf8(&data[1..]).ok() else {
                    return Self::build_error_packet(response_seq, 1049, "Unknown database");
                };
                if db.is_empty() || db.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
                    return Self::build_error_packet(response_seq, 1049, "Unknown database");
                }
                tracing::debug!("MySQL USE {}", nettrap_core::sanitize::single_line(db));
                tracing::info!("MySQL USE {}", REDACTED_QUERY_FIELD);
                Self::build_ok_packet(response_seq)
            }
            0x04 => {
                if Self::field_list_request_is_valid(&data[1..]) {
                    Self::build_ok_packet(response_seq)
                } else {
                    Self::build_error_packet(response_seq, 1146, "Unknown table")
                }
            }
            0x0e => {
                if data.len() != 1 {
                    return Self::build_error_packet_with_state(
                        response_seq,
                        1047,
                        "08S01",
                        "Malformed command",
                    );
                }
                Self::build_ok_packet(response_seq)
            }
            _ => {
                tracing::info!("MySQL command: 0x{:02x}", cmd);
                Self::build_error_packet_with_state(response_seq, 1047, "08S01", "Unknown command")
            }
        }
    }

    fn field_list_request_is_valid(data: &[u8]) -> bool {
        let Some(table_end) = data.iter().position(|&byte| byte == 0) else {
            return false;
        };
        if table_end == 0 {
            return false;
        }

        let table = &data[..table_end];
        let wildcard = &data[table_end + 1..];
        Self::field_list_token_is_safe(table) && Self::field_list_token_is_safe(wildcard)
    }

    fn handshake_response_41_tail_is_valid(mut tail: &[u8], cap_flags: u32) -> bool {
        tail = if cap_flags & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            let Some((auth_len, len_bytes)) = Self::parse_lenenc_int(tail) else {
                return false;
            };
            let Some(auth_end) = len_bytes.checked_add(auth_len) else {
                return false;
            };
            let Some(rest) = tail.get(auth_end..) else {
                return false;
            };
            rest
        } else if cap_flags & CLIENT_SECURE_CONNECTION != 0 {
            let Some((&auth_len, rest)) = tail.split_first() else {
                return false;
            };
            let auth_len = auth_len as usize;
            let Some(rest) = rest.get(auth_len..) else {
                return false;
            };
            rest
        } else {
            let Some(auth_end) = tail.iter().position(|&byte| byte == 0) else {
                return false;
            };
            &tail[auth_end + 1..]
        };

        if cap_flags & CLIENT_CONNECT_WITH_DB != 0 {
            let Some(db_end) = tail.iter().position(|&byte| byte == 0) else {
                return false;
            };
            tail = &tail[db_end + 1..];
        }

        if cap_flags & CLIENT_PLUGIN_AUTH != 0 {
            let Some(plugin_end) = tail.iter().position(|&byte| byte == 0) else {
                return false;
            };
            let plugin = &tail[..plugin_end];
            if plugin.is_empty()
                || plugin.len() > 128
                || !plugin
                    .iter()
                    .all(|byte| byte.is_ascii_graphic() && *byte != b'\\')
            {
                return false;
            }
            tail = &tail[plugin_end + 1..];
        }

        if cap_flags & CLIENT_CONNECT_ATTRS != 0 {
            let Some((attrs_len, len_bytes)) = Self::parse_lenenc_int(tail) else {
                return false;
            };
            let Some(attrs_end) = len_bytes.checked_add(attrs_len) else {
                return false;
            };
            let Some(attrs) = tail.get(len_bytes..attrs_end) else {
                return false;
            };
            if !Self::connect_attrs_are_well_formed(attrs) {
                return false;
            }
            tail = &tail[attrs_end..];
        }

        tail.is_empty()
    }

    fn parse_lenenc_int(data: &[u8]) -> Option<(usize, usize)> {
        let first = *data.first()?;
        match first {
            0x00..=0xfa => Some((first as usize, 1)),
            0xfc => {
                let bytes = data.get(1..3)?;
                let value = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
                (value >= 251).then_some((value, 3))
            }
            0xfd => {
                let bytes = data.get(1..4)?;
                let value =
                    bytes[0] as usize | ((bytes[1] as usize) << 8) | ((bytes[2] as usize) << 16);
                (value >= 0x1_0000).then_some((value, 4))
            }
            0xfe => {
                let bytes = data.get(1..9)?;
                let value = u64::from_le_bytes(bytes.try_into().ok()?);
                let value = usize::try_from(value).ok()?;
                (value >= 0x100_0000).then_some((value, 9))
            }
            _ => None,
        }
    }

    fn connect_attrs_are_well_formed(mut attrs: &[u8]) -> bool {
        while !attrs.is_empty() {
            let Some((key_len, key_len_bytes)) = Self::parse_lenenc_int(attrs) else {
                return false;
            };
            let Some(key_end) = key_len_bytes.checked_add(key_len) else {
                return false;
            };
            let Some(rest) = attrs.get(key_end..) else {
                return false;
            };
            let key = &attrs[key_len_bytes..key_end];
            if key.is_empty() || !Self::field_list_token_is_safe(key) {
                return false;
            }

            let Some((value_len, value_len_bytes)) = Self::parse_lenenc_int(rest) else {
                return false;
            };
            let Some(value_end) = value_len_bytes.checked_add(value_len) else {
                return false;
            };
            let Some(next) = rest.get(value_end..) else {
                return false;
            };
            let value = &rest[value_len_bytes..value_end];
            if !Self::connect_attr_value_is_safe(value) {
                return false;
            }
            attrs = next;
        }

        true
    }

    fn field_list_token_is_safe(value: &[u8]) -> bool {
        match std::str::from_utf8(value) {
            Ok(text) => text
                .chars()
                .all(|ch| !ch.is_control() && (!ch.is_whitespace() || ch == ' ')),
            Err(_) => value.iter().all(|byte| {
                !byte.is_ascii_control()
                    && *byte != b'\n'
                    && *byte != b'\r'
                    && *byte != b'\t'
                    && *byte != 0x0b
                    && *byte != 0x0c
            }),
        }
    }

    fn connect_attr_value_is_safe(value: &[u8]) -> bool {
        Self::field_list_token_is_safe(value)
    }

    fn build_ok_packet(seq: u8) -> Vec<u8> {
        let payload = vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]; // OK packet
        Self::wrap_packet(&payload, seq)
    }

    fn build_error_packet(seq: u8, code: u16, msg: &str) -> Vec<u8> {
        Self::build_error_packet_with_state(seq, code, "28000", msg)
    }

    fn build_error_packet_with_state(seq: u8, code: u16, state: &str, msg: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(0xFF); // Error marker
        payload.extend_from_slice(&code.to_le_bytes());
        payload.push(b'#');
        payload.extend_from_slice(state.as_bytes());
        payload.extend_from_slice(msg.as_bytes());
        Self::wrap_packet(&payload, seq)
    }

    fn build_single_value_resultset(seq: u8, column_name: &str, value: &str) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&Self::wrap_packet(&[0x01], seq));

        let mut column = Vec::new();
        push_lenenc_str(&mut column, b"def");
        push_lenenc_str(&mut column, b"");
        push_lenenc_str(&mut column, b"");
        push_lenenc_str(&mut column, b"");
        push_lenenc_str(&mut column, column_name.as_bytes());
        push_lenenc_str(&mut column, b"");
        column.push(0x0c);
        column.extend_from_slice(&33u16.to_le_bytes());
        column.extend_from_slice(&1024u32.to_le_bytes());
        column.push(0xfd);
        column.extend_from_slice(&0u16.to_le_bytes());
        column.push(0);
        column.extend_from_slice(&0u16.to_le_bytes());
        response.extend_from_slice(&Self::wrap_packet(&column, seq.wrapping_add(1)));

        response.extend_from_slice(&Self::wrap_packet(
            &[0xfe, 0x00, 0x00, 0x02, 0x00],
            seq.wrapping_add(2),
        ));

        let mut row = Vec::new();
        push_lenenc_str(&mut row, value.as_bytes());
        response.extend_from_slice(&Self::wrap_packet(&row, seq.wrapping_add(3)));
        response.extend_from_slice(&Self::wrap_packet(
            &[0xfe, 0x00, 0x00, 0x02, 0x00],
            seq.wrapping_add(4),
        ));

        response
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
        packet.extend_from_slice(&len.to_le_bytes()[..3]);
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

    const LOG_FIELD_PREVIEW_CHARS: usize = 240;

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
        packet.extend_from_slice(&payload.len().to_le_bytes()[..3]);
        packet.push(seq);
        packet.extend_from_slice(payload);
        packet
    }

    fn protocol_41_login(capabilities: u32) -> Vec<u8> {
        let mut login = vec![0; 32];
        login[..4].copy_from_slice(&capabilities.to_le_bytes());
        login.extend_from_slice(b"root\0");
        login.push(3);
        login.extend_from_slice(b"abc");
        if capabilities & CLIENT_CONNECT_WITH_DB != 0 {
            login.extend_from_slice(b"nettrap\0");
        }
        if capabilities & CLIENT_PLUGIN_AUTH != 0 {
            login.extend_from_slice(b"mysql_native_password\0");
        }
        login
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
        assert_ne!(capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA, 0);
        assert_ne!(capabilities & CLIENT_CONNECT_ATTRS, 0);
        assert_ne!(capabilities & CLIENT_CONNECT_WITH_DB, 0);
    }

    #[test]
    fn configured_version_accepts_long_versions_within_budget() {
        let version = format!("8.0.36-custom+{}", "build".repeat(40));
        let handshake = MysqlHandler {
            version: version.clone(),
            server_id: 1,
        }
        .get_handshake();

        let handshake_text = String::from_utf8_lossy(&handshake);
        assert!(
            handshake_text.contains(&version),
            "expected configured MySQL version in handshake"
        );
        assert!(
            !handshake_text.contains(DEFAULT_MYSQL_VERSION),
            "long but valid version should not fall back to default"
        );
    }

    #[test]
    fn handshake_with_tls_advertises_client_ssl() {
        let handshake = MysqlHandler::new().get_handshake_with_tls(true);
        let capabilities = handshake_capabilities(&handshake);

        assert_ne!(capabilities & CLIENT_SSL, 0);
        assert_ne!(capabilities & CLIENT_PROTOCOL_41, 0);
        assert_ne!(capabilities & CLIENT_SECURE_CONNECTION, 0);
        assert_ne!(capabilities & CLIENT_PLUGIN_AUTH, 0);
    }

    #[test]
    fn handshake_with_tls_false_matches_default() {
        assert_eq!(
            MysqlHandler::new().get_handshake_with_tls(false),
            MysqlHandler::new().get_handshake()
        );
    }

    #[test]
    fn client_ssl_handshake_response_is_accepted_post_tls() {
        // After the TLS upgrade the client re-sends a full HandshakeResponse
        // that still has CLIENT_SSL set, plus a username. It must now be
        // accepted (OK), not rejected.
        let handler = MysqlHandler::new();
        let capabilities =
            CLIENT_PROTOCOL_41 | CLIENT_SSL | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
        let login = protocol_41_login(capabilities);
        let response = handler.handle(&wrap_client_packet(&login, 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0x00);
    }

    #[test]
    fn short_malformed_login_is_not_accepted_as_ok() {
        let handler = MysqlHandler::new();
        let response = handler.handle(&wrap_client_packet(&[0x01, 0x00, 0x00], 1));

        assert!(response.is_empty());
    }

    #[test]
    fn bare_four_byte_ssl_request_falls_through_to_malformed() {
        // The real bare SSLRequest is intercepted by the TCP listener before
        // it reaches the handler; if a 4-byte CLIENT_SSL frame ever does
        // reach handle() it is just an incomplete HandshakeResponse.
        let handler = MysqlHandler::new();
        let response = handler.handle(&wrap_client_packet(&CLIENT_SSL.to_le_bytes(), 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Malformed handshake response"));
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
        let capabilities = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
        let login = protocol_41_login(capabilities);

        let response = handler.handle(&wrap_client_packet(&login, 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0x00);
    }

    #[test]
    fn protocol_41_login_accepts_database_and_connection_attrs() {
        let handler = MysqlHandler::new();
        let capabilities = CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_CONNECT_WITH_DB
            | CLIENT_PLUGIN_AUTH
            | CLIENT_CONNECT_ATTRS;
        let mut login = protocol_41_login(capabilities);
        let mut attrs = Vec::new();
        push_lenenc_str(&mut attrs, b"_client_name");
        push_lenenc_str(&mut attrs, b"nettrap-test");
        push_lenenc_str(&mut login, &attrs);

        let response = handler.handle(&wrap_client_packet(&login, 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0x00);
    }

    #[test]
    fn protocol_41_login_rejects_c1_controls_in_connection_attrs() {
        let handler = MysqlHandler::new();
        let capabilities = CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH
            | CLIENT_CONNECT_ATTRS;
        let mut login = protocol_41_login(capabilities);
        let mut attrs = Vec::new();
        push_lenenc_str(&mut attrs, "_client\u{009f}name".as_bytes());
        push_lenenc_str(&mut attrs, b"nettrap-test");
        push_lenenc_str(&mut login, &attrs);

        let response = handler.handle(&wrap_client_packet(&login, 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Malformed handshake response"),);
    }

    #[test]
    fn protocol_41_login_accepts_non_utf8_connection_attrs() {
        let handler = MysqlHandler::new();
        let capabilities = CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH
            | CLIENT_CONNECT_ATTRS;
        let mut login = protocol_41_login(capabilities);
        let mut attrs = Vec::new();
        push_lenenc_str(&mut attrs, b"_client_\xffname");
        push_lenenc_str(&mut attrs, b"nettrap-\xfe");
        push_lenenc_str(&mut login, &attrs);

        let response = handler.handle(&wrap_client_packet(&login, 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0x00);
    }

    #[test]
    fn protocol_41_login_rejects_truncated_auth_response_tail() {
        let handler = MysqlHandler::new();
        let capabilities = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
        let mut login = vec![0; 32];
        login[..4].copy_from_slice(&capabilities.to_le_bytes());
        login.extend_from_slice(b"root\0");
        login.push(4);
        login.extend_from_slice(b"abc");

        let response = handler.handle(&wrap_client_packet(&login, 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Malformed handshake response"));
    }

    #[test]
    fn protocol_41_login_rejects_non_minimal_lenenc_auth_response_length() {
        let handler = MysqlHandler::new();
        let capabilities =
            CLIENT_PROTOCOL_41 | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA | CLIENT_PLUGIN_AUTH;
        let mut login = vec![0; 32];
        login[..4].copy_from_slice(&capabilities.to_le_bytes());
        login.extend_from_slice(b"root\0");
        login.extend_from_slice(&[0xfc, 0x01, 0x00, b'a']);
        login.extend_from_slice(b"mysql_native_password\0");

        let response = handler.handle(&wrap_client_packet(&login, 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Malformed handshake response"));
    }

    #[test]
    fn protocol_41_login_rejects_non_minimal_lenenc_connection_attrs_length() {
        let handler = MysqlHandler::new();
        let capabilities = CLIENT_PROTOCOL_41
            | CLIENT_SECURE_CONNECTION
            | CLIENT_PLUGIN_AUTH
            | CLIENT_CONNECT_ATTRS;
        let mut login = protocol_41_login(capabilities);
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&[0xfc, 0x0c, 0x00]);
        attrs.extend_from_slice(b"_client_name");
        push_lenenc_str(&mut attrs, b"nettrap");
        push_lenenc_str(&mut login, &attrs);

        let response = handler.handle(&wrap_client_packet(&login, 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Malformed handshake response"));
    }

    #[test]
    fn response_sequence_wraps_without_panic() {
        let handler = MysqlHandler::new();
        let response = handler.handle(&wrap_client_packet(&[0x03, b'D', b'O', b' ', b'1'], 255));

        assert_eq!(response[3], 0);
        assert_eq!(response[4], 0x00);
    }

    #[test]
    fn select_query_returns_minimal_resultset_instead_of_ok_packet() {
        let handler = MysqlHandler::new();
        let response = handler.handle(&wrap_client_packet(
            &[0x03, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'1'],
            2,
        ));

        assert_eq!(response[3], 3);
        assert_eq!(response[4], 0x01);
        assert!(response.windows(3).any(|window| window == b"def"));
        assert!(response.windows(2).any(|window| window == [0x01, b'1']));
    }

    #[test]
    fn select_query_rejects_unicode_whitespace_separator() {
        let handler = MysqlHandler::new();
        let mut query = Vec::from([0x03]);
        query.extend_from_slice("SELECT\u{00a0}1".as_bytes());

        let response = handler.handle(&wrap_client_packet(&query, 2));

        assert_eq!(response[4], 0x00);
        assert!(!response.windows(3).any(|window| window == b"def"));
    }

    #[test]
    fn select_query_with_leading_comment_still_returns_resultset() {
        let handler = MysqlHandler::new();
        let response = handler.handle(&wrap_client_packet(
            b"\x03/* leading comment */ SELECT 1",
            2,
        ));

        assert_eq!(response[3], 3);
        assert_eq!(response[4], 0x01);
    }

    #[test]
    fn select_query_with_leading_version_comment_still_returns_resultset() {
        let handler = MysqlHandler::new();
        let response = handler.handle(&wrap_client_packet(b"\x03/*!40101 SELECT 1 */", 2));

        assert_eq!(response[3], 3);
        assert_eq!(response[4], 0x01);
    }

    #[test]
    fn ping_gets_ok_but_unknown_commands_return_mysql_error() {
        let handler = MysqlHandler::new();

        let ping = handler.handle(&wrap_client_packet(&[0x0e], 2));
        assert_eq!(ping[3], 3);
        assert_eq!(ping[4], 0x00);

        let malformed_ping = handler.handle(&wrap_client_packet(&[0x0e, b'X'], 2));
        assert_eq!(malformed_ping[3], 3);
        assert_eq!(malformed_ping[4], 0xff);
        assert!(String::from_utf8_lossy(&malformed_ping).contains("Malformed command"));

        let malformed_quit = handler.handle(&wrap_client_packet(&[0x01, b'X'], 2));
        assert_eq!(malformed_quit[3], 3);
        assert_eq!(malformed_quit[4], 0xff);
        assert!(String::from_utf8_lossy(&malformed_quit).contains("Malformed command"));

        let unknown = handler.handle(&wrap_client_packet(&[0xff], 2));
        assert_eq!(unknown[3], 3);
        assert_eq!(unknown[4], 0xff);
        assert!(String::from_utf8_lossy(&unknown).contains("Unknown command"));
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
        let capabilities = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
        login[..4].copy_from_slice(&capabilities.to_le_bytes());
        login[9] = 1;
        login.extend_from_slice(b"root\0");
        login.push(0);
        login.extend_from_slice(b"mysql_native_password\0");

        let response = handler.handle(&wrap_client_packet(&login, 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Malformed handshake response"));
    }

    #[test]
    fn login_username_must_be_null_terminated() {
        let handler = MysqlHandler::new();
        let mut login = vec![0; 32];
        let capabilities = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
        login[..4].copy_from_slice(&capabilities.to_le_bytes());
        login.extend_from_slice(b"root");

        let response = handler.handle(&wrap_client_packet(&login, 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Malformed handshake response"));
    }

    #[test]
    fn login_rejects_trailing_bytes_after_username() {
        let handler = MysqlHandler::new();
        let mut login = vec![0; 32];
        let capabilities = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
        login[..4].copy_from_slice(&capabilities.to_le_bytes());
        login.extend_from_slice(b"root\0");
        login.push(0);
        login.extend_from_slice(b"mysql_native_password\0junk");

        let response = handler.handle(&wrap_client_packet(&login, 1));

        assert_eq!(response[3], 2);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Malformed handshake response"));
    }

    #[test]
    fn protocol_41_login_rejects_empty_username() {
        let handler = MysqlHandler::new();
        let mut login = vec![0; 32];
        let capabilities = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
        login[..4].copy_from_slice(&capabilities.to_le_bytes());
        login.push(0);
        login.push(0);
        login.extend_from_slice(b"mysql_native_password\\0");

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

    #[test]
    fn field_list_requires_null_terminated_table_name() {
        let handler = MysqlHandler::new();

        let valid = handler.handle(&wrap_client_packet(b"\x04users\0%", 2));
        assert_eq!(valid[3], 3);
        assert_eq!(valid[4], 0x00);

        for payload in [
            b"\x04".as_slice(),
            b"\x04users".as_slice(),
            b"\x04\0%".as_slice(),
        ] {
            let response = handler.handle(&wrap_client_packet(payload, 2));

            assert_eq!(response[3], 3);
            assert_eq!(response[4], 0xff);
            assert!(String::from_utf8_lossy(&response).contains("Unknown table"));
        }
    }

    #[test]
    fn field_list_accepts_non_utf8_table_and_wildcard_bytes() {
        let handler = MysqlHandler::new();

        let response = handler.handle(&wrap_client_packet(b"\x04us\xffers\0%\x80", 2));

        assert_eq!(response[3], 3);
        assert_eq!(response[4], 0x00);
    }

    #[test]
    fn query_rejects_invalid_utf8() {
        let handler = MysqlHandler::new();

        let response = handler.handle(&wrap_client_packet(&[0x03, b'S', b'E', 0xff], 2));

        assert_eq!(response[3], 3);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Malformed query"));
    }

    #[test]
    fn query_rejects_embedded_nul_bytes() {
        let handler = MysqlHandler::new();

        let response = handler.handle(&wrap_client_packet(&[0x03, b'S', 0x00, b'E', b'L'], 2));

        assert_eq!(response[3], 3);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Malformed query"));
    }

    #[test]
    fn init_db_rejects_invalid_utf8() {
        let handler = MysqlHandler::new();

        let response = handler.handle(&wrap_client_packet(&[0x02, b'm', b'y', 0xff], 2));

        assert_eq!(response[3], 3);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Unknown database"));
    }

    #[test]
    fn init_db_rejects_control_bytes() {
        let handler = MysqlHandler::new();

        let response = handler.handle(&wrap_client_packet(&[0x02, b'm', b'y', 0, b'd', b'b'], 2));

        assert_eq!(response[3], 3);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Unknown database"));
    }

    #[test]
    fn init_db_rejects_c1_controls() {
        let handler = MysqlHandler::new();
        let mut db = vec![0x02];
        db.extend_from_slice("my\u{009f}db".as_bytes());

        let response = handler.handle(&wrap_client_packet(&db, 2));

        assert_eq!(response[3], 3);
        assert_eq!(response[4], 0xff);
        assert!(String::from_utf8_lossy(&response).contains("Unknown database"));
    }

    #[test]
    fn init_db_rejects_whitespace() {
        let handler = MysqlHandler::new();

        for name in ["my db", "my\tdb", "my\u{00a0}db"] {
            let mut db = vec![0x02];
            db.extend_from_slice(name.as_bytes());

            let response = handler.handle(&wrap_client_packet(&db, 2));

            assert_eq!(response[3], 3);
            assert_eq!(response[4], 0xff);
            assert!(String::from_utf8_lossy(&response).contains("Unknown database"));
        }
    }

    #[test]
    fn log_fields_are_single_line() {
        assert_eq!(
            nettrap_core::sanitize::single_line_bytes(b"root\r\nadmin\x1b"),
            "root  admin "
        );
        assert_eq!(
            nettrap_core::sanitize::single_line("SELECT\r\n1\t--\x1b"),
            "SELECT  1 -- "
        );

        let long = "a".repeat(LOG_FIELD_PREVIEW_CHARS + 1);
        assert_eq!(
            nettrap_core::sanitize::single_line(&long).len(),
            LOG_FIELD_PREVIEW_CHARS
        );
    }

    #[test]
    fn lenenc_str_encodes_all_length_ranges() {
        let mut buf = Vec::new();
        push_lenenc_str(&mut buf, b"ab");
        assert_eq!(buf, vec![2, b'a', b'b']);

        // 1-byte length boundary: 250 fits in the single-byte form.
        let mut buf = Vec::new();
        push_lenenc_str(&mut buf, &vec![0u8; 250]);
        assert_eq!(buf[0], 250);
        assert_eq!(buf.len(), 1 + 250);

        // 2-byte form (0xfc) for 251..=65535.
        let mut buf = Vec::new();
        push_lenenc_str(&mut buf, &vec![0u8; 251]);
        assert_eq!(buf[0], 0xfc);
        assert_eq!(&buf[1..3], &251u16.to_le_bytes());
        assert_eq!(buf.len(), 3 + 251);

        // 3-byte form (0xfd) for 65536..=16M-1.
        let mut buf = Vec::new();
        push_lenenc_str(&mut buf, &vec![0u8; 0x1_0000]);
        assert_eq!(buf[0], 0xfd);
        assert_eq!(&buf[1..4], &[0x00, 0x00, 0x01]);
        assert_eq!(buf.len(), 4 + 0x1_0000);

        // 8-byte form (0xfe) for >= 16M.
        let mut buf = Vec::new();
        push_lenenc_str(&mut buf, &vec![0u8; 0x100_0000]);
        assert_eq!(buf[0], 0xfe);
        assert_eq!(&buf[1..9], &(0x100_0000u64).to_le_bytes());
        assert_eq!(buf.len(), 9 + 0x100_0000);
    }
}
