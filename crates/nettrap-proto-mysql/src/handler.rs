pub struct MysqlHandler {
    version: String,
    server_id: u32,
}

impl MysqlHandler {
    pub fn new() -> Self {
        Self { version: "8.0.36-0ubuntu0.22.04.1".to_string(), server_id: 1 }
    }
    pub fn with_version(mut self, v: impl Into<String>) -> Self { self.version = v.into(); self }

    /// Build MySQL initial handshake packet (sent on connect)
    pub fn get_handshake(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(10); // Protocol version 10
        payload.extend_from_slice(self.version.as_bytes());
        payload.push(0); // null terminator
        payload.extend_from_slice(&self.server_id.to_le_bytes()); // Connection ID
        payload.extend_from_slice(b"nettrap!"); // Auth plugin data part 1 (8 bytes)
        payload.push(0); // Filler
        // Capability flags (lower 2 bytes)
        payload.extend_from_slice(&0xFFFFu16.to_le_bytes());
        payload.push(0x21); // Character set (utf8)
        payload.extend_from_slice(&0x0002u16.to_le_bytes()); // Status flags
        // Capability flags (upper 2 bytes)
        payload.extend_from_slice(&0x81FFu16.to_le_bytes());
        payload.push(21); // Length of auth plugin data
        payload.extend_from_slice(&[0; 10]); // Reserved
        payload.extend_from_slice(b"nettrap!!!!!"); // Auth plugin data part 2 (12 bytes)
        payload.push(0); // null
        payload.extend_from_slice(b"mysql_native_password");
        payload.push(0); // null

        Self::wrap_packet(&payload, 0)
    }

    /// Handle client response (auth or command)
    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 5 { return Vec::new(); }
        let seq = data[3];
        let payload = &data[4..];

        if seq == 1 {
            // Login attempt
            self.handle_login(payload, seq)
        } else {
            // Command
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
        if data.len() > 4 {
            let cap_flags = u16::from_le_bytes([data[0], data[1]]);
            let is_41 = cap_flags & 0x0200 != 0; // CLIENT_PROTOCOL_41
            let username_start = if is_41 && data.len() > 32 { 32 } else if data.len() > 5 { 5 } else { data.len() };
            if username_start < data.len() {
                let username_end = data[username_start..].iter().position(|&b| b == 0)
                    .map(|p| username_start + p).unwrap_or(data.len());
                let username = String::from_utf8_lossy(&data[username_start..username_end]);
                tracing::warn!("MySQL LOGIN attempt: user={}", username);
            }
        }
        // Return OK packet (let them "in" to capture more commands)
        Self::build_ok_packet(seq + 1)
    }

    fn handle_command(&self, data: &[u8], seq: u8) -> Vec<u8> {
        if data.is_empty() { return Vec::new(); }
        let cmd = data[0];

        match cmd {
            0x03 => { // COM_QUERY
                let query = String::from_utf8_lossy(&data[1..]);
                tracing::warn!("MySQL QUERY: {}", query);
                // Return empty result set
                Self::build_ok_packet(seq + 1)
            }
            0x01 => { // COM_QUIT
                Vec::new()
            }
            0x02 => { // COM_INIT_DB
                let db = String::from_utf8_lossy(&data[1..]);
                tracing::info!("MySQL USE {}", db);
                Self::build_ok_packet(seq + 1)
            }
            0x04 => { // COM_FIELD_LIST
                Self::build_ok_packet(seq + 1)
            }
            _ => {
                tracing::info!("MySQL command: 0x{:02x}", cmd);
                Self::build_ok_packet(seq + 1)
            }
        }
    }

    fn build_ok_packet(seq: u8) -> Vec<u8> {
        let payload = vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]; // OK packet
        Self::wrap_packet(&payload, seq)
    }

    fn _build_error_packet(seq: u8, code: u16, msg: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(0xFF); // Error marker
        payload.extend_from_slice(&code.to_le_bytes());
        payload.push(b'#');
        payload.extend_from_slice(b"28000"); // SQL state
        payload.extend_from_slice(msg.as_bytes());
        Self::wrap_packet(&payload, seq)
    }

    fn wrap_packet(payload: &[u8], seq: u8) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut packet = Vec::with_capacity(4 + payload.len());
        packet.push((len & 0xFF) as u8);
        packet.push(((len >> 8) & 0xFF) as u8);
        packet.push(((len >> 16) & 0xFF) as u8);
        packet.push(seq);
        packet.extend_from_slice(payload);
        packet
    }
}

impl Default for MysqlHandler { fn default() -> Self { Self::new() } }
