pub struct PostgresHandler {
    version: String,
}

impl PostgresHandler {
    pub fn new() -> Self {
        Self {
            version: "16.2".to_string(),
        }
    }

    pub fn get_handshake_response(&self) -> Vec<u8> {
        // PostgreSQL sends 'R' authentication request
        let mut resp = Vec::new();
        resp.push(b'R'); // Auth request
        resp.extend_from_slice(&8u32.to_be_bytes()); // Length
        resp.extend_from_slice(&0u32.to_be_bytes()); // AuthenticationOk
        // Ready for query
        resp.push(b'Z');
        resp.extend_from_slice(&5u32.to_be_bytes());
        resp.push(b'I'); // Idle
        resp
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        match data[0] {
            b'Q' => {
                // Simple query
                if data.len() < 6 {
                    return Vec::new();
                }
                let query = String::from_utf8_lossy(&data[5..]);
                tracing::warn!("POSTGRES QUERY: {}", query);
                // CommandComplete + ReadyForQuery
                let mut resp = Vec::new();
                let tag = b"SELECT 0";
                resp.push(b'C');
                resp.extend_from_slice(&((4 + tag.len() + 1) as u32).to_be_bytes());
                resp.extend_from_slice(tag);
                resp.push(0);
                resp.push(b'Z');
                resp.extend_from_slice(&5u32.to_be_bytes());
                resp.push(b'I');
                resp
            }
            b'X' => Vec::new(), // Terminate
            _ if data.len() >= 4 => {
                // Startup message (no type byte, starts with length)
                let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                if len > 8 && data.len() >= 8 {
                    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                    tracing::info!("POSTGRES startup: version=0x{:08x}", version);
                    if version == 196608 {
                        // 3.0
                        // Parse user/database from key=value pairs
                        let params = String::from_utf8_lossy(&data[8..]);
                        tracing::info!("POSTGRES params: {}", params.replace('\0', " "));
                    }
                }
                self.get_handshake_response()
            }
            _ => Vec::new(),
        }
    }
}

impl Default for PostgresHandler {
    fn default() -> Self {
        Self::new()
    }
}
