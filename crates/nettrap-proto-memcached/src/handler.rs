pub struct MemcachedHandler;

impl MemcachedHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(data);
        let cmd = text.trim();

        if cmd.starts_with("stats") {
            tracing::info!("MEMCACHED stats request");
            let stats = "STAT pid 1\r\nSTAT uptime 86400\r\nSTAT time 1704067200\r\nSTAT version 1.6.22\r\nSTAT curr_items 0\r\nSTAT total_items 0\r\nSTAT bytes 0\r\nSTAT curr_connections 1\r\nSTAT total_connections 1\r\nEND\r\n";
            stats.as_bytes().to_vec()
        } else if cmd.starts_with("get ") {
            tracing::info!("MEMCACHED get: {}", cmd);
            b"END\r\n".to_vec()
        } else if cmd.starts_with("set ")
            || cmd.starts_with("add ")
            || cmd.starts_with("replace ")
        {
            tracing::warn!(
                "MEMCACHED write attempt: {}",
                cmd.lines().next().unwrap_or(cmd)
            );
            b"STORED\r\n".to_vec()
        } else if cmd.starts_with("delete ") {
            b"DELETED\r\n".to_vec()
        } else if cmd.starts_with("flush_all") {
            tracing::warn!("MEMCACHED flush_all attempt");
            b"OK\r\n".to_vec()
        } else if cmd.starts_with("version") {
            b"VERSION 1.6.22\r\n".to_vec()
        } else if cmd.starts_with("quit") {
            Vec::new()
        } else {
            // Check for binary protocol (0x80 = request magic)
            if !data.is_empty() && data[0] == 0x80 {
                tracing::info!("MEMCACHED binary protocol request");
                self.handle_binary(data)
            } else {
                b"ERROR\r\n".to_vec()
            }
        }
    }

    fn handle_binary(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 24 {
            return Vec::new();
        }
        let opcode = data[1];
        tracing::info!("MEMCACHED binary opcode: 0x{:02x}", opcode);
        // Minimal binary response header
        let mut resp = vec![0x81]; // Response magic
        resp.push(opcode);
        resp.extend_from_slice(&[0; 22]); // Rest of header (zeros = success)
        resp
    }
}

impl Default for MemcachedHandler {
    fn default() -> Self {
        Self::new()
    }
}
