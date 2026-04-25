pub struct MemcachedHandler;

impl MemcachedHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(data);
        let cmd = text.trim();
        let verb = cmd
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let has_args = cmd.split_whitespace().nth(1).is_some();

        if verb == "stats" {
            tracing::info!("MEMCACHED stats request");
            let stats = "STAT pid 1\r\nSTAT uptime 86400\r\nSTAT time 1704067200\r\nSTAT version 1.6.22\r\nSTAT curr_items 0\r\nSTAT total_items 0\r\nSTAT bytes 0\r\nSTAT curr_connections 1\r\nSTAT total_connections 1\r\nEND\r\n";
            stats.as_bytes().to_vec()
        } else if verb == "get" && has_args {
            tracing::info!("MEMCACHED get: {}", cmd);
            b"END\r\n".to_vec()
        } else if matches!(verb.as_str(), "set" | "add" | "replace") && has_args {
            tracing::warn!(
                "MEMCACHED write attempt: {}",
                cmd.lines().next().unwrap_or(cmd)
            );
            b"STORED\r\n".to_vec()
        } else if verb == "delete" && has_args {
            b"DELETED\r\n".to_vec()
        } else if verb == "flush_all" {
            tracing::warn!("MEMCACHED flush_all attempt");
            b"OK\r\n".to_vec()
        } else if verb == "version" {
            b"VERSION 1.6.22\r\n".to_vec()
        } else if verb == "quit" {
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
        // Memcached binary protocol header is 24 bytes
        if data.len() < 24 {
            return Vec::new();
        }

        // Validate magic byte (0x80 = request)
        if data[0] != 0x80 {
            return Vec::new();
        }

        // Extract body length (bytes 8-11) and validate full packet presence
        let body_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let total_len = 24usize + body_len;
        if data.len() < total_len {
            // Incomplete packet - wait for more data
            return Vec::new();
        }

        let opcode = data[1];
        tracing::info!(
            "MEMCACHED binary opcode: 0x{:02x}, body_len: {}",
            opcode,
            body_len
        );

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixed_text_verbs_are_not_accepted() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"statsfoo\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"versionx\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"flush_all_now\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"quitnow\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"get\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"set\r\n"), b"ERROR\r\n");
    }

    #[test]
    fn exact_text_verbs_still_work() {
        let handler = MemcachedHandler::new();

        assert!(handler.handle(b"stats\r\n").starts_with(b"STAT pid "));
        assert_eq!(handler.handle(b"version\r\n"), b"VERSION 1.6.22\r\n");
        assert_eq!(handler.handle(b"flush_all\r\n"), b"OK\r\n");
        assert!(handler.handle(b"quit\r\n").is_empty());
    }
}
