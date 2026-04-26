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
        } else if is_storage_verb(&verb) {
            if storage_command_is_complete(data, &verb) {
                tracing::warn!(
                    "MEMCACHED write attempt: {}",
                    cmd.lines().next().unwrap_or(cmd)
                );
                b"STORED\r\n".to_vec()
            } else {
                b"ERROR\r\n".to_vec()
            }
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

fn is_storage_verb(verb: &str) -> bool {
    matches!(
        verb,
        "set" | "add" | "replace" | "append" | "prepend" | "cas"
    )
}

fn storage_command_is_complete(data: &[u8], verb: &str) -> bool {
    let Some(header_end) = find_crlf(data) else {
        return false;
    };
    let Ok(header) = std::str::from_utf8(&data[..header_end]) else {
        return false;
    };

    let parts: Vec<&str> = header.split_whitespace().collect();
    let required_parts = if verb == "cas" { 6 } else { 5 };
    if parts.len() < required_parts || parts.len() > required_parts + 1 {
        return false;
    }
    if !parts[0].eq_ignore_ascii_case(verb) || parts[1].is_empty() {
        return false;
    }
    if parts.len() == required_parts + 1 && !parts[required_parts].eq_ignore_ascii_case("noreply") {
        return false;
    }
    if parts[2].parse::<u32>().is_err() || parts[3].parse::<i64>().is_err() {
        return false;
    }
    let Ok(body_len) = parts[4].parse::<usize>() else {
        return false;
    };
    if verb == "cas" && parts[5].parse::<u64>().is_err() {
        return false;
    }

    let body_start = header_end + 2;
    let Some(body_end) = body_start.checked_add(body_len) else {
        return false;
    };
    let Some(packet_end) = body_end.checked_add(2) else {
        return false;
    };
    packet_end == data.len() && data.get(body_end..packet_end) == Some(&b"\r\n"[..])
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|window| window == b"\r\n")
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
        assert_eq!(handler.handle(b"set key\r\n"), b"ERROR\r\n");
    }

    #[test]
    fn exact_text_verbs_still_work() {
        let handler = MemcachedHandler::new();

        assert!(handler.handle(b"stats\r\n").starts_with(b"STAT pid "));
        assert_eq!(handler.handle(b"version\r\n"), b"VERSION 1.6.22\r\n");
        assert_eq!(handler.handle(b"flush_all\r\n"), b"OK\r\n");
        assert!(handler.handle(b"quit\r\n").is_empty());
    }

    #[test]
    fn storage_commands_require_complete_declared_body() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"set key 0 0 5\r\nhello\r\n"), b"STORED\r\n");
        assert_eq!(
            handler.handle(b"append key 0 0 5 noreply\r\nhello\r\n"),
            b"STORED\r\n"
        );
        assert_eq!(
            handler.handle(b"cas key 0 0 5 123\r\nhello\r\n"),
            b"STORED\r\n"
        );

        assert_eq!(
            handler.handle(b"set key 0 0 abc\r\nhello\r\n"),
            b"ERROR\r\n"
        );
        assert_eq!(handler.handle(b"set key 0 0 5\r\nhel\r\n"), b"ERROR\r\n");
        assert_eq!(
            handler.handle(b"cas key 0 0 5 nope\r\nhello\r\n"),
            b"ERROR\r\n"
        );
    }
}
