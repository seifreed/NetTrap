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
        let key_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let extras_len = data[4] as usize;
        if extras_len
            .checked_add(key_len)
            .is_none_or(|metadata_len| metadata_len > body_len)
        {
            tracing::debug!(
                "MEMCACHED binary packet has invalid extras/key lengths: extras={}, key={}, body={}",
                extras_len,
                key_len,
                body_len
            );
            return Self::binary_response(opcode, 0x0004, data);
        }

        tracing::info!(
            "MEMCACHED binary opcode: 0x{:02x}, body_len: {}",
            opcode,
            body_len
        );

        let status = if Self::supported_binary_opcode(opcode) {
            0x0000
        } else {
            0x0081
        };
        Self::binary_response(opcode, status, data)
    }

    fn supported_binary_opcode(opcode: u8) -> bool {
        matches!(opcode, 0x00..=0x17 | 0x1c | 0x1d)
    }

    fn binary_response(opcode: u8, status: u16, request: &[u8]) -> Vec<u8> {
        let mut resp = vec![0x81]; // Response magic
        resp.push(opcode);
        resp.extend_from_slice(&0u16.to_be_bytes()); // key length
        resp.push(0); // extras length
        resp.push(0); // data type
        resp.extend_from_slice(&status.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes()); // body length
        resp.extend_from_slice(request.get(12..16).unwrap_or(&[0, 0, 0, 0]));
        resp.extend_from_slice(&0u64.to_be_bytes()); // CAS
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

    #[test]
    fn binary_packets_reject_inconsistent_extras_and_key_lengths() {
        let handler = MemcachedHandler::new();
        let mut request = vec![0x80, 0x00, 0x00, 0x04, 0x04, 0x00, 0x00, 0x00];
        request.extend_from_slice(&4u32.to_be_bytes());
        request.extend_from_slice(&0x12345678u32.to_be_bytes());
        request.extend_from_slice(&0u64.to_be_bytes());
        request.extend_from_slice(b"body");

        let response = handler.handle(&request);

        assert_eq!(response[0], 0x81);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0x0004);
        assert_eq!(&response[12..16], &0x12345678u32.to_be_bytes());
    }

    #[test]
    fn binary_packets_report_unknown_opcodes() {
        let handler = MemcachedHandler::new();
        let mut request = vec![0x80, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        request.extend_from_slice(&0u32.to_be_bytes());
        request.extend_from_slice(&0x01020304u32.to_be_bytes());
        request.extend_from_slice(&0u64.to_be_bytes());

        let response = handler.handle(&request);

        assert_eq!(response[0], 0x81);
        assert_eq!(response[1], 0xff);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0x0081);
        assert_eq!(&response[12..16], &0x01020304u32.to_be_bytes());
    }
}
