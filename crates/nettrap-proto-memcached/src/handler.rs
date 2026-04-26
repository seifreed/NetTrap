pub struct MemcachedHandler;

impl MemcachedHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(data);
        let cmd = text.trim();
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let verb = parts
            .first()
            .copied()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let has_args = parts.get(1).is_some();

        if verb == "stats" {
            stats_response(&parts)
        } else if verb == "get" && has_args {
            tracing::info!("MEMCACHED get: {}", cmd);
            b"END\r\n".to_vec()
        } else if is_storage_verb(&verb) {
            if storage_command_is_complete(data, &verb) {
                tracing::warn!(
                    "MEMCACHED write attempt: {}",
                    cmd.lines().next().unwrap_or(cmd)
                );
                if storage_command_has_noreply(data, &verb) {
                    Vec::new()
                } else {
                    b"STORED\r\n".to_vec()
                }
            } else {
                b"ERROR\r\n".to_vec()
            }
        } else if verb == "delete" {
            if delete_command_is_valid(cmd) {
                if command_has_noreply(&parts) {
                    Vec::new()
                } else {
                    b"DELETED\r\n".to_vec()
                }
            } else {
                b"ERROR\r\n".to_vec()
            }
        } else if verb == "flush_all" {
            if flush_all_command_is_valid(cmd) {
                tracing::warn!("MEMCACHED flush_all attempt");
                if command_has_noreply(&parts) {
                    Vec::new()
                } else {
                    b"OK\r\n".to_vec()
                }
            } else {
                b"ERROR\r\n".to_vec()
            }
        } else if verb == "version" && parts.len() == 1 {
            b"VERSION 1.6.22\r\n".to_vec()
        } else if verb == "quit" && parts.len() == 1 {
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

        let status = if !Self::supported_binary_opcode(opcode) {
            0x0081
        } else if Self::binary_request_shape_is_valid(opcode, extras_len, key_len, body_len) {
            0x0000
        } else {
            0x0004
        };
        if status == 0 && Self::is_quiet_binary_opcode(opcode) {
            Vec::new()
        } else {
            Self::binary_response(opcode, status, data)
        }
    }

    fn supported_binary_opcode(opcode: u8) -> bool {
        matches!(opcode, 0x00..=0x1a | 0x1c | 0x1d)
    }

    fn binary_request_shape_is_valid(
        opcode: u8,
        extras_len: usize,
        key_len: usize,
        body_len: usize,
    ) -> bool {
        let value_len = match extras_len.checked_add(key_len) {
            Some(metadata_len) if metadata_len <= body_len => body_len - metadata_len,
            _ => return false,
        };

        match opcode {
            // Get/GetQ/GetK/GetKQ/Delete/DeleteQ.
            0x00 | 0x04 | 0x09 | 0x0c | 0x0d | 0x14 => {
                extras_len == 0 && key_len > 0 && value_len == 0
            }
            // Set/Add/Replace and quiet variants: flags + expiry, key, value.
            0x01 | 0x02 | 0x03 | 0x11 | 0x12 | 0x13 => extras_len == 8 && key_len > 0,
            // Increment/Decrement and quiet variants.
            0x05 | 0x06 | 0x15 | 0x16 => extras_len == 20 && key_len > 0 && value_len == 0,
            // Quit/Noop/Version/QuitQ.
            0x07 | 0x0a | 0x0b | 0x17 => extras_len == 0 && key_len == 0 && value_len == 0,
            // Flush/FlushQ: optional expiry extras only.
            0x08 | 0x18 => matches!(extras_len, 0 | 4) && key_len == 0 && value_len == 0,
            // Append/Prepend and quiet variants.
            0x0e | 0x0f | 0x19 | 0x1a => extras_len == 0 && key_len > 0,
            // Stat: optional key, no extras/value.
            0x10 => extras_len == 0 && value_len == 0,
            // Touch/GAT/GATQ: expiry extras + key.
            0x1c | 0x1d => extras_len == 4 && key_len > 0 && value_len == 0,
            _ => false,
        }
    }

    fn is_quiet_binary_opcode(opcode: u8) -> bool {
        matches!(
            opcode,
            0x09 | 0x0d | 0x11 | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x17 | 0x18 | 0x19 | 0x1a
        )
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

fn stats_response(parts: &[&str]) -> Vec<u8> {
    match parts {
        ["stats"] => {
            tracing::info!("MEMCACHED stats request");
            let stats = "STAT pid 1\r\nSTAT uptime 86400\r\nSTAT time 1704067200\r\nSTAT version 1.6.22\r\nSTAT curr_items 0\r\nSTAT total_items 0\r\nSTAT bytes 0\r\nSTAT curr_connections 1\r\nSTAT total_connections 1\r\nEND\r\n";
            stats.as_bytes().to_vec()
        }
        ["stats", subcommand]
            if matches!(
                subcommand.to_ascii_lowercase().as_str(),
                "items" | "slabs" | "settings" | "sizes"
            ) =>
        {
            b"END\r\n".to_vec()
        }
        _ => b"ERROR\r\n".to_vec(),
    }
}

fn command_has_noreply(parts: &[&str]) -> bool {
    parts
        .last()
        .is_some_and(|value| value.eq_ignore_ascii_case("noreply"))
}

fn delete_command_is_valid(cmd: &str) -> bool {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if !parts
        .first()
        .is_some_and(|verb| verb.eq_ignore_ascii_case("delete"))
    {
        return false;
    }
    match parts.as_slice() {
        [_, key] => !key.is_empty(),
        [_, key, noreply] => !key.is_empty() && noreply.eq_ignore_ascii_case("noreply"),
        _ => false,
    }
}

fn flush_all_command_is_valid(cmd: &str) -> bool {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if !parts
        .first()
        .is_some_and(|verb| verb.eq_ignore_ascii_case("flush_all"))
    {
        return false;
    }
    match parts.as_slice() {
        [_] => true,
        [_, arg] => arg.eq_ignore_ascii_case("noreply") || arg.parse::<u32>().is_ok(),
        [_, delay, noreply] => {
            delay.parse::<u32>().is_ok() && noreply.eq_ignore_ascii_case("noreply")
        }
        _ => false,
    }
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

fn storage_command_has_noreply(data: &[u8], verb: &str) -> bool {
    let Some(header_end) = find_crlf(data) else {
        return false;
    };
    let Ok(header) = std::str::from_utf8(&data[..header_end]) else {
        return false;
    };

    let parts: Vec<&str> = header.split_whitespace().collect();
    let required_parts = if verb == "cas" { 6 } else { 5 };
    parts
        .get(required_parts)
        .is_some_and(|value| value.eq_ignore_ascii_case("noreply"))
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|window| window == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binary_request(opcode: u8) -> Vec<u8> {
        binary_request_with_parts(opcode, &[], &[], &[])
    }

    fn binary_request_with_parts(opcode: u8, extras: &[u8], key: &[u8], value: &[u8]) -> Vec<u8> {
        let body_len = extras.len() + key.len() + value.len();
        let mut request = vec![
            0x80,
            opcode,
            ((key.len() >> 8) & 0xff) as u8,
            (key.len() & 0xff) as u8,
            extras.len() as u8,
            0x00,
            0x00,
            0x00,
        ];
        request.extend_from_slice(&(body_len as u32).to_be_bytes());
        request.extend_from_slice(&0x01020304u32.to_be_bytes());
        request.extend_from_slice(&0u64.to_be_bytes());
        request.extend_from_slice(extras);
        request.extend_from_slice(key);
        request.extend_from_slice(value);
        request
    }

    fn binary_status(response: &[u8]) -> u16 {
        u16::from_be_bytes([response[6], response[7]])
    }

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
    fn delete_and_flush_all_validate_arguments() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"delete key\r\n"), b"DELETED\r\n");
        assert!(handler.handle(b"delete key noreply\r\n").is_empty());
        assert_eq!(handler.handle(b"DELETE key\r\n"), b"DELETED\r\n");
        assert_eq!(handler.handle(b"delete key extra\r\n"), b"ERROR\r\n");
        assert_eq!(
            handler.handle(b"delete key noreply extra\r\n"),
            b"ERROR\r\n"
        );

        assert_eq!(handler.handle(b"flush_all 10\r\n"), b"OK\r\n");
        assert!(handler.handle(b"flush_all 10 noreply\r\n").is_empty());
        assert!(handler.handle(b"FLUSH_ALL noreply\r\n").is_empty());
        assert_eq!(handler.handle(b"flush_all nope\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"flush_all 10 nope extra\r\n"), b"ERROR\r\n");
    }

    #[test]
    fn text_noreply_suppresses_success_responses() {
        let handler = MemcachedHandler::new();

        assert!(
            handler
                .handle(b"set key 0 0 5 noreply\r\nhello\r\n")
                .is_empty()
        );
        assert!(handler.handle(b"delete key noreply\r\n").is_empty());
        assert!(handler.handle(b"flush_all noreply\r\n").is_empty());
        assert!(handler.handle(b"flush_all 10 noreply\r\n").is_empty());
    }

    #[test]
    fn text_commands_reject_unsupported_arguments() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"stats unknown\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"version now\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"quit now\r\n"), b"ERROR\r\n");
    }

    #[test]
    fn storage_commands_require_complete_declared_body() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"set key 0 0 5\r\nhello\r\n"), b"STORED\r\n");
        assert!(
            handler
                .handle(b"append key 0 0 5 noreply\r\nhello\r\n")
                .is_empty()
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
    fn binary_quiet_successes_do_not_send_responses() {
        let handler = MemcachedHandler::new();
        let storage_extras = [0u8; 8];
        let counter_extras = [0u8; 20];

        for (opcode, extras, key, value) in [
            (0x09, &b""[..], &b"k"[..], &b""[..]),
            (0x0d, &b""[..], &b"k"[..], &b""[..]),
            (0x11, &storage_extras[..], &b"k"[..], &b"v"[..]),
            (0x12, &storage_extras[..], &b"k"[..], &b"v"[..]),
            (0x13, &storage_extras[..], &b"k"[..], &b"v"[..]),
            (0x14, &b""[..], &b"k"[..], &b""[..]),
            (0x15, &counter_extras[..], &b"k"[..], &b""[..]),
            (0x16, &counter_extras[..], &b"k"[..], &b""[..]),
            (0x17, &b""[..], &b""[..], &b""[..]),
            (0x18, &b""[..], &b""[..], &b""[..]),
            (0x19, &b""[..], &b"k"[..], &b"v"[..]),
            (0x1a, &b""[..], &b"k"[..], &b"v"[..]),
        ] {
            assert!(
                handler
                    .handle(&binary_request_with_parts(opcode, extras, key, value))
                    .is_empty(),
                "opcode 0x{opcode:02x} should be quiet on success"
            );
        }
    }

    #[test]
    fn binary_quiet_errors_still_send_responses() {
        let handler = MemcachedHandler::new();
        let mut request = vec![0x80, 0x11, 0x00, 0x04, 0x04, 0x00, 0x00, 0x00];
        request.extend_from_slice(&4u32.to_be_bytes());
        request.extend_from_slice(&0x12345678u32.to_be_bytes());
        request.extend_from_slice(&0u64.to_be_bytes());
        request.extend_from_slice(b"body");

        let response = handler.handle(&request);

        assert_eq!(response[0], 0x81);
        assert_eq!(binary_status(&response), 0x0004);
        assert_eq!(&response[12..16], &0x12345678u32.to_be_bytes());
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
        assert_eq!(binary_status(&response), 0x0004);
        assert_eq!(&response[12..16], &0x12345678u32.to_be_bytes());
    }

    #[test]
    fn binary_packets_validate_opcode_specific_layouts() {
        let handler = MemcachedHandler::new();

        let get_with_extras = handler.handle(&binary_request_with_parts(0x00, &[0; 4], b"k", b""));
        assert_eq!(get_with_extras[0], 0x81);
        assert_eq!(binary_status(&get_with_extras), 0x0004);

        let set_without_extras = handler.handle(&binary_request_with_parts(0x01, &[], b"k", b"v"));
        assert_eq!(set_without_extras[0], 0x81);
        assert_eq!(binary_status(&set_without_extras), 0x0004);

        let valid_set = handler.handle(&binary_request_with_parts(0x01, &[0; 8], b"k", b"v"));
        assert_eq!(valid_set[0], 0x81);
        assert_eq!(binary_status(&valid_set), 0x0000);
    }

    #[test]
    fn binary_packets_report_unknown_opcodes() {
        let handler = MemcachedHandler::new();
        let request = binary_request(0xff);

        let response = handler.handle(&request);

        assert_eq!(response[0], 0x81);
        assert_eq!(response[1], 0xff);
        assert_eq!(binary_status(&response), 0x0081);
        assert_eq!(&response[12..16], &0x01020304u32.to_be_bytes());
    }
}
