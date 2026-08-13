pub struct MemcachedHandler {
    started_at: std::time::Instant,
    now: fn() -> chrono::DateTime<chrono::Utc>,
}

mod commands;
pub(crate) use commands::*;

const REDACTED_MEMCACHED_FIELD: &str = "***REDACTED***";

impl MemcachedHandler {
    pub fn new() -> Self {
        Self {
            started_at: std::time::Instant::now(),
            now: chrono::Utc::now,
        }
    }

    /// Inject the clock used by `stats` so FakeTime mode reaches the reported
    /// `STAT time` field.
    pub fn with_now(mut self, now: fn() -> chrono::DateTime<chrono::Utc>) -> Self {
        self.now = now;
        self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if !data.is_empty() && data[0] == 0x80 {
            tracing::info!("MEMCACHED binary protocol request");
            return self.handle_binary(data);
        }

        if data.len() > MAX_MEMCACHED_TEXT_REQUEST_BYTES {
            return b"ERROR\r\n".to_vec();
        }
        let Some(header_end) = find_crlf(data) else {
            return if data.iter().any(|&byte| byte == b'\r' || byte == b'\n') {
                b"ERROR\r\n".to_vec()
            } else if std::str::from_utf8(data).is_ok() {
                Vec::new()
            } else {
                tracing::warn!("MEMCACHED text protocol request contained invalid UTF-8");
                b"ERROR\r\n".to_vec()
            };
        };

        let Ok(command_line) = std::str::from_utf8(&data[..header_end]) else {
            tracing::warn!("MEMCACHED text protocol header contained invalid UTF-8");
            return b"ERROR\r\n".to_vec();
        };
        let command_line_bytes = command_line.as_bytes();
        if command_line_bytes.iter().enumerate().any(|(idx, &byte)| {
            byte == b'\r' && (idx + 1 == command_line.len() || command_line_bytes[idx + 1] != b'\n')
        }) {
            return b"ERROR\r\n".to_vec();
        }

        if command_line.is_empty()
            || command_line.chars().next().is_some_and(char::is_whitespace)
            || command_line.chars().last().is_some_and(char::is_whitespace)
            || command_line.len() > MAX_MEMCACHED_TEXT_LINE_BYTES
        {
            return b"ERROR\r\n".to_vec();
        }

        if command_uses_invalid_whitespace(command_line)
            || command_uses_mixed_spaces_and_tabs(command_line)
            || command_uses_compressed_ascii_whitespace(command_line)
        {
            return b"ERROR\r\n".to_vec();
        }

        let header_parts = command_parts(command_line);
        if header_parts.len() > MAX_MEMCACHED_TEXT_ARGS + 1 {
            return b"ERROR\r\n".to_vec();
        }
        let verb = header_parts
            .first()
            .copied()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let is_storage_command = is_storage_verb(&verb);
        if !is_storage_command && data.len() != header_end + 2 {
            return b"ERROR\r\n".to_vec();
        }

        let parts = header_parts;
        let has_args = parts.get(1).is_some();

        if verb == "stats" {
            stats_response(
                &parts,
                self.started_at.elapsed().as_secs(),
                (self.now)().timestamp(),
            )
        } else if matches!(verb.as_str(), "get" | "gets")
            && has_args
            && parts[1..].iter().all(|key| is_valid_key_token(key))
        {
            tracing::debug!("MEMCACHED get: {}", safe_log_line(command_line));
            tracing::info!("MEMCACHED get: keys={}", parts.len().saturating_sub(1));
            b"END\r\n".to_vec()
        } else if matches!(verb.as_str(), "gat" | "gats")
            && parts.len() >= 3
            && parse_unsigned_decimal::<u32>(parts[1]).is_some()
            && parts[2..].iter().all(|key| is_valid_key_token(key))
        {
            tracing::debug!("MEMCACHED get-and-touch: {}", safe_log_line(command_line));
            tracing::info!(
                "MEMCACHED get-and-touch: keys={}",
                parts.len().saturating_sub(2)
            );
            b"END\r\n".to_vec()
        } else if is_storage_command {
            if storage_command_is_complete(data, &verb) {
                tracing::debug!("MEMCACHED write attempt: {}", safe_log_line(command_line));
                tracing::warn!("MEMCACHED write attempt: {}", REDACTED_MEMCACHED_FIELD);
                if storage_command_has_noreply(data, &verb) {
                    Vec::new()
                } else if verb == "cas" {
                    b"NOT_FOUND\r\n".to_vec()
                } else if matches!(verb.as_str(), "replace" | "append" | "prepend") {
                    b"NOT_STORED\r\n".to_vec()
                } else {
                    b"STORED\r\n".to_vec()
                }
            } else {
                b"ERROR\r\n".to_vec()
            }
        } else if verb == "delete" {
            if delete_command_is_valid(command_line) {
                if command_has_noreply(&parts) {
                    Vec::new()
                } else {
                    b"DELETED\r\n".to_vec()
                }
            } else {
                b"ERROR\r\n".to_vec()
            }
        } else if verb == "flush_all" {
            if flush_all_command_is_valid(command_line) {
                tracing::warn!("MEMCACHED flush_all attempt");
                if command_has_noreply(&parts) {
                    Vec::new()
                } else {
                    b"OK\r\n".to_vec()
                }
            } else {
                b"ERROR\r\n".to_vec()
            }
        } else if verb == "touch" {
            if touch_command_is_valid(command_line) {
                if command_has_noreply(&parts) {
                    Vec::new()
                } else {
                    b"TOUCHED\r\n".to_vec()
                }
            } else {
                b"ERROR\r\n".to_vec()
            }
        } else if matches!(verb.as_str(), "incr" | "decr") {
            if counter_command_is_valid(command_line, &verb) {
                if command_has_noreply(&parts) {
                    Vec::new()
                } else {
                    b"NOT_FOUND\r\n".to_vec()
                }
            } else {
                b"ERROR\r\n".to_vec()
            }
        } else if verb == "verbosity" {
            if verbosity_command_is_valid(command_line) {
                b"OK\r\n".to_vec()
            } else {
                b"ERROR\r\n".to_vec()
            }
        } else if verb == "version" && parts.len() == 1 {
            b"VERSION 1.6.22\r\n".to_vec()
        } else if verb == "quit" && parts.len() == 1 {
            Vec::new()
        } else {
            b"ERROR\r\n".to_vec()
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
        let Some(total_len) = 24usize.checked_add(body_len) else {
            tracing::debug!(
                "MEMCACHED binary packet body length overflows platform usize: {}",
                body_len
            );
            return Vec::new();
        };
        if data.len() < total_len {
            return Vec::new();
        }
        if data.len() != total_len {
            tracing::debug!(
                "MEMCACHED binary packet has trailing bytes: declared={}, actual={}",
                total_len,
                data.len()
            );
            return Vec::new();
        }

        let opcode = data[1];
        if data[5] != 0 {
            tracing::debug!("MEMCACHED binary packet has nonzero data type");
            return Self::binary_response(opcode, 0x0004, data);
        }

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
        if opcode == 0x10 && status == 0 {
            Self::binary_stats_response(self, data)
        } else if opcode == 0x0b && status == 0 {
            Self::binary_response_with_body(opcode, status, data, b"1.6.22")
        } else if status == 0 && Self::is_quiet_binary_opcode(opcode) {
            Vec::new()
        } else {
            Self::binary_response(opcode, status, data)
        }
    }

    fn supported_binary_opcode(opcode: u8) -> bool {
        matches!(opcode, 0x00..=0x1e)
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
            0x00 | 0x04 | 0x09 | 0x0c | 0x0d | 0x14 => {
                extras_len == 0
                    && (1..=MAX_MEMCACHED_KEY_BYTES).contains(&key_len)
                    && value_len == 0
            }
            0x01 | 0x02 | 0x03 | 0x11 | 0x12 | 0x13 => {
                extras_len == 8 && (1..=MAX_MEMCACHED_KEY_BYTES).contains(&key_len)
            }
            0x05 | 0x06 | 0x15 | 0x16 => {
                extras_len == 20
                    && (1..=MAX_MEMCACHED_KEY_BYTES).contains(&key_len)
                    && value_len == 0
            }
            0x07 | 0x0a | 0x0b | 0x17 => extras_len == 0 && key_len == 0 && value_len == 0,
            0x08 | 0x18 => matches!(extras_len, 0 | 4) && key_len == 0 && value_len == 0,
            0x0e | 0x0f | 0x19 | 0x1a => {
                extras_len == 0 && (1..=MAX_MEMCACHED_KEY_BYTES).contains(&key_len)
            }
            0x10 => extras_len == 0 && key_len == 0 && value_len == 0,
            0x1b => extras_len == 4 && key_len == 0 && value_len == 0,
            0x1c..=0x1e => {
                extras_len == 4
                    && (1..=MAX_MEMCACHED_KEY_BYTES).contains(&key_len)
                    && value_len == 0
            }
            _ => false,
        }
    }

    fn is_quiet_binary_opcode(opcode: u8) -> bool {
        matches!(
            opcode,
            0x09 | 0x0d
                | 0x11
                | 0x12
                | 0x13
                | 0x14
                | 0x15
                | 0x16
                | 0x17
                | 0x18
                | 0x19
                | 0x1a
                | 0x1e
        )
    }

    fn binary_response(opcode: u8, status: u16, request: &[u8]) -> Vec<u8> {
        let body = match status {
            0x0004 => b"Invalid arguments".as_slice(),
            0x0081 => b"Unknown command".as_slice(),
            _ => &[],
        };
        Self::binary_response_with_body(opcode, status, request, body)
    }

    fn binary_response_with_body(opcode: u8, status: u16, request: &[u8], body: &[u8]) -> Vec<u8> {
        Self::binary_response_with_key_and_body(opcode, status, request, &[], body)
    }

    fn binary_response_with_key_and_body(
        opcode: u8,
        status: u16,
        request: &[u8],
        key: &[u8],
        body: &[u8],
    ) -> Vec<u8> {
        let Ok(key_len) = u16::try_from(key.len()) else {
            return Vec::new();
        };
        let Some(body_len) = key.len().checked_add(body.len()) else {
            return Vec::new();
        };
        let Ok(body_len) = u32::try_from(body_len) else {
            return Vec::new();
        };

        let mut resp = vec![0x81]; // Response magic
        resp.push(opcode);
        resp.extend_from_slice(&key_len.to_be_bytes());
        resp.push(0); // extras length
        resp.push(0); // data type
        resp.extend_from_slice(&status.to_be_bytes());
        resp.extend_from_slice(&body_len.to_be_bytes()); // body length
        resp.extend_from_slice(request.get(12..16).unwrap_or(&[0, 0, 0, 0]));
        resp.extend_from_slice(&0u64.to_be_bytes()); // CAS
        resp.extend_from_slice(key);
        resp.extend_from_slice(body);
        resp
    }

    fn binary_stats_response(&self, request: &[u8]) -> Vec<u8> {
        let uptime = self.started_at.elapsed().as_secs().to_string();
        let time = (self.now)().timestamp().to_string();
        let stats = [
            ("pid", "1".to_string()),
            ("uptime", uptime),
            ("time", time),
            ("version", "1.6.22".to_string()),
            ("curr_items", "0".to_string()),
            ("total_items", "0".to_string()),
            ("bytes", "0".to_string()),
            ("curr_connections", "1".to_string()),
            ("total_connections", "1".to_string()),
        ];

        let mut response = Vec::new();
        for (name, value) in stats {
            response.extend_from_slice(&Self::binary_response_with_key_and_body(
                0x10,
                0x0000,
                request,
                name.as_bytes(),
                value.as_bytes(),
            ));
        }
        response.extend_from_slice(&Self::binary_response(0x10, 0x0000, request));
        response
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

    const LOG_LINE_PREVIEW_CHARS: usize = 240;

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
    fn text_commands_accept_whitespace_separated_arguments() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"get\tkey\r\n"), b"END\r\n");
        assert_eq!(handler.handle(b"gets\tkey\r\n"), b"END\r\n");
        assert_eq!(handler.handle(b"gat\t10\tkey\r\n"), b"END\r\n");
        assert_eq!(handler.handle(b"delete\tkey\r\n"), b"DELETED\r\n");
        assert_eq!(handler.handle(b"flush_all\t10\r\n"), b"OK\r\n");
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
    fn stats_command_uses_injected_clock_for_time_field() {
        fn fixed_now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(1_800_000_000, 0).expect("valid instant")
        }

        let handler = MemcachedHandler::new().with_now(fixed_now);
        let response = String::from_utf8(handler.handle(b"stats\r\n"))
            .expect("stats response should be UTF-8");

        assert!(response.contains("STAT time 1800000000\r\n"));
    }

    #[test]
    fn stats_command_preserves_pre_epoch_time_field() {
        fn fixed_now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(-1, 0).expect("valid instant")
        }

        let handler = MemcachedHandler::new().with_now(fixed_now);
        let response = String::from_utf8(handler.handle(b"stats\r\n"))
            .expect("stats response should be UTF-8");

        assert!(response.contains("STAT time -1\r\n"));
    }

    #[test]
    fn stats_detail_commands_are_accepted() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"stats detail on\r\n"), b"OK\r\n");
        assert_eq!(handler.handle(b"stats detail off\r\n"), b"OK\r\n");
        assert_eq!(handler.handle(b"stats detail dump\r\n"), b"END\r\n");
        assert_eq!(handler.handle(b"stats detail maybe\r\n"), b"ERROR\r\n");
    }

    #[test]
    fn verbosity_command_validates_arguments() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"verbosity 1\r\n"), b"OK\r\n");
        assert_eq!(handler.handle(b"verbosity 10\r\n"), b"OK\r\n");
        assert_eq!(handler.handle(b"verbosity nope\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"verbosity 1 extra\r\n"), b"ERROR\r\n");
    }

    #[test]
    fn text_commands_without_crlf_are_incomplete() {
        let handler = MemcachedHandler::new();

        assert!(handler.handle(b"stats").is_empty());
        assert!(handler.handle(b"version").is_empty());
        assert!(handler.handle(b"get key").is_empty());
    }

    #[test]
    fn bare_carriage_return_text_requests_are_rejected() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"stats\r"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"get key\rvalue\r\n"), b"ERROR\r\n");
    }

    #[test]
    fn stats_response_does_not_report_frozen_uptime() {
        let handler = MemcachedHandler::new();
        let response = handler.handle(b"stats\r\n");
        let text = String::from_utf8(response).expect("stats response should be UTF-8");

        assert!(text.contains("STAT uptime "));
        assert!(!text.contains("STAT uptime 86400\r\n"));
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
        assert_eq!(handler.handle(b"flush_all +10\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"flush_all nope\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"flush_all 10 nope extra\r\n"), b"ERROR\r\n");
    }

    #[test]
    fn touch_command_validates_arguments() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"touch key 10\r\n"), b"TOUCHED\r\n");
        assert!(handler.handle(b"touch key 10 noreply\r\n").is_empty());
        assert_eq!(handler.handle(b"touch key nope\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"touch key 10 extra\r\n"), b"ERROR\r\n");
    }

    #[test]
    fn counter_commands_validate_arguments() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"incr key 1\r\n"), b"NOT_FOUND\r\n");
        assert_eq!(handler.handle(b"decr key 1\r\n"), b"NOT_FOUND\r\n");
        assert!(handler.handle(b"incr key 1 noreply\r\n").is_empty());
        assert_eq!(handler.handle(b"incr key nope\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"decr key 1 extra\r\n"), b"ERROR\r\n");
    }

    #[test]
    fn storage_commands_allow_carriage_returns_in_values() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"set key 0 0 3\r\nA\rB\r\n"), b"STORED\r\n");
    }

    #[test]
    fn append_and_prepend_return_not_stored() {
        let handler = MemcachedHandler::new();

        assert_eq!(
            handler.handle(b"append key 0 0 1\r\na\r\n"),
            b"NOT_STORED\r\n"
        );
        assert_eq!(
            handler.handle(b"prepend key 0 0 1\r\na\r\n"),
            b"NOT_STORED\r\n"
        );
        assert!(
            handler
                .handle(b"append key 0 0 1 noreply\r\na\r\n")
                .is_empty()
        );
    }

    #[test]
    fn cas_commands_return_not_found() {
        let handler = MemcachedHandler::new();

        assert_eq!(
            handler.handle(b"cas key 0 0 1 42\r\na\r\n"),
            b"NOT_FOUND\r\n"
        );
        assert!(
            handler
                .handle(b"cas key 0 0 1 42 noreply\r\na\r\n")
                .is_empty()
        );
    }

    #[test]
    fn replace_commands_return_not_stored() {
        let handler = MemcachedHandler::new();

        assert_eq!(
            handler.handle(b"replace key 0 0 1\r\na\r\n"),
            b"NOT_STORED\r\n"
        );
        assert!(
            handler
                .handle(b"replace key 0 0 1 noreply\r\na\r\n")
                .is_empty()
        );
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
        assert_eq!(handler.handle(b"stats  items\r\n"), b"ERROR\r\n");
    }

    #[test]
    fn text_commands_reject_tab_separated_arguments() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"stats\titems\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"version\tnow\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"get key\tother\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"delete key\t\r\n"), b"ERROR\r\n");
        assert_eq!(
            handler.handle(b"set key\t 0 0 5\r\nhello\r\n"),
            b"ERROR\r\n"
        );
    }

    #[test]
    fn text_commands_reject_compressed_ascii_whitespace() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"get  key\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"get\t\tkey\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"set key 0 0  1\r\na\r\n"), b"ERROR\r\n");
    }

    #[test]
    fn text_commands_reject_unicode_whitespace_separators() {
        let handler = MemcachedHandler::new();

        assert_eq!(
            handler.handle("get\u{00a0}key\r\n".as_bytes()),
            b"ERROR\r\n"
        );
        assert_eq!(
            handler.handle("set key 0\u{2028}0 5\r\nhello\r\n".as_bytes()),
            b"ERROR\r\n"
        );
    }

    #[test]
    fn leading_whitespace_text_commands_are_rejected() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b" stats\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b" version\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b" get key\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b" delete key\r\n"), b"ERROR\r\n");
    }

    #[test]
    fn text_protocol_rejects_invalid_utf8() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"\xff\xfe\xfd"), b"ERROR\r\n");
    }

    #[test]
    fn text_protocol_rejects_oversized_command_line() {
        let handler = MemcachedHandler::new();
        let mut command = b"get ".to_vec();
        command.extend(std::iter::repeat_n(b'a', MAX_MEMCACHED_TEXT_LINE_BYTES));
        command.extend_from_slice(b"\r\n");

        assert_eq!(handler.handle(&command), b"ERROR\r\n");
    }

    #[test]
    fn text_protocol_rejects_too_many_arguments() {
        let handler = MemcachedHandler::new();
        let mut command = String::from("get");
        for index in 0..=MAX_MEMCACHED_TEXT_ARGS {
            command.push_str(" key");
            command.push_str(&index.to_string());
        }
        command.push_str("\r\n");

        assert_eq!(handler.handle(command.as_bytes()), b"ERROR\r\n");
    }

    #[test]
    fn text_protocol_accepts_maximum_argument_count() {
        let handler = MemcachedHandler::new();
        let mut command = String::from("get");
        for index in 0..MAX_MEMCACHED_TEXT_ARGS {
            command.push_str(" key");
            command.push_str(&index.to_string());
        }
        command.push_str("\r\n");

        assert_eq!(handler.handle(command.as_bytes()), b"END\r\n");
    }

    #[test]
    fn text_protocol_rejects_oversized_requests_before_text_parsing() {
        let handler = MemcachedHandler::new();
        let body_len = MAX_MEMCACHED_TEXT_REQUEST_BYTES;
        let mut command = format!("set key 0 0 {body_len}\r\n").into_bytes();
        command.extend(std::iter::repeat_n(b'a', body_len));
        command.extend_from_slice(b"\r\n");

        assert_eq!(handler.handle(&command), b"ERROR\r\n");
    }

    #[test]
    fn storage_commands_require_complete_declared_body() {
        let handler = MemcachedHandler::new();

        assert_eq!(handler.handle(b"set key 0 0 5\r\nhello\r\n"), b"STORED\r\n");
        assert_eq!(handler.handle(b"set key 0 0 0\r\n\r\n"), b"STORED\r\n");
        assert_eq!(
            handler.handle(b"set key 0 0 6\r\nhello \r\n"),
            b"STORED\r\n"
        );
        assert!(
            handler
                .handle(b"append key 0 0 5 noreply\r\nhello\r\n")
                .is_empty()
        );
        assert_eq!(
            handler.handle(b"cas key 0 0 5 123\r\nhello\r\n"),
            b"NOT_FOUND\r\n"
        );

        assert_eq!(
            handler.handle(b"set key 0 0 abc\r\nhello\r\n"),
            b"ERROR\r\n"
        );
        assert_eq!(handler.handle(b"set key +0 0 5\r\nhello\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"set key 0 +0 5\r\nhello\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"set key 0 -1 5\r\nhello\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"set key 0 0 +5\r\nhello\r\n"), b"ERROR\r\n");
        assert_eq!(handler.handle(b"set key 0 0 5\r\nhel\r\n"), b"ERROR\r\n");
        assert_eq!(
            handler.handle(b"cas key 0 0 5 nope\r\nhello\r\n"),
            b"ERROR\r\n"
        );
        assert_eq!(
            handler.handle(b"cas key 0 0 5 +123\r\nhello\r\n"),
            b"ERROR\r\n"
        );
    }

    #[test]
    fn storage_commands_accept_binary_value_bytes() {
        let handler = MemcachedHandler::new();

        assert_eq!(
            handler.handle(b"set key 0 0 3\r\n\xff\x00\xfe\r\n"),
            b"STORED\r\n"
        );
    }

    #[test]
    fn text_commands_reject_keys_over_protocol_limit() {
        let handler = MemcachedHandler::new();
        let oversized_key = "k".repeat(MAX_MEMCACHED_KEY_BYTES + 1);

        assert_eq!(
            handler.handle(format!("get {oversized_key}\r\n").as_bytes()),
            b"ERROR\r\n"
        );
        assert_eq!(
            handler.handle(format!("set {oversized_key} 0 0 5\r\nhello\r\n").as_bytes()),
            b"ERROR\r\n"
        );
    }

    #[test]
    fn logged_text_commands_are_single_line() {
        let logged_get = safe_log_line("get key\r\nset owned\x1b");
        let logged_storage = safe_log_line("set key\x1b 0 0 5\r");

        assert_eq!(logged_get, "get key  set owned ");
        assert_eq!(logged_storage, "set key  0 0 5 ");
        assert!(!logged_get.chars().any(char::is_control));
        assert!(!logged_storage.chars().any(char::is_control));

        let long = "a".repeat(LOG_LINE_PREVIEW_CHARS + 1);
        assert_eq!(safe_log_line(&long).len(), LOG_LINE_PREVIEW_CHARS);
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
            (0x1e, &[0; 4][..], &b"k"[..], &b""[..]),
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
    fn binary_gat_responds_while_gatq_is_quiet() {
        let handler = MemcachedHandler::new();

        let gat = handler.handle(&binary_request_with_parts(0x1d, &[0; 4], b"k", b""));
        let gatq = handler.handle(&binary_request_with_parts(0x1e, &[0; 4], b"k", b""));

        assert_eq!(gat[0], 0x81);
        assert_eq!(gat[1], 0x1d);
        assert_eq!(binary_status(&gat), 0x0000);
        assert!(gatq.is_empty());
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
    fn binary_packets_reject_nonzero_data_type() {
        let handler = MemcachedHandler::new();
        let mut request = binary_request_with_parts(0x00, b"", b"k", b"");
        request[5] = 1;

        let response = handler.handle(&request);

        assert_eq!(response[0], 0x81);
        assert_eq!(binary_status(&response), 0x0004);
    }

    #[test]
    fn binary_packets_reject_trailing_bytes_after_declared_body() {
        let handler = MemcachedHandler::new();
        let mut request = binary_request_with_parts(0x00, b"", b"k", b"");
        request.push(0);

        let response = handler.handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn binary_packets_reject_body_length_that_overflows_total_length() {
        let handler = MemcachedHandler::new();
        let mut request = vec![0; 24];
        request[0] = 0x80;
        request[8..12].copy_from_slice(&u32::MAX.to_be_bytes());

        let response = handler.handle(&request);

        assert!(response.is_empty());
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

        let valid_verbosity = handler.handle(&binary_request_with_parts(0x1b, &[0; 4], b"", b""));
        assert_eq!(valid_verbosity[0], 0x81);
        assert_eq!(binary_status(&valid_verbosity), 0x0000);

        let verbosity_with_key =
            handler.handle(&binary_request_with_parts(0x1b, &[0; 4], b"k", b""));
        assert_eq!(verbosity_with_key[0], 0x81);
        assert_eq!(binary_status(&verbosity_with_key), 0x0004);
    }

    #[test]
    fn binary_packets_reject_keys_over_protocol_limit() {
        let handler = MemcachedHandler::new();
        let oversized_key = vec![b'k'; MAX_MEMCACHED_KEY_BYTES + 1];

        let get_response =
            handler.handle(&binary_request_with_parts(0x00, b"", &oversized_key, b""));
        assert_eq!(get_response[0], 0x81);
        assert_eq!(binary_status(&get_response), 0x0004);

        let set_response = handler.handle(&binary_request_with_parts(
            0x01,
            &[0; 8],
            &oversized_key,
            b"v",
        ));
        assert_eq!(set_response[0], 0x81);
        assert_eq!(binary_status(&set_response), 0x0004);
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
        assert_eq!(&response[24..], b"Unknown command");
    }

    #[test]
    fn binary_invalid_arguments_include_error_text() {
        let handler = MemcachedHandler::new();
        let mut request = binary_request_with_parts(0x01, &[], b"k", b"v");
        request[4] = 0x00;

        let response = handler.handle(&request);

        assert_eq!(response[0], 0x81);
        assert_eq!(response[1], 0x01);
        assert_eq!(binary_status(&response), 0x0004);
        assert_eq!(&response[24..], b"Invalid arguments");
    }

    #[test]
    fn binary_stat_requests_return_default_statistics() {
        fn fixed_now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(1_800_000_000, 0).expect("valid instant")
        }

        let handler = MemcachedHandler::new().with_now(fixed_now);
        let request = binary_request(0x10);

        let response = handler.handle(&request);

        assert_eq!(response[0], 0x81);
        assert_eq!(response[1], 0x10);
        assert_eq!(binary_status(&response), 0x0000);
        assert_eq!(&response[2..4], &3u16.to_be_bytes());
        assert_eq!(&response[8..12], &4u32.to_be_bytes());
        assert_eq!(&response[24..27], b"pid");
        assert_eq!(&response[27..28], b"1");
        assert_eq!(
            &response[response.len() - 24..response.len() - 22],
            &[0x81, 0x10]
        );
        assert_eq!(
            &response[response.len() - 16..response.len() - 12],
            &[0, 0, 0, 0]
        );
    }

    #[test]
    fn binary_version_packets_return_version_string() {
        let handler = MemcachedHandler::new();
        let request = binary_request(0x0b);

        let response = handler.handle(&request);

        assert_eq!(response[0], 0x81);
        assert_eq!(response[1], 0x0b);
        assert_eq!(binary_status(&response), 0x0000);
        assert_eq!(&response[8..12], &6u32.to_be_bytes());
        assert_eq!(&response[24..], b"1.6.22");
    }
}
