pub struct PostgresHandler {
    version: String,
}

const POSTGRES_SSL_REQUEST: u32 = 80877103;
const POSTGRES_GSSENC_REQUEST: u32 = 80877104;
const POSTGRES_CANCEL_REQUEST: u32 = 80877102;
const LOG_FIELD_PREVIEW_CHARS: usize = 240;
const POSTGRES_PROTOCOL_VIOLATION_CODE: &[u8] = b"08P01";
const POSTGRES_FATAL_SEVERITY: &[u8] = b"FATAL";
const REDACTED_QUERY_FIELD: &str = "***REDACTED***";

/// PostgreSQL ReadyForQuery message: tag 'Z', length 5, transaction status 'I' (idle).
const READY_FOR_QUERY_IDLE: [u8; 6] = [b'Z', 0, 0, 0, 5, b'I'];

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
        resp.extend_from_slice(&READY_FOR_QUERY_IDLE);
        resp
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        match data[0] {
            b'Q' => {
                // Simple query: 'Q'(1) + length(4) + query_string
                if data.len() < 5 {
                    return postgres_error_response("Malformed simple query frame");
                }
                let msg_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
                let Some(frame_len) = msg_len.checked_add(1) else {
                    tracing::debug!(
                        "POSTGRES malformed Query length overflows platform usize: {}",
                        msg_len
                    );
                    return postgres_error_response("Malformed simple query frame");
                };
                if msg_len < 4 || data.len() < frame_len {
                    tracing::debug!(
                        "POSTGRES malformed Query length: declared={}, available={}",
                        msg_len,
                        data.len().saturating_sub(1)
                    );
                    return postgres_error_response("Malformed simple query frame");
                }
                if data.len() != frame_len {
                    tracing::debug!(
                        "POSTGRES Query has trailing bytes: declared={}, actual={}",
                        msg_len,
                        data.len().saturating_sub(1)
                    );
                    return postgres_error_response("Malformed simple query frame");
                }
                let query_end = frame_len;
                let query_bytes = &data[5..query_end];
                let Some(query_without_nul) = query_bytes.strip_suffix(&[0]) else {
                    tracing::debug!("POSTGRES malformed Query without NUL terminator");
                    return postgres_error_response("Malformed simple query frame");
                };
                if query_without_nul.contains(&0) {
                    tracing::debug!("POSTGRES malformed Query with embedded NUL");
                    return postgres_error_response("Malformed simple query frame");
                }
                let Ok(query) = std::str::from_utf8(query_without_nul) else {
                    tracing::debug!("POSTGRES malformed Query with invalid UTF-8");
                    return postgres_error_response("Malformed simple query frame");
                };
                tracing::debug!(
                    "POSTGRES QUERY (v{}): {}",
                    self.version,
                    safe_log_text(query)
                );
                tracing::warn!(
                    "POSTGRES QUERY (v{}): {}",
                    self.version,
                    REDACTED_QUERY_FIELD
                );
                let mut resp = Vec::new();
                let tag = b"SELECT 0";
                resp.push(b'C');
                let Ok(tag_len) = u32::try_from(4 + tag.len() + 1) else {
                    return postgres_error_response("Response too large");
                };
                resp.extend_from_slice(&tag_len.to_be_bytes());
                resp.extend_from_slice(tag);
                resp.push(0);
                resp.extend_from_slice(&READY_FOR_QUERY_IDLE);
                resp
            }
            b'X' => {
                if !Self::typed_message_is_complete(data) {
                    tracing::debug!("POSTGRES malformed Terminate message");
                    return postgres_error_response("Malformed terminate message");
                }
                Vec::new()
            }
            // Post-auth commands: Parse, Bind, Describe, Execute, Close, Flush, Sync, FunctionCall
            b'P' | b'B' | b'D' | b'E' | b'C' | b'H' | b'S' | b'F' => {
                if !Self::typed_message_is_complete(data) {
                    tracing::debug!("POSTGRES malformed typed message: tag=0x{:02x}", data[0]);
                    return postgres_error_response("Malformed typed message");
                }
                tracing::info!("POSTGRES command: 0x{:02x}", data[0]);
                let mut resp = Vec::new();
                resp.extend_from_slice(&READY_FOR_QUERY_IDLE);
                resp
            }
            _ if data.len() >= 8 => {
                // Startup message (no type byte, starts with length + version)
                let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                if len < 8 {
                    tracing::debug!(
                        "POSTGRES malformed startup length: declared={}, available={}",
                        len,
                        data.len()
                    );
                    return postgres_error_response("Malformed startup packet");
                }
                let pg_version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                if pg_version == POSTGRES_CANCEL_REQUEST {
                    if len != 16 || data.len() != 16 {
                        tracing::debug!("POSTGRES malformed CancelRequest");
                        return postgres_error_response("Malformed cancel request");
                    }
                    tracing::info!("POSTGRES CancelRequest from client");
                    return Vec::new();
                }
                if data.len() < len {
                    tracing::debug!(
                        "POSTGRES malformed startup length: declared={}, available={}",
                        len,
                        data.len()
                    );
                    return postgres_error_response("Malformed startup packet");
                }
                if data.len() != len {
                    tracing::debug!(
                        "POSTGRES startup has trailing bytes: declared={}, actual={}",
                        len,
                        data.len()
                    );
                    return postgres_error_response("Malformed startup packet");
                }
                if pg_version == POSTGRES_SSL_REQUEST {
                    if len != 8 {
                        return postgres_error_response("Malformed SSL request");
                    }
                    tracing::info!("POSTGRES SSLRequest from client, declining");
                    vec![b'N']
                } else if pg_version == POSTGRES_GSSENC_REQUEST {
                    if len != 8 {
                        return postgres_error_response("Malformed GSSENC request");
                    }
                    tracing::info!("POSTGRES GSSENCRequest from client, declining");
                    vec![b'N']
                } else if pg_version == 196608 {
                    let params = &data[8..len];
                    if !Self::startup_parameters_are_complete(params) {
                        tracing::debug!("POSTGRES malformed startup parameter list");
                        return postgres_error_response("Malformed startup packet");
                    }
                    tracing::info!(
                        "POSTGRES startup (server v{}): client version=0x{:08x}",
                        self.version,
                        pg_version
                    );
                    if !params.is_empty() {
                        let params = safe_log_field(params);
                        tracing::debug!("POSTGRES params: {}", params.replace('\0', " "));
                        tracing::info!("POSTGRES params: {}", REDACTED_QUERY_FIELD);
                    }
                    self.get_handshake_response()
                } else {
                    tracing::info!("POSTGRES unknown message: first_byte=0x{:02x}", data[0]);
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    }

    fn startup_parameters_are_complete(params: &[u8]) -> bool {
        if params.last().copied() != Some(0) {
            return false;
        }
        let final_terminator = params.len() - 1;
        let mut pos = 0usize;
        while pos < final_terminator {
            let Some(name_len) = params[pos..final_terminator]
                .iter()
                .position(|&byte| byte == 0)
            else {
                return false;
            };
            if name_len == 0 {
                return false;
            }
            pos += name_len + 1;

            let Some(value_len) = params[pos..final_terminator]
                .iter()
                .position(|&byte| byte == 0)
            else {
                return false;
            };
            pos += value_len + 1;
        }
        pos == final_terminator
    }

    fn typed_message_is_complete(data: &[u8]) -> bool {
        if data.len() < 5 {
            return false;
        }
        let msg_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        let min_len = match data[0] {
            b'H' | b'S' | b'X' => 4,
            b'D' | b'C' => 6,
            b'E' => 9,
            b'P' | b'B' => 8,
            b'F' => 14,
            _ => return false,
        };
        let Some(frame_len) = msg_len.checked_add(1) else {
            return false;
        };
        if msg_len < min_len || data.len() != frame_len {
            return false;
        }

        Self::typed_message_body_is_valid(data[0], &data[5..])
    }

    fn typed_message_body_is_valid(tag: u8, body: &[u8]) -> bool {
        match tag {
            b'P' => Self::parse_message_body_is_valid(body),
            b'B' => Self::bind_message_body_is_valid(body),
            b'D' | b'C' => {
                matches!(body.first(), Some(b'S' | b'P'))
                    && Self::nul_terminated_field_is_valid(&body[1..])
            }
            b'E' => {
                let mut pos = 0usize;
                Self::consume_nul_terminated_field(body, &mut pos)
                    && pos.checked_add(4) == Some(body.len())
            }
            b'F' => Self::function_call_body_is_valid(body),
            _ => true,
        }
    }

    fn bind_message_body_is_valid(body: &[u8]) -> bool {
        let mut pos = 0usize;
        if !Self::consume_nul_terminated_field(body, &mut pos)
            || !Self::consume_nul_terminated_field(body, &mut pos)
        {
            return false;
        }

        Self::consume_format_codes(body, &mut pos)
            && Self::consume_parameter_values(body, &mut pos)
            && Self::consume_format_codes(body, &mut pos)
            && pos == body.len()
    }

    fn function_call_body_is_valid(body: &[u8]) -> bool {
        let mut pos = 4usize; // function OID
        body.len() >= pos
            && Self::consume_format_codes(body, &mut pos)
            && Self::consume_parameter_values(body, &mut pos)
            && Self::consume_format_codes(body, &mut pos)
            && pos == body.len()
    }

    fn parse_message_body_is_valid(body: &[u8]) -> bool {
        let mut pos = 0usize;
        if !Self::consume_nul_terminated_field(body, &mut pos)
            || !Self::consume_nul_terminated_field(body, &mut pos)
        {
            return false;
        }
        let Some(count_end) = pos.checked_add(2) else {
            return false;
        };
        let Some(count_bytes) = body.get(pos..count_end) else {
            return false;
        };
        let parameter_count = u16::from_be_bytes([count_bytes[0], count_bytes[1]]) as usize;
        pos = count_end;
        let Some(parameter_bytes) = parameter_count.checked_mul(4) else {
            return false;
        };
        pos.checked_add(parameter_bytes) == Some(body.len())
    }

    fn consume_format_codes(data: &[u8], pos: &mut usize) -> bool {
        let Some(count) = Self::consume_u16(data, pos) else {
            return false;
        };
        let Some(bytes) = usize::from(count).checked_mul(2) else {
            return false;
        };
        let Some(end) = (*pos).checked_add(bytes) else {
            return false;
        };
        if end > data.len() {
            return false;
        }
        *pos = end;
        true
    }

    fn consume_parameter_values(data: &[u8], pos: &mut usize) -> bool {
        let Some(parameter_count) = Self::consume_u16(data, pos) else {
            return false;
        };
        for _ in 0..parameter_count {
            let Some(length_end) = (*pos).checked_add(4) else {
                return false;
            };
            let Some(length_bytes) = data.get(*pos..length_end) else {
                return false;
            };
            let value_len = i32::from_be_bytes([
                length_bytes[0],
                length_bytes[1],
                length_bytes[2],
                length_bytes[3],
            ]);
            *pos = length_end;
            if value_len < -1 {
                return false;
            }
            if value_len >= 0 {
                let Some(value_end) = (*pos).checked_add(value_len as usize) else {
                    return false;
                };
                if value_end > data.len() {
                    return false;
                }
                *pos = value_end;
            }
        }
        true
    }

    fn consume_u16(data: &[u8], pos: &mut usize) -> Option<u16> {
        let end = pos.checked_add(2)?;
        let bytes = data.get(*pos..end)?;
        *pos = end;
        Some(u16::from_be_bytes(bytes.try_into().ok()?))
    }

    fn consume_nul_terminated_field(data: &[u8], pos: &mut usize) -> bool {
        let Some(rest) = data.get(*pos..) else {
            return false;
        };
        let Some(field_len) = rest.iter().position(|&byte| byte == 0) else {
            return false;
        };
        let Some(next_pos) = (*pos).checked_add(field_len + 1) else {
            return false;
        };
        *pos = next_pos;
        true
    }

    fn nul_terminated_field_is_valid(value: &[u8]) -> bool {
        value.last().copied() == Some(0) && !value[..value.len() - 1].contains(&0)
    }
}

fn safe_log_field(data: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut rendered = String::new();
    for &byte in data.iter().take(LOG_FIELD_PREVIEW_CHARS) {
        match byte {
            b'\0' => rendered.push('\0'),
            b'\r' | b'\n' | b'\t' => rendered.push(' '),
            b if b.is_ascii_graphic() || b == b' ' => rendered.push(b as char),
            b => {
                let _ = write!(&mut rendered, "\\x{:02x}", b);
            }
        }
    }
    rendered
}

fn safe_log_text(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch != '\0' && (ch.is_control() || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
            {
                ' '
            } else {
                ch
            }
        })
        .take(LOG_FIELD_PREVIEW_CHARS)
        .collect()
}

impl Default for PostgresHandler {
    fn default() -> Self {
        Self::new()
    }
}

fn postgres_error_response(message: &str) -> Vec<u8> {
    let mut resp = Vec::new();
    let mut body = Vec::new();
    body.push(b'S');
    body.extend_from_slice(POSTGRES_FATAL_SEVERITY);
    body.push(0);
    body.push(b'C');
    body.extend_from_slice(POSTGRES_PROTOCOL_VIOLATION_CODE);
    body.push(0);
    body.push(b'M');
    body.extend_from_slice(message.as_bytes());
    body.push(0);
    body.push(0);

    let Some(body_len) = body.len().checked_add(4) else {
        return Vec::new();
    };
    let Ok(body_len) = u32::try_from(body_len) else {
        return Vec::new();
    };
    resp.push(b'E');
    resp.extend_from_slice(&body_len.to_be_bytes());
    resp.extend_from_slice(&body);
    resp.extend_from_slice(&READY_FOR_QUERY_IDLE);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gssenc_request_is_declined_like_ssl_request() {
        let mut request = Vec::new();
        request.extend_from_slice(&8u32.to_be_bytes());
        request.extend_from_slice(&POSTGRES_GSSENC_REQUEST.to_be_bytes());

        assert_eq!(PostgresHandler::new().handle(&request), b"N");
    }

    #[test]
    fn malformed_encryption_requests_are_rejected() {
        for request_code in [POSTGRES_SSL_REQUEST, POSTGRES_GSSENC_REQUEST] {
            let mut request = Vec::new();
            request.extend_from_slice(&12u32.to_be_bytes());
            request.extend_from_slice(&request_code.to_be_bytes());
            request.extend_from_slice(&0u32.to_be_bytes());

            let response = PostgresHandler::new().handle(&request);

            assert!(response.starts_with(b"E"));
            assert!(response.ends_with(&READY_FOR_QUERY_IDLE));
        }
    }

    #[test]
    fn cancel_request_is_ignored_without_panic() {
        let mut request = Vec::new();
        request.extend_from_slice(&16u32.to_be_bytes());
        request.extend_from_slice(&POSTGRES_CANCEL_REQUEST.to_be_bytes());
        request.extend_from_slice(&1234u32.to_be_bytes());
        request.extend_from_slice(&5678u32.to_be_bytes());

        assert!(PostgresHandler::new().handle(&request).is_empty());
    }

    #[test]
    fn malformed_cancel_request_is_rejected() {
        let mut request = Vec::new();
        request.extend_from_slice(&12u32.to_be_bytes());
        request.extend_from_slice(&POSTGRES_CANCEL_REQUEST.to_be_bytes());
        request.extend_from_slice(&1234u32.to_be_bytes());

        let response = PostgresHandler::new().handle(&request);

        assert!(response.starts_with(b"E"));
        assert!(response.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn malformed_query_length_does_not_panic() {
        let response = PostgresHandler::new().handle(&[b'Q', 0, 0, 0, 1]);

        assert!(response.starts_with(b"E"));
        assert!(response.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn overflowing_query_length_is_rejected() {
        let mut request = vec![b'Q'];
        request.extend_from_slice(&u32::MAX.to_be_bytes());

        let response = PostgresHandler::new().handle(&request);

        assert!(response.starts_with(b"E"));
        assert!(response.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn truncated_query_length_is_rejected() {
        let response = PostgresHandler::new().handle(&[b'Q', 0, 0, 0, 8, b'S', b'E']);

        assert!(response.starts_with(b"E"));
        assert!(response.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn query_without_nul_terminator_is_rejected() {
        let response =
            PostgresHandler::new().handle(&[b'Q', 0, 0, 0, 10, b'S', b'E', b'L', b'E', b'C', b'T']);

        assert!(response.starts_with(b"E"));
        assert!(response.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn query_with_embedded_nul_is_rejected() {
        let response =
            PostgresHandler::new().handle(&[b'Q', 0, 0, 0, 12, b'S', b'E', b'L', 0, b'C', b'T', 0]);

        assert!(response.starts_with(b"E"));
        assert!(response.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn query_rejects_invalid_utf8() {
        let response = PostgresHandler::new().handle(&[b'Q', 0, 0, 0, 8, b'S', b'E', 0xff, 0]);

        assert!(response.starts_with(b"E"));
        assert!(response.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn query_rejects_trailing_bytes_after_declared_length() {
        let response = PostgresHandler::new().handle(&[
            b'Q', 0, 0, 0, 11, b'S', b'E', b'L', b'E', b'C', b'T', 0, b'X',
        ]);

        assert!(response.starts_with(b"E"));
        assert!(response.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn malformed_startup_lengths_are_rejected() {
        let short_len = [0, 0, 0, 7, 0, 3, 0, 0];
        let short_response = PostgresHandler::new().handle(&short_len);
        assert!(short_response.starts_with(b"E"));
        assert!(short_response.ends_with(&READY_FOR_QUERY_IDLE));

        let truncated = [0, 0, 0, 12, 0, 3, 0, 0, b'u'];
        let truncated_response = PostgresHandler::new().handle(&truncated);
        assert!(truncated_response.starts_with(b"E"));
        assert!(truncated_response.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn startup_requires_final_parameter_terminator() {
        let mut startup = Vec::new();
        startup.extend_from_slice(&14u32.to_be_bytes());
        startup.extend_from_slice(&196608u32.to_be_bytes());
        startup.extend_from_slice(b"user\0x");

        let response = PostgresHandler::new().handle(&startup);
        assert!(response.starts_with(b"E"));
        assert!(response.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn startup_rejects_parameter_name_without_value() {
        let mut startup = Vec::new();
        startup.extend_from_slice(&19u32.to_be_bytes());
        startup.extend_from_slice(&196608u32.to_be_bytes());
        startup.extend_from_slice(b"user\0nettrap\0db\0");

        let response = PostgresHandler::new().handle(&startup);
        assert!(response.starts_with(b"E"));
        assert!(response.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn startup_accepts_terminated_parameter_pairs() {
        let mut startup = Vec::new();
        startup.extend_from_slice(&22u32.to_be_bytes());
        startup.extend_from_slice(&196608u32.to_be_bytes());
        startup.extend_from_slice(b"user\0nettrap\0\0");

        let response = PostgresHandler::new().handle(&startup);

        assert_eq!(response.first().copied(), Some(b'R'));
    }

    #[test]
    fn startup_accepts_minimal_16_byte_parameter_set() {
        let mut startup = Vec::new();
        startup.extend_from_slice(&16u32.to_be_bytes());
        startup.extend_from_slice(&196608u32.to_be_bytes());
        startup.extend_from_slice(b"user\0x\0\0");

        let response = PostgresHandler::new().handle(&startup);

        assert_eq!(response.first().copied(), Some(b'R'));
    }

    #[test]
    fn startup_rejects_trailing_bytes_after_declared_length() {
        let mut startup = Vec::new();
        startup.extend_from_slice(&22u32.to_be_bytes());
        startup.extend_from_slice(&196608u32.to_be_bytes());
        startup.extend_from_slice(b"user\0nettrap\0\0extra");

        let response = PostgresHandler::new().handle(&startup);
        assert!(response.starts_with(b"E"));
        assert!(response.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn typed_messages_require_complete_declared_length() {
        let incomplete = PostgresHandler::new().handle(b"S");
        assert!(incomplete.starts_with(b"E"));
        assert!(incomplete.ends_with(&READY_FOR_QUERY_IDLE));

        let short_declared = PostgresHandler::new().handle(&[b'S', 0, 0, 0, 3]);
        assert!(short_declared.starts_with(b"E"));
        assert!(short_declared.ends_with(&READY_FOR_QUERY_IDLE));

        let response = PostgresHandler::new().handle(&[b'S', 0, 0, 0, 4]);
        assert_eq!(response, b"Z\0\0\0\x05I");

        let incomplete_parse = PostgresHandler::new().handle(&[b'P', 0, 0, 0, 4]);
        assert!(incomplete_parse.starts_with(b"E"));
        assert!(incomplete_parse.ends_with(&READY_FOR_QUERY_IDLE));

        let trailing = PostgresHandler::new().handle(&[b'S', 0, 0, 0, 4, b'X']);
        assert!(trailing.starts_with(b"E"));
        assert!(trailing.ends_with(&READY_FOR_QUERY_IDLE));

        let valid_terminate = PostgresHandler::new().handle(&[b'X', 0, 0, 0, 4]);
        assert!(valid_terminate.is_empty());

        let incomplete_terminate = PostgresHandler::new().handle(&[b'X', 0, 0, 0]);
        assert!(incomplete_terminate.starts_with(b"E"));
        assert!(incomplete_terminate.ends_with(&READY_FOR_QUERY_IDLE));

        let trailing_terminate = PostgresHandler::new().handle(&[b'X', 0, 0, 0, 4, 0]);
        assert!(trailing_terminate.starts_with(b"E"));
        assert!(trailing_terminate.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn describe_and_close_messages_validate_target_and_name() {
        let valid_describe = PostgresHandler::new().handle(&[b'D', 0, 0, 0, 6, b'S', 0]);
        assert_eq!(valid_describe, b"Z\0\0\0\x05I");

        for request in [
            &[b'D', 0, 0, 0, 6, b'X', 0][..],
            &[b'D', 0, 0, 0, 6, b'S', b'a'][..],
            &[b'C', 0, 0, 0, 8, b'P', b'a', 0, 0][..],
        ] {
            let response = PostgresHandler::new().handle(request);
            assert!(response.starts_with(b"E"));
            assert!(response.ends_with(&READY_FOR_QUERY_IDLE));
        }
    }

    #[test]
    fn parse_messages_validate_nul_fields_and_parameter_types() {
        let valid_parse = PostgresHandler::new().handle(&[
            b'P', 0, 0, 0, 16, 0, b'S', b'E', b'L', b'E', b'C', b'T', b' ', b'1', 0, 0, 0,
        ]);
        assert_eq!(valid_parse, b"Z\0\0\0\x05I");

        for request in [
            &[b'P', 0, 0, 0, 8, b's', b'q', b'l', 0][..],
            &[b'P', 0, 0, 0, 8, 0, 0, 0, 1][..],
        ] {
            let response = PostgresHandler::new().handle(request);
            assert!(response.starts_with(b"E"));
            assert!(response.ends_with(&READY_FOR_QUERY_IDLE));
        }
    }

    #[test]
    fn bind_messages_validate_declared_sections() {
        let valid_bind =
            PostgresHandler::new().handle(&[b'B', 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(valid_bind, b"Z\0\0\0\x05I");

        let truncated_bind = PostgresHandler::new().handle(&[b'B', 0, 0, 0, 8, 0, 0, 0, 1]);
        assert!(truncated_bind.starts_with(b"E"));
        assert!(truncated_bind.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn execute_messages_validate_portal_name() {
        let valid_execute = PostgresHandler::new().handle(&[b'E', 0, 0, 0, 9, 0, 0, 0, 0, 0]);
        assert_eq!(valid_execute, b"Z\0\0\0\x05I");

        let unterminated_execute =
            PostgresHandler::new().handle(&[b'E', 0, 0, 0, 9, b'p', b'o', b'r', b't', 0]);
        assert!(unterminated_execute.starts_with(b"E"));
        assert!(unterminated_execute.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn function_call_messages_validate_declared_sections() {
        let valid_function_call =
            PostgresHandler::new().handle(&[b'F', 0, 0, 0, 14, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(valid_function_call, b"Z\0\0\0\x05I");

        let truncated_function_call = PostgresHandler::new()
            .handle(&[b'F', 0, 0, 0, 18, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 4, b'a']);
        assert!(truncated_function_call.starts_with(b"E"));
        assert!(truncated_function_call.ends_with(&READY_FOR_QUERY_IDLE));
    }

    #[test]
    fn log_fields_are_single_line_except_parameter_nul_separators() {
        assert_eq!(safe_log_text("SELECT\r\n1\t--\x1b"), "SELECT  1 -- ");
        assert_eq!(safe_log_text("SELECT\u{2028}1"), "SELECT 1");
        assert_eq!(
            safe_log_field(b"user\0net\r\ntrap\x1b\0\0"),
            "user\0net  trap\\x1b\0\0"
        );
        assert_eq!(safe_log_field(b"user\xff\0"), "user\\xff\0");

        let long = "a".repeat(LOG_FIELD_PREVIEW_CHARS + 1);
        assert_eq!(safe_log_text(&long).len(), LOG_FIELD_PREVIEW_CHARS);
        assert_eq!(
            safe_log_field(long.as_bytes()).len(),
            LOG_FIELD_PREVIEW_CHARS
        );

        let binary = vec![0xff; LOG_FIELD_PREVIEW_CHARS + 1];
        assert_eq!(
            safe_log_field(&binary),
            "\\xff".repeat(LOG_FIELD_PREVIEW_CHARS)
        );
    }
}
