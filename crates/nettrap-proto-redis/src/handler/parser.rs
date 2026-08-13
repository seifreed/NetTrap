use super::*;

impl RedisHandler {
    /// Parse RESP protocol (Redis Serialization Protocol).
    pub(crate) fn parse_resp(data: &[u8]) -> Option<Vec<Vec<Vec<u8>>>> {
        if data.len() > MAX_RESP_FRAME_SIZE {
            tracing::warn!("RESP frame too large ({} bytes), rejecting", data.len());
            return None;
        }

        let mut commands = Vec::new();
        let mut pos = 0usize;

        while pos < data.len() {
            while data.get(pos..pos + 2) == Some(b"\r\n") {
                pos += 2;
            }
            if pos >= data.len() {
                break;
            }

            if data[pos] == b'*' {
                let (parts, next_pos) = Self::parse_resp_array_at(data, pos)?;
                if !parts.is_empty() {
                    if commands.len() >= MAX_RESP_COMMANDS {
                        tracing::warn!("RESP command batch too large, rejecting");
                        return None;
                    }
                    commands.push(parts);
                }
                pos = next_pos;
                continue;
            }

            let line_end = find_crlf_from(data, pos)?;
            let line = &data[pos..line_end];
            if line.len() > MAX_INLINE_COMMAND_BYTES {
                tracing::warn!(
                    "Redis inline command too large ({} bytes), rejecting",
                    line.len()
                );
                return None;
            }
            let text = std::str::from_utf8(line).ok()?;
            if text.chars().any(|ch| ch.is_control() && ch != ' ') {
                return None;
            }
            if text.chars().next().is_some_and(char::is_whitespace)
                || text
                    .chars()
                    .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
            {
                return None;
            }
            let parts: Vec<Vec<u8>> = text
                .split(' ')
                .take(MAX_INLINE_COMMAND_ARGS + 1)
                .map(|s| s.as_bytes().to_vec())
                .collect();
            if parts.iter().skip(1).any(|part| part.is_empty()) {
                return None;
            }
            if parts.len() > MAX_INLINE_COMMAND_ARGS {
                tracing::warn!("Redis inline command has too many arguments, rejecting");
                return None;
            }
            if !parts.is_empty() {
                if commands.len() >= MAX_RESP_COMMANDS {
                    tracing::warn!("RESP command batch too large, rejecting");
                    return None;
                }
                commands.push(parts);
            }
            pos = line_end + 2;
        }
        Some(commands)
    }

    fn parse_resp_array_at(data: &[u8], start: usize) -> Option<(Vec<Vec<u8>>, usize)> {
        let header_end = find_crlf_from(data, start)?;
        let count_text = std::str::from_utf8(&data[start + 1..header_end]).ok()?;
        let count = parse_resp_array_count(count_text)?;
        if count == 0 {
            return None;
        }
        if count > MAX_RESP_ARRAY_COUNT {
            tracing::warn!("RESP array too large ({count}), rejecting");
            return None;
        }

        let mut pos = header_end + 2;
        let mut parts = Vec::new();
        for _ in 0..count {
            if data.get(pos) != Some(&b'$') {
                return None;
            }

            let bulk_header_end = find_crlf_from(data, pos)?;
            let bulk_len_text = std::str::from_utf8(&data[pos + 1..bulk_header_end]).ok()?;
            let bulk_len = parse_resp_bulk_len(bulk_len_text)?;
            pos = bulk_header_end + 2;

            let bulk_len = bulk_len?;
            if bulk_len > MAX_RESP_BULK_SIZE {
                tracing::warn!("RESP bulk string too large ({bulk_len}), rejecting");
                return None;
            }
            let data_end = pos.checked_add(bulk_len)?;
            let frame_end = data_end.checked_add(2)?;
            if frame_end > data.len() || &data[data_end..frame_end] != b"\r\n" {
                return None;
            }

            parts.push(data[pos..data_end].to_vec());
            pos = frame_end;
        }

        Some((parts, pos))
    }
}
