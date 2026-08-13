pub(crate) use nettrap_core::parse::unsigned_decimal as parse_unsigned_decimal;

pub(crate) const MAX_MEMCACHED_KEY_BYTES: usize = 250;
pub(crate) const MAX_MEMCACHED_TEXT_ARGS: usize = 1024;
pub(crate) const MAX_MEMCACHED_TEXT_LINE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_MEMCACHED_TEXT_REQUEST_BYTES: usize = 1024 * 1024;

pub(crate) fn is_storage_verb(verb: &str) -> bool {
    matches!(
        verb,
        "set" | "add" | "replace" | "append" | "prepend" | "cas"
    )
}

pub(crate) fn command_parts(cmd: &str) -> Vec<&str> {
    cmd.split_whitespace()
        .take(MAX_MEMCACHED_TEXT_ARGS + 2)
        .collect()
}

pub(crate) fn command_uses_mixed_spaces_and_tabs(cmd: &str) -> bool {
    let has_space = cmd.as_bytes().contains(&b' ');
    let has_tab = cmd.as_bytes().contains(&b'\t');
    has_space && has_tab
}

pub(crate) fn command_uses_compressed_ascii_whitespace(cmd: &str) -> bool {
    cmd.as_bytes()
        .windows(2)
        .any(|window| matches!(window, b"  " | b"\t\t"))
}

pub(crate) fn command_uses_invalid_whitespace(cmd: &str) -> bool {
    cmd.chars()
        .any(|ch| ch.is_whitespace() && !matches!(ch, ' ' | '\t'))
}

pub(crate) fn stats_response(parts: &[&str], uptime_secs: u64, unix_time_secs: i64) -> Vec<u8> {
    match parts {
        ["stats"] => {
            tracing::info!("MEMCACHED stats request");
            stats_payload(unix_time_secs, uptime_secs).into_bytes()
        }
        ["stats", detail, mode]
            if detail.eq_ignore_ascii_case("detail")
                && matches!(mode.to_ascii_lowercase().as_str(), "on" | "off") =>
        {
            b"OK\r\n".to_vec()
        }
        ["stats", detail, mode]
            if detail.eq_ignore_ascii_case("detail") && mode.eq_ignore_ascii_case("dump") =>
        {
            b"END\r\n".to_vec()
        }
        _ => b"ERROR\r\n".to_vec(),
    }
}

fn stats_payload(unix_time_secs: i64, uptime_secs: u64) -> String {
    format!(
        "STAT pid 1\r\nSTAT uptime {uptime_secs}\r\nSTAT time {unix_time_secs}\r\nSTAT version 1.6.22\r\nSTAT curr_items 0\r\nSTAT total_items 0\r\nSTAT bytes 0\r\nSTAT curr_connections 1\r\nSTAT total_connections 1\r\nEND\r\n"
    )
}

pub(crate) fn command_has_noreply(parts: &[&str]) -> bool {
    parts
        .last()
        .is_some_and(|value| value.eq_ignore_ascii_case("noreply"))
}

pub(crate) fn is_valid_key_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_MEMCACHED_KEY_BYTES
        && !value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
}

pub(crate) fn delete_command_is_valid(cmd: &str) -> bool {
    let parts = command_parts(cmd);
    if !parts
        .first()
        .is_some_and(|verb| verb.eq_ignore_ascii_case("delete"))
    {
        return false;
    }
    match parts.as_slice() {
        [_, key] => is_valid_key_token(key),
        [_, key, noreply] => is_valid_key_token(key) && noreply.eq_ignore_ascii_case("noreply"),
        _ => false,
    }
}

pub(crate) fn flush_all_command_is_valid(cmd: &str) -> bool {
    let parts = command_parts(cmd);
    if !parts
        .first()
        .is_some_and(|verb| verb.eq_ignore_ascii_case("flush_all"))
    {
        return false;
    }
    match parts.as_slice() {
        [_] => true,
        [_, arg] => {
            arg.eq_ignore_ascii_case("noreply") || parse_unsigned_decimal::<u32>(arg).is_some()
        }
        [_, delay, noreply] => {
            parse_unsigned_decimal::<u32>(delay).is_some()
                && noreply.eq_ignore_ascii_case("noreply")
        }
        _ => false,
    }
}

pub(crate) fn touch_command_is_valid(cmd: &str) -> bool {
    let parts = command_parts(cmd);
    if !parts
        .first()
        .is_some_and(|verb| verb.eq_ignore_ascii_case("touch"))
    {
        return false;
    }
    match parts.as_slice() {
        [_, key, exptime] => {
            is_valid_key_token(key) && parse_unsigned_decimal::<u32>(exptime).is_some()
        }
        [_, key, exptime, noreply] => {
            is_valid_key_token(key)
                && parse_unsigned_decimal::<u32>(exptime).is_some()
                && noreply.eq_ignore_ascii_case("noreply")
        }
        _ => false,
    }
}

pub(crate) fn verbosity_command_is_valid(cmd: &str) -> bool {
    let parts = command_parts(cmd);
    if !parts
        .first()
        .is_some_and(|verb| verb.eq_ignore_ascii_case("verbosity"))
    {
        return false;
    }
    match parts.as_slice() {
        [_, level] => parse_unsigned_decimal::<u32>(level).is_some(),
        _ => false,
    }
}

pub(crate) fn counter_command_is_valid(cmd: &str, verb: &str) -> bool {
    let parts = command_parts(cmd);
    if !parts
        .first()
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(verb))
    {
        return false;
    }
    match parts.as_slice() {
        [_, key, delta] => {
            is_valid_key_token(key) && parse_unsigned_decimal::<u64>(delta).is_some()
        }
        [_, key, delta, noreply] => {
            is_valid_key_token(key)
                && parse_unsigned_decimal::<u64>(delta).is_some()
                && noreply.eq_ignore_ascii_case("noreply")
        }
        _ => false,
    }
}

pub(crate) fn storage_command_is_complete(data: &[u8], verb: &str) -> bool {
    let Some(header_end) = find_crlf(data) else {
        return false;
    };
    let Ok(header) = std::str::from_utf8(&data[..header_end]) else {
        return false;
    };

    let parts = command_parts(header);
    let required_parts = if verb == "cas" { 6 } else { 5 };
    if parts.len() < required_parts || parts.len() > required_parts + 1 {
        return false;
    }
    if !parts[0].eq_ignore_ascii_case(verb) || parts[1].is_empty() {
        return false;
    }
    if !is_valid_key_token(parts[1]) {
        return false;
    }
    if parts.len() == required_parts + 1 && !parts[required_parts].eq_ignore_ascii_case("noreply") {
        return false;
    }
    if parse_unsigned_decimal::<u32>(parts[2]).is_none()
        || parse_unsigned_decimal::<u32>(parts[3]).is_none()
    {
        return false;
    }
    let Some(body_len) = parse_unsigned_decimal::<usize>(parts[4]) else {
        return false;
    };
    if verb == "cas" && parse_unsigned_decimal::<u64>(parts[5]).is_none() {
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

pub(crate) fn storage_command_has_noreply(data: &[u8], verb: &str) -> bool {
    let Some(header_end) = find_crlf(data) else {
        return false;
    };
    let Ok(header) = std::str::from_utf8(&data[..header_end]) else {
        return false;
    };

    let parts = command_parts(header);
    let required_parts = if verb == "cas" { 6 } else { 5 };
    parts
        .get(required_parts)
        .is_some_and(|value| value.eq_ignore_ascii_case("noreply"))
}

pub(crate) fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|window| window == b"\r\n")
}

pub(crate) fn safe_log_line(value: &str) -> String {
    nettrap_core::sanitize::single_line(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat_value<'a>(stats: &'a str, key: &str) -> Option<&'a str> {
        stats.lines().find_map(|line| {
            let mut parts = line.split(' ');
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some("STAT"), Some(candidate), Some(value), None) if candidate == key => {
                    Some(value)
                }
                _ => None,
            }
        })
    }

    #[test]
    fn stats_payload_uses_supplied_unix_time() {
        let stats = stats_payload(1_800_000_000, 123);

        assert_eq!(stat_value(&stats, "time"), Some("1800000000"));
        assert_eq!(stat_value(&stats, "uptime"), Some("123"));
    }

    #[test]
    fn stats_response_uses_supplied_unix_time() {
        let response = stats_response(&["stats"], 456, 1_800_000_000);
        let response = String::from_utf8(response).expect("stats response should be UTF-8");
        let reported = stat_value(&response, "time")
            .expect("stats response should include time")
            .parse::<i64>()
            .expect("time should be numeric");

        assert_eq!(reported, 1_800_000_000);
        assert_eq!(stat_value(&response, "uptime"), Some("456"));
    }

    #[test]
    fn stats_response_preserves_pre_epoch_time() {
        let response = stats_response(&["stats"], 456, -1);
        let response = String::from_utf8(response).expect("stats response should be UTF-8");

        assert_eq!(stat_value(&response, "time"), Some("-1"));
    }

    #[test]
    fn is_valid_key_token_rejects_c1_controls() {
        assert!(!is_valid_key_token("cache\u{009f}key"));
    }
}
