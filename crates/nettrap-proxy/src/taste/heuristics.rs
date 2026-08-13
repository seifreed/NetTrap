//! Byte-pattern heuristics shared by the `ProtocolTaste` implementations.

use nettrap_core::parse::{
    absolute_http_authority as absolute_form_authority, nonzero_port as parse_http_port,
    unsigned_decimal as parse_unsigned_decimal,
};
use nettrap_core::sanitize::{has_numeric_domain_labels, has_valid_domain_labels};
use serde::de::Deserializer as _;
use serde::de::{self, IgnoredAny, MapAccess, Visitor};

#[path = "mqtt.rs"]
mod mqtt;
#[path = "mysql.rs"]
mod mysql;
#[path = "postgres.rs"]
mod postgres;

pub(crate) use mqtt::looks_like_mqtt_client_packet;
pub(crate) use mysql::looks_like_mysql_client_packet;
pub(crate) use postgres::{
    looks_like_postgres_cancel_request, looks_like_postgres_startup_message,
    looks_like_postgres_typed_message,
};

const MAX_NKN_JSON_RPC_TASTE_BYTES: usize = 4096;
const MAX_NKN_JSON_RPC_METHOD_BYTES: usize = 128;
const MAX_NKN_JSON_RPC_ID_STRING_BYTES: usize = 256;
const MQTT_MAX_PACKET_BYTES: usize = 1024 * 1024;
const MQTT_MAX_VARIABLE_BYTE_INTEGER: usize = 268_435_455;
const MAX_MEMCACHED_KEY_BYTES: usize = 250;
const MYSQL_CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const MYSQL_CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const MYSQL_CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const MYSQL_CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const MYSQL_CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;
const MYSQL_CLIENT_CONNECT_ATTRS: u32 = 0x0010_0000;
const MAX_SNMP_COMMUNITY_BYTES: usize = 1024;
const MAX_SYSLOG_PACKET_BYTES: usize = 1024;
const TFTP_MAX_CONTROL_PACKET_BYTES: usize = u16::MAX as usize - 8;

#[derive(Debug)]
struct NknJsonRpcTaste {
    jsonrpc: Option<String>,
    method: Option<String>,
    id: Option<serde_json::Value>,
}

pub(crate) fn first_ascii_token(data: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(data).ok()?;
    if text
        .chars()
        .any(|ch| matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
    {
        return None;
    }
    if text
        .as_bytes()
        .iter()
        .enumerate()
        .any(|(idx, &byte)| byte == b'\n' && (idx == 0 || text.as_bytes()[idx - 1] != b'\r'))
    {
        return None;
    }
    if text
        .as_bytes()
        .iter()
        .enumerate()
        .any(|(idx, &byte)| byte == b'\r' && text.as_bytes().get(idx + 1) != Some(&b'\n'))
    {
        return None;
    }
    let line = text.strip_suffix("\r\n").unwrap_or(text);
    if line.contains("\r\n") {
        return None;
    }
    if line.chars().last().is_some_and(char::is_whitespace) {
        return None;
    }
    line.split(' ').next()
}

pub(crate) fn command_token_matches(data: &[u8], commands: &[&str]) -> bool {
    let Some(token) = first_ascii_token(data) else {
        return false;
    };
    commands
        .iter()
        .any(|command| token.eq_ignore_ascii_case(command))
}

pub(crate) fn looks_like_irc_command_line(data: &[u8]) -> bool {
    let Some(token) = first_ascii_token(data) else {
        return false;
    };
    !data.contains(&0)
        && data.ends_with(b"\r\n")
        && !token.is_empty()
        && token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'_' | b'-' | b'[' | b']' | b'\\' | b'`' | b'^' | b'{' | b'}' | b'|'
                )
        })
}

pub(crate) fn looks_like_memcached_text_request(data: &[u8]) -> bool {
    let Some(command_end) = memcached_text_command_end(data) else {
        return false;
    };
    command_end == data.len()
}

fn memcached_text_command_end(data: &[u8]) -> Option<usize> {
    let line = first_text_line(data)?;
    if data
        .iter()
        .enumerate()
        .any(|(idx, &byte)| byte == b'\n' && (idx == 0 || data[idx - 1] != b'\r'))
    {
        return None;
    }
    if line.is_empty()
        || line.chars().next().is_some_and(char::is_whitespace)
        || line.chars().last().is_some_and(char::is_whitespace)
    {
        return None;
    }

    if line.chars().any(|ch| ch.is_whitespace() && ch != ' ') {
        return None;
    }
    let parts: Vec<&str> = line.split(' ').collect();
    if parts.iter().skip(1).any(|part| part.is_empty()) {
        return None;
    }
    let verb = parts.first().copied()?;

    if is_storage_verb(verb) {
        return memcached_storage_command_end(data, verb);
    }

    let line_end = find_crlf(data)?;
    let command_end = line_end + 2;

    let valid = if verb.eq_ignore_ascii_case("stats") {
        match parts[1..] {
            [] => true,
            [detail, mode] => {
                detail.eq_ignore_ascii_case("detail")
                    && matches!(mode.to_ascii_lowercase().as_str(), "on" | "off" | "dump")
            }
            _ => false,
        }
    } else if verb.eq_ignore_ascii_case("version") || verb.eq_ignore_ascii_case("quit") {
        parts.len() == 1
    } else if verb.eq_ignore_ascii_case("get") || verb.eq_ignore_ascii_case("gets") {
        parts.len() > 1 && parts[1..].iter().all(|key| is_valid_memcached_key(key))
    } else if verb.eq_ignore_ascii_case("gat") || verb.eq_ignore_ascii_case("gats") {
        parts.len() >= 3
            && parse_unsigned_decimal::<u32>(parts[1]).is_some()
            && parts[2..].iter().all(|key| is_valid_memcached_key(key))
    } else if verb.eq_ignore_ascii_case("delete") {
        match parts.as_slice() {
            [_, key] => is_valid_memcached_key(key),
            [_, key, noreply] => {
                is_valid_memcached_key(key) && noreply.eq_ignore_ascii_case("noreply")
            }
            _ => false,
        }
    } else if verb.eq_ignore_ascii_case("flush_all") {
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
    } else if verb.eq_ignore_ascii_case("touch") {
        match parts.as_slice() {
            [_, key, exptime] => {
                is_valid_memcached_key(key) && parse_unsigned_decimal::<u32>(exptime).is_some()
            }
            [_, key, exptime, noreply] => {
                is_valid_memcached_key(key)
                    && parse_unsigned_decimal::<u32>(exptime).is_some()
                    && noreply.eq_ignore_ascii_case("noreply")
            }
            _ => false,
        }
    } else if verb.eq_ignore_ascii_case("incr") || verb.eq_ignore_ascii_case("decr") {
        match parts.as_slice() {
            [_, key, delta] => {
                is_valid_memcached_key(key) && parse_unsigned_decimal::<u64>(delta).is_some()
            }
            [_, key, delta, noreply] => {
                is_valid_memcached_key(key)
                    && parse_unsigned_decimal::<u64>(delta).is_some()
                    && noreply.eq_ignore_ascii_case("noreply")
            }
            _ => false,
        }
    } else if verb.eq_ignore_ascii_case("verbosity") {
        match parts.as_slice() {
            [_, level] => parse_unsigned_decimal::<u32>(level).is_some(),
            _ => false,
        }
    } else {
        false
    };

    valid.then_some(command_end)
}

pub(crate) fn looks_like_redis_inline_request(data: &[u8]) -> bool {
    let Some(line_end) = redis_inline_request_end(data) else {
        return false;
    };
    redis_sample_tail_is_plausible(data, line_end)
}

fn redis_inline_request_end(data: &[u8]) -> Option<usize> {
    let line_end = find_crlf_from(data, 0)?;
    let line = first_text_line(data)?;
    if data
        .iter()
        .enumerate()
        .any(|(idx, &byte)| byte == b'\n' && (idx == 0 || data[idx - 1] != b'\r'))
    {
        return None;
    }
    if line.is_empty()
        || line.chars().next().is_some_and(char::is_whitespace)
        || line.chars().last().is_some_and(char::is_whitespace)
        || line
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return None;
    }

    let parts: Vec<&str> = line.split(' ').collect();
    if parts.iter().skip(1).any(|part| part.is_empty()) {
        return None;
    }
    let verb = parts.first().copied()?;
    let args = &parts[1..];

    let valid = match verb.to_ascii_uppercase().as_str() {
        "PING" => matches!(args, [] | [_]),
        "ECHO" => args.len() == 1 && is_valid_redis_token(args[0]),
        "HELLO" => redis_hello_args_are_valid(args),
        "INFO" => args.len() <= 1,
        "TIME" | "ROLE" => args.is_empty(),
        "AUTH" => matches!(args.len(), 1 | 2) && args.iter().all(|arg| !arg.is_empty()),
        "SET" => redis_set_args_are_valid(args),
        "GET" => args.len() == 1 && is_valid_redis_token(args[0]),
        "GETDEL" | "TTL" | "PTTL" | "EXPIRETIME" | "PEXPIRETIME" | "TYPE" | "STRLEN" | "INCR"
        | "DECR" => args.len() == 1 && is_valid_redis_token(args[0]),
        "GETSET" | "SETNX" | "APPEND" => redis_tokens_are_valid(args, 2),
        "DEL" | "EXISTS" | "MGET" => {
            !args.is_empty() && args.iter().all(|arg| is_valid_redis_token(arg))
        }
        "SETEX" | "PSETEX" => redis_setex_args_are_valid(args),
        "MSET" | "MSETNX" => redis_mset_args_are_valid(args),
        "INCRBY" | "DECRBY" => redis_incrby_args_are_valid(args),
        "EXPIRE" | "PEXPIRE" | "EXPIREAT" | "PEXPIREAT" => redis_expire_args_are_valid(args),
        "CONFIG" => redis_config_args_are_valid(args),
        "SLAVEOF" | "REPLICAOF" => redis_replication_args_are_valid(args),
        "MODULE" => true,
        "EVAL" => redis_eval_args_are_valid("EVAL", args),
        "EVALSHA" => redis_eval_args_are_valid("EVALSHA", args),
        "FLUSHALL" | "FLUSHDB" => redis_flush_args_are_valid(args),
        "DBSIZE" => args.is_empty(),
        "SELECT" => args.len() == 1 && parse_unsigned_decimal::<u64>(args[0]).is_some(),
        "QUIT" => args.is_empty(),
        "COMMAND" => args.is_empty(),
        "CLUSTER" => true,
        "CLIENT" => true,
        "SAVE" => args.is_empty(),
        "BGSAVE" => redis_bgsave_args_are_valid(args),
        _ => false,
    };

    valid.then_some(line_end + 2)
}

pub(crate) fn first_text_line(data: &[u8]) -> Option<&str> {
    let line_end = data
        .iter()
        .position(|&byte| byte == b'\n')
        .unwrap_or(data.len());
    let line = data
        .get(..line_end)?
        .strip_suffix(b"\r")
        .unwrap_or(&data[..line_end]);
    let text = std::str::from_utf8(line).ok()?;
    if text
        .chars()
        .any(|ch| matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
    {
        return None;
    }
    Some(text)
}

fn is_valid_memcached_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 250
        && !value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
}

fn is_storage_verb(verb: &str) -> bool {
    ["set", "add", "replace", "append", "prepend", "cas"]
        .iter()
        .any(|candidate| verb.eq_ignore_ascii_case(candidate))
}

fn memcached_storage_command_end(data: &[u8], verb: &str) -> Option<usize> {
    let header_end = find_crlf(data)?;
    let Ok(header) = std::str::from_utf8(&data[..header_end]) else {
        return None;
    };

    let parts: Vec<&str> = header.split(' ').collect();
    let required_parts = if verb.eq_ignore_ascii_case("cas") {
        6
    } else {
        5
    };
    if parts.len() < required_parts || parts.len() > required_parts + 1 {
        return None;
    }
    if !parts[0].eq_ignore_ascii_case(verb) || !is_valid_memcached_key(parts[1]) {
        return None;
    }
    if parts.len() == required_parts + 1 && !parts[required_parts].eq_ignore_ascii_case("noreply") {
        return None;
    }
    if parse_unsigned_decimal::<u32>(parts[2]).is_none()
        || parse_unsigned_decimal::<u32>(parts[3]).is_none()
    {
        return None;
    }
    let body_len = parse_unsigned_decimal::<usize>(parts[4])?;
    if verb.eq_ignore_ascii_case("cas") && parse_unsigned_decimal::<u64>(parts[5]).is_none() {
        return None;
    }

    let body_start = header_end + 2;
    let body_end = body_start.checked_add(body_len)?;
    let packet_end = body_end.checked_add(2)?;
    if data.get(body_end..packet_end) == Some(&b"\r\n"[..]) {
        Some(packet_end)
    } else {
        None
    }
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|window| window == b"\r\n")
}

fn is_valid_redis_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| !ch.is_control() && !ch.is_whitespace())
}

fn parse_signed_decimal<T: std::str::FromStr>(value: &str) -> Option<T> {
    if value.is_empty() {
        return None;
    }
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn redis_tokens_are_valid(args: &[&str], count: usize) -> bool {
    args.len() == count && args.iter().all(|arg| is_valid_redis_token(arg))
}

fn redis_hello_args_are_valid(args: &[&str]) -> bool {
    let Some((&version, rest)) = args.split_first() else {
        return true;
    };
    if !matches!(version, "2" | "3") {
        return false;
    }

    let mut index = 0usize;
    let mut saw_auth = false;
    let mut saw_setname = false;
    while index < rest.len() {
        match rest[index].to_ascii_uppercase().as_str() {
            "AUTH" => {
                if saw_auth
                    || !rest.get(index + 1..index + 3).is_some_and(|values| {
                        values.iter().all(|value| is_valid_redis_token(value))
                    })
                {
                    return false;
                }
                saw_auth = true;
                index += 3;
            }
            "SETNAME" => {
                if saw_setname
                    || !rest
                        .get(index + 1)
                        .is_some_and(|value| is_valid_redis_token(value))
                {
                    return false;
                }
                saw_setname = true;
                index += 2;
            }
            _ => return false,
        }
    }
    true
}

fn redis_setex_args_are_valid(args: &[&str]) -> bool {
    args.len() == 3
        && is_valid_redis_token(args[0])
        && parse_unsigned_decimal::<u64>(args[1]).is_some_and(|value| value != 0)
        && is_valid_redis_token(args[2])
}

fn redis_mset_args_are_valid(args: &[&str]) -> bool {
    !args.is_empty()
        && args.len().is_multiple_of(2)
        && args.iter().all(|arg| is_valid_redis_token(arg))
}

fn redis_incrby_args_are_valid(args: &[&str]) -> bool {
    args.len() == 2
        && is_valid_redis_token(args[0])
        && parse_signed_decimal::<i64>(args[1]).is_some()
}

fn redis_expire_args_are_valid(args: &[&str]) -> bool {
    if !(args.len() == 2 || args.len() == 3)
        || !is_valid_redis_token(args[0])
        || parse_unsigned_decimal::<u64>(args[1]).is_none()
    {
        return false;
    }
    args.get(2).is_none_or(|option| {
        matches!(
            option.to_ascii_uppercase().as_str(),
            "NX" | "XX" | "GT" | "LT"
        )
    })
}

fn redis_set_args_are_valid(args: &[&str]) -> bool {
    if args.len() < 2 || !args.iter().all(|arg| !arg.is_empty()) {
        return false;
    }

    let mut index = 2usize;
    let mut saw_expiry = false;
    let mut saw_condition = false;
    while index < args.len() {
        match args[index].to_ascii_uppercase().as_str() {
            "EX" | "PX" => {
                if saw_expiry {
                    return false;
                }
                saw_expiry = true;
                index += 1;
                let Some(expiry) = args.get(index) else {
                    return false;
                };
                if parse_unsigned_decimal::<u64>(expiry).is_none_or(|value| value == 0) {
                    return false;
                }
            }
            "NX" | "XX" => {
                if saw_condition {
                    return false;
                }
                saw_condition = true;
            }
            _ => return false,
        }
        index += 1;
    }

    true
}

fn redis_config_args_are_valid(args: &[&str]) -> bool {
    match args {
        [subcommand, key] if subcommand.eq_ignore_ascii_case("GET") => !key.is_empty(),
        [subcommand, key, value] if subcommand.eq_ignore_ascii_case("SET") => {
            !key.is_empty() && !value.is_empty()
        }
        _ => false,
    }
}

fn redis_replication_args_are_valid(args: &[&str]) -> bool {
    if args.len() != 2 {
        return false;
    }
    if args[0].eq_ignore_ascii_case("NO") && args[1].eq_ignore_ascii_case("ONE") {
        return true;
    }
    if !is_valid_redis_replication_host(args[0]) {
        return false;
    }
    parse_unsigned_decimal::<u16>(args[1]).is_some_and(|port| port != 0)
}

fn is_valid_redis_replication_host(host: &str) -> bool {
    if let Some(rest) = host.strip_prefix('[') {
        let Some((inner, suffix)) = rest.split_once(']') else {
            return false;
        };
        return suffix.is_empty()
            && inner.parse::<std::net::Ipv6Addr>().is_ok_and(|ip| {
                !ip.is_unspecified()
                    && ip
                        .to_ipv4_mapped()
                        .is_none_or(is_usable_redis_replication_ipv4)
            });
    }

    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return is_usable_redis_replication_ipv4(ip);
    }
    if let Some(host) = host.strip_suffix('.')
        && (host.is_empty() || host.ends_with('.'))
    {
        return false;
    }

    let host = host.strip_suffix('.').unwrap_or(host);
    host.len() <= 253
        && nettrap_core::sanitize::has_valid_domain_labels(host)
        && !nettrap_core::sanitize::has_numeric_domain_labels(host)
}

fn redis_eval_args_are_valid(_command: &str, args: &[&str]) -> bool {
    if args.len() < 2 {
        return false;
    }
    let Some(key_count) = parse_unsigned_decimal::<usize>(args[1]) else {
        return false;
    };
    key_count <= args.len().saturating_sub(2)
}

fn redis_flush_args_are_valid(args: &[&str]) -> bool {
    match args {
        [] => true,
        [mode] => mode.eq_ignore_ascii_case("ASYNC") || mode.eq_ignore_ascii_case("SYNC"),
        _ => false,
    }
}

fn redis_bgsave_args_are_valid(args: &[&str]) -> bool {
    match args {
        [] => true,
        [mode] => mode.eq_ignore_ascii_case("SCHEDULE"),
        _ => false,
    }
}

pub(crate) fn looks_like_http_start_line(data: &[u8]) -> bool {
    if !header_line_endings_are_plausible(data) {
        return false;
    }
    let Some(line) = first_text_line(data) else {
        return false;
    };
    let mut parts = line.split(' ');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return false;
    };
    let Some(third) = parts.next() else {
        return false;
    };
    if parts.next().is_some() || second.is_empty() || third.is_empty() {
        return false;
    }

    is_http_token(first)
        && matches!(third, "HTTP/1.0" | "HTTP/1.1")
        && is_valid_http_target_for_method(first, second)
}

pub(crate) fn looks_like_http_request_line_shape(data: &[u8]) -> bool {
    if !header_line_endings_are_plausible(data) {
        return false;
    }
    let Some(line) = first_text_line(data) else {
        return false;
    };
    let mut parts = line.split(' ');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return false;
    };
    let Some(third) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && !second.is_empty()
        && !third.is_empty()
        && is_http_token(first)
        && matches!(third, "HTTP/1.0" | "HTTP/1.1")
}

fn header_line_endings_are_plausible(data: &[u8]) -> bool {
    let end = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(data.len(), |idx| idx + 4);
    crlf_line_endings_are_plausible(&data[..end])
}

fn crlf_line_endings_are_plausible(data: &[u8]) -> bool {
    !data
        .iter()
        .enumerate()
        .any(|(idx, &byte)| byte == b'\n' && (idx == 0 || data[idx - 1] != b'\r'))
        && !data
            .iter()
            .enumerate()
            .any(|(idx, &byte)| byte == b'\r' && idx + 1 < data.len() && data[idx + 1] != b'\n')
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_valid_http_target_for_method(method: &str, value: &str) -> bool {
    if !is_valid_http_target_syntax(value) {
        return false;
    }

    if value == "*" {
        return method.eq_ignore_ascii_case("OPTIONS");
    }

    if is_authority_form_target(value) {
        return method.eq_ignore_ascii_case("CONNECT");
    }

    if let Some(authority) = absolute_form_authority(value) {
        if !is_valid_authority_port(authority) {
            return false;
        }
    } else if value.contains("://") {
        return false;
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        return false;
    }

    true
}

fn is_valid_http_target_syntax(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace())
        && !value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        && (value == "*"
            || value.starts_with('/')
            || value.contains("://")
            || is_authority_form_target(value))
}

fn is_authority_form_target(value: &str) -> bool {
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if host.is_empty() || parse_http_port(port).is_none() {
        return false;
    }

    if let Some(rest) = host.strip_prefix('[') {
        let Some((inner, suffix)) = rest.split_once(']') else {
            return false;
        };
        return !inner.is_empty()
            && inner
                .parse::<std::net::Ipv6Addr>()
                .is_ok_and(|ip| !is_special_http_authority_ipv6_literal(ip))
            && suffix.is_empty();
    }

    !host.contains(':')
        && !host.contains('@')
        && !host.contains('/')
        && !host.contains('\\')
        && !host.contains('?')
        && !host.contains('#')
        && host.len() <= 253
        && (host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| !is_special_http_authority_ipv4_literal(ip))
            || host_is_valid_authority_host(host))
}

fn is_valid_authority_port(authority: &str) -> bool {
    if authority.contains('@') {
        return false;
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let Some((inner, suffix)) = rest.split_once(']') else {
            return false;
        };
        if inner.is_empty() || !suffix.is_empty() && !suffix.starts_with(':') {
            return false;
        }
        if suffix.is_empty() {
            return inner
                .parse::<std::net::Ipv6Addr>()
                .is_ok_and(|ip| !is_special_http_authority_ipv6_literal(ip));
        }
        if suffix[1..].contains(':') {
            return false;
        }
        return inner
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| !is_special_http_authority_ipv6_literal(ip))
            && parse_http_port(&suffix[1..]).is_some();
    }

    if let Some((host, port)) = authority.rsplit_once(':') {
        if host.is_empty() {
            return false;
        }
        if host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| !is_special_http_authority_ipv4_literal(ip))
        {
            return parse_http_port(port).is_some();
        }
        return host_is_valid_authority_host(host) && parse_http_port(port).is_some();
    }

    if authority
        .parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| !is_special_http_authority_ipv4_literal(ip))
    {
        return true;
    }
    host_is_valid_authority_host(authority)
}

fn is_special_http_authority_ipv4_literal(ip: std::net::Ipv4Addr) -> bool {
    ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()
}

fn is_special_http_authority_ipv6_literal(ip: std::net::Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_special_http_authority_ipv4_literal(mapped);
    }

    ip.is_unspecified() || ip.is_loopback() || ip.is_multicast()
}

fn host_is_valid_authority_host(host: &str) -> bool {
    let host = if let Some(host) = host.strip_suffix('.') {
        if host.is_empty() || host.ends_with('.') {
            return false;
        }
        host
    } else {
        host
    };
    !host.contains(':')
        && !host.contains('/')
        && !host.contains('\\')
        && !host.contains('?')
        && !host.contains('#')
        && host.len() <= 253
        && has_valid_domain_labels(host)
        && !has_numeric_domain_labels(host)
}

fn is_usable_redis_replication_ipv4(ip: std::net::Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
}

pub(crate) fn looks_like_dns_query(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_query = (flags & 0x8000) == 0;
    let opcode = (flags >> 11) & 0x0f;
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let nscount = u16::from_be_bytes([data[8], data[9]]);
    let arcount = u16::from_be_bytes([data[10], data[11]]);

    if !is_query || opcode != 0 || qdcount != 1 || ancount != 0 || nscount != 0 {
        return false;
    }

    let Some(question_end) = dns_question_section_end(data, qdcount) else {
        return false;
    };

    match arcount {
        0 => question_end == data.len(),
        1 => dns_opt_record_is_well_formed(data, question_end),
        _ => false,
    }
}

fn dns_question_section_end(data: &[u8], qdcount: u16) -> Option<usize> {
    let mut pos = 12usize;

    for _ in 0..qdcount {
        pos = dns_name_end(data, pos, 0)?;

        pos = match pos.checked_add(4) {
            Some(next) if next <= data.len() => next,
            _ => return None,
        };
    }

    Some(pos)
}

fn dns_name_end(data: &[u8], mut pos: usize, depth: u8) -> Option<usize> {
    if depth > 8 {
        return None;
    }

    loop {
        let &label_len = data.get(pos)?;

        match label_len & 0xc0 {
            0x00 => {
                pos += 1;
                if label_len == 0 {
                    return Some(pos);
                }
                pos = match pos.checked_add(label_len as usize) {
                    Some(next) if next <= data.len() => next,
                    _ => return None,
                };
            }
            0xc0 => {
                let &pointer_low = data.get(pos + 1)?;
                let pointer = (((label_len & 0x3f) as usize) << 8) | pointer_low as usize;
                if pointer >= pos {
                    return None;
                }
                dns_name_end(data, pointer, depth + 1)?;
                return Some(pos + 2);
            }
            _ => return None,
        }
    }
}

fn dns_opt_record_is_well_formed(data: &[u8], pos: usize) -> bool {
    let Some(next) = pos.checked_add(11) else {
        return false;
    };
    let Some(record) = data.get(pos..next) else {
        return false;
    };
    if record[0] != 0 || u16::from_be_bytes([record[1], record[2]]) != 41 {
        return false;
    }
    if u16::from_be_bytes([record[3], record[4]]) == 0 {
        return false;
    }

    let rdlen = u16::from_be_bytes([record[9], record[10]]) as usize;
    match next.checked_add(rdlen) {
        Some(end) => end == data.len(),
        None => false,
    }
}

pub(crate) fn looks_like_complete_tls_client_hello(data: &[u8]) -> bool {
    if data.len() < 9 || data[0] != 0x16 || data[1] != 0x03 || !(0x01..=0x04).contains(&data[2]) {
        return false;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let Some(record_end) = 5usize.checked_add(record_len) else {
        return false;
    };
    if record_len < 4 || record_end != data.len() || data[5] != 0x01 {
        return false;
    }

    let handshake_len = ((data[6] as usize) << 16) | ((data[7] as usize) << 8) | data[8] as usize;
    let Some(handshake_end) = 9usize.checked_add(handshake_len) else {
        return false;
    };
    handshake_len > 0
        && handshake_end >= 44
        && handshake_end == record_end
        && tls_client_hello_prefix_is_well_formed(&data[..handshake_end])
}

fn tls_client_hello_prefix_is_well_formed(data: &[u8]) -> bool {
    let mut pos = 43usize;
    let Some(&session_id_len) = data.get(pos) else {
        return false;
    };
    pos += 1 + session_id_len as usize;

    let Some(cipher_len_bytes) = data.get(pos..pos + 2) else {
        return false;
    };
    let cipher_suites_len = u16::from_be_bytes([cipher_len_bytes[0], cipher_len_bytes[1]]) as usize;
    if !cipher_suites_len.is_multiple_of(2) {
        return false;
    }
    pos += 2 + cipher_suites_len;

    let Some(&compression_methods_len) = data.get(pos) else {
        return false;
    };
    pos += 1 + compression_methods_len as usize;

    let Some(extension_len_bytes) = data.get(pos..pos + 2) else {
        return false;
    };
    let extensions_len =
        u16::from_be_bytes([extension_len_bytes[0], extension_len_bytes[1]]) as usize;
    pos += 2;

    pos.checked_add(extensions_len)
        .is_some_and(|extensions_end| extensions_end == data.len())
}

pub(crate) fn looks_like_ssh_client_version(data: &[u8]) -> bool {
    let Some(line_end) = data.iter().position(|&byte| byte == b'\n') else {
        return false;
    };
    if line_end + 1 != data.len() {
        return false;
    }
    let Some(mut line) = data.get(..line_end) else {
        return false;
    };
    let max_len = if line.ends_with(b"\r") { 253 } else { 254 };
    if line.ends_with(b"\r") {
        let Some(trimmed) = line.get(..line.len().saturating_sub(1)) else {
            return false;
        };
        line = trimmed;
    }
    if line.is_empty() || line.len() > max_len {
        return false;
    }

    let Ok(line) = std::str::from_utf8(line) else {
        return false;
    };
    let prefix_len = if line.starts_with("SSH-2.0-") {
        "SSH-2.0-".len()
    } else if line.starts_with("SSH-1.99-") {
        "SSH-1.99-".len()
    } else {
        return false;
    };
    let software_version = &line[prefix_len..];
    !software_version.is_empty()
        && !software_version.starts_with(' ')
        && line.bytes().all(|byte| matches!(byte, 0x20..=0x7e))
}

pub(crate) fn looks_like_sslv2_client_hello(data: &[u8]) -> bool {
    let Some(record_end) = sslv2_client_hello_end(data) else {
        return false;
    };
    sslv2_tail_is_plausible(data, record_end)
}

fn sslv2_client_hello_end(data: &[u8]) -> Option<usize> {
    if data.len() < 11 || (data[0] & 0x80) == 0 {
        return None;
    }

    let record_len = (((data[0] & 0x7f) as usize) << 8) | data[1] as usize;
    let record_end = 2usize.checked_add(record_len)?;
    if record_len < 9 || record_end > data.len() || data[2] != 0x01 {
        return None;
    }

    if !matches!([data[3], data[4]], [0x00, 0x02] | [0x03, 0x00..=0x04]) {
        return None;
    }

    let cipher_specs_len = u16::from_be_bytes([data[5], data[6]]) as usize;
    let session_id_len = u16::from_be_bytes([data[7], data[8]]) as usize;
    let challenge_len = u16::from_be_bytes([data[9], data[10]]) as usize;
    (cipher_specs_len > 0
        && cipher_specs_len.is_multiple_of(3)
        && (16..=32).contains(&challenge_len)
        && 9usize
            .checked_add(cipher_specs_len)
            .and_then(|len| len.checked_add(session_id_len))
            .and_then(|len| len.checked_add(challenge_len))
            == Some(record_len))
    .then_some(record_end)
}

fn sslv2_tail_is_plausible(data: &[u8], record_end: usize) -> bool {
    if record_end > data.len() {
        return false;
    }
    let mut pos = record_end;
    while pos < data.len() {
        let tail = &data[pos..];
        if looks_like_complete_tls_client_hello(tail) {
            return true;
        }
        let Some(next_len) = sslv2_client_hello_end(tail) else {
            return false;
        };
        pos += next_len;
    }
    true
}

pub(crate) fn looks_like_sip_request_line(data: &[u8]) -> bool {
    let Some(line) = first_text_line(data) else {
        return false;
    };
    let Some(headers_end) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    if !crlf_line_endings_are_plausible(&data[..headers_end + 4]) {
        return false;
    }
    let body_len = data.len().saturating_sub(headers_end + 4);
    let Ok(headers) = std::str::from_utf8(&data[..headers_end + 4]) else {
        return false;
    };
    if !sip_headers_are_well_formed(headers) {
        return false;
    }
    let mut content_length = None;
    for line in headers.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if !sip_header_name_matches(key.trim_matches([' ', '\t']), "content-length") {
            continue;
        }
        let Some(parsed) = parse_sip_unsigned_decimal::<usize>(value) else {
            return false;
        };
        match content_length {
            Some(current) if current != parsed => return false,
            Some(_) => {}
            None => content_length = Some(parsed),
        }
    }
    if body_len == 0 {
        if content_length.is_some_and(|len| len != 0) {
            return false;
        }
    } else if content_length != Some(body_len) {
        return false;
    }
    let mut parts = line.split(' ');
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(target) = parts.next() else {
        return false;
    };
    let Some(version) = parts.next() else {
        return false;
    };
    if parts.next().is_some()
        || method.is_empty()
        || method.starts_with("SIP/")
        || !method.bytes().all(|byte| byte.is_ascii_uppercase())
        || target.is_empty()
        || target
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        || version != "SIP/2.0"
    {
        return false;
    }
    if !sip_header_present(headers, "Via")
        || !sip_unique_header_present(headers, "From")
        || !sip_unique_header_present(headers, "To")
        || !sip_unique_header_present(headers, "Call-ID")
        || !sip_cseq_matches_method(headers, method)
    {
        return false;
    }
    true
}

fn sip_headers_are_well_formed(headers: &str) -> bool {
    if nettrap_core::sanitize::contains_unicode_line_separator(headers) {
        return false;
    }
    for line in headers.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            return true;
        }
        let Some((key, _)) = line.split_once(':') else {
            return false;
        };
        let key = key.trim_matches([' ', '\t']);
        if key.is_empty()
            || line.chars().next().is_some_and(char::is_whitespace)
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return false;
        }
    }

    false
}

fn sip_header_present(headers: &str, name: &str) -> bool {
    headers.lines().skip(1).any(|line| {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            return false;
        }
        let Some((key, _)) = line.split_once(':') else {
            return false;
        };
        sip_header_name_matches(key.trim_matches([' ', '\t']), name)
    })
}

fn sip_unique_header_present(headers: &str, name: &str) -> bool {
    headers
        .lines()
        .skip(1)
        .filter(|line| {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                return false;
            }
            let Some((key, _)) = line.split_once(':') else {
                return false;
            };
            sip_header_name_matches(key.trim_matches([' ', '\t']), name)
        })
        .take(2)
        .count()
        == 1
}

fn sip_cseq_matches_method(headers: &str, method: &str) -> bool {
    let mut cseq = None;
    for line in headers.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if !key.trim_matches([' ', '\t']).eq_ignore_ascii_case("CSeq") {
            continue;
        }
        if cseq.is_some() {
            return false;
        }
        cseq = Some(value.trim_matches([' ', '\t']));
    }

    let Some(cseq) = cseq else {
        return false;
    };
    if cseq.contains('\t') {
        return false;
    }
    let mut parts = cseq.split(' ');
    let Some(sequence) = parts.next() else {
        return false;
    };
    let Some(cseq_method) = parts.next() else {
        return false;
    };
    if cseq_method.is_empty() || parts.next().is_some() {
        return false;
    }
    parse_sip_unsigned_decimal::<u32>(sequence).is_some_and(|sequence| sequence > 0)
        && cseq_method.eq_ignore_ascii_case(method)
}

fn sip_header_name_matches(candidate: &str, canonical: &str) -> bool {
    let candidate_lower = candidate.to_ascii_lowercase();
    candidate.eq_ignore_ascii_case(canonical)
        || matches!(
            (canonical, candidate_lower.as_str()),
            ("Via", "v")
                | ("From", "f")
                | ("To", "t")
                | ("Call-ID", "i")
                | ("Content-Length", "l")
                | ("content-length", "l")
        )
}

fn parse_sip_unsigned_decimal<T: std::str::FromStr>(value: &str) -> Option<T> {
    let value = value.trim_matches([' ', '\t']);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn mysql_ssl_request_is_well_formed(data: &[u8]) -> bool {
    const CLIENT_SSL: u32 = 0x0000_0800;

    if data.len() < 8 || data[3] != 1 {
        return false;
    }

    let declared_len = (data[0] as usize) | ((data[1] as usize) << 8) | ((data[2] as usize) << 16);
    if declared_len != data.len() - 4 || !matches!(declared_len, 4 | 32) {
        return false;
    }

    let cap_flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if cap_flags & CLIENT_SSL == 0 {
        return false;
    }

    declared_len == 4 || data[13..36].iter().all(|byte| *byte == 0)
}

pub(crate) fn looks_like_nkn_json_rpc(data: &[u8]) -> bool {
    nkn_json_rpc_request(data)
        .is_some_and(|request| request.method.as_deref().is_some_and(is_known_nkn_method))
}

pub(crate) fn looks_like_nkn_json_rpc_request(data: &[u8]) -> bool {
    nkn_json_rpc_request(data).is_some()
}

fn nkn_json_rpc_request(data: &[u8]) -> Option<NknJsonRpcTaste> {
    if data.len() > MAX_NKN_JSON_RPC_TASTE_BYTES {
        return None;
    }
    let mut deserializer = serde_json::Deserializer::from_slice(data);
    let request = deserializer.deserialize_any(NknTasteVisitor).ok()?;
    deserializer.end().ok()?;
    (request.jsonrpc.as_deref() == Some("2.0")).then_some(())?;
    let method = request.method.as_deref()?;
    (!method.is_empty() && method.len() <= MAX_NKN_JSON_RPC_METHOD_BYTES).then_some(())?;
    if let Some(id) = request.id.as_ref() {
        is_valid_nkn_json_rpc_id(id).then_some(())?;
    }
    Some(request)
}

fn is_known_nkn_method(method: &str) -> bool {
    matches!(
        method,
        "getnodestate" | "getlatestblockheight" | "getwsaddr"
    )
}

fn is_valid_nkn_json_rpc_id(id: &serde_json::Value) -> bool {
    id.is_null()
        || id.is_number()
        || id
            .as_str()
            .is_some_and(|value| value.len() <= MAX_NKN_JSON_RPC_ID_STRING_BYTES)
}

struct NknTasteVisitor;

impl<'de> Visitor<'de> for NknTasteVisitor {
    type Value = NknJsonRpcTaste;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an NKN JSON-RPC object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut jsonrpc = None;
        let mut method = None;
        let mut id = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "jsonrpc" => {
                    if jsonrpc.replace(map.next_value::<String>()?).is_some() {
                        return Err(de::Error::custom("duplicate jsonrpc field"));
                    }
                }
                "method" => {
                    if method.replace(map.next_value::<String>()?).is_some() {
                        return Err(de::Error::custom("duplicate method field"));
                    }
                }
                "id" => {
                    if id.replace(map.next_value::<serde_json::Value>()?).is_some() {
                        return Err(de::Error::custom("duplicate id field"));
                    }
                }
                _ => {
                    let _: IgnoredAny = map.next_value()?;
                }
            }
        }

        Ok(NknJsonRpcTaste {
            jsonrpc,
            method,
            id,
        })
    }
}

pub(crate) fn looks_like_tftp_request(data: &[u8]) -> bool {
    if data.len() < 6 || data.len() > TFTP_MAX_CONTROL_PACKET_BYTES || !data.ends_with(&[0]) {
        return false;
    }
    let opcode = u16::from_be_bytes([data[0], data[1]]);
    if !matches!(opcode, 1 | 2) {
        return false;
    }

    let mut parts: Vec<&[u8]> = data[2..].split(|&byte| byte == 0).collect();
    if matches!(parts.last(), Some(part) if part.is_empty()) {
        parts.pop();
    }
    if parts.len() < 2
        || parts[0].is_empty()
        || parts[1].is_empty()
        || !parts.len().is_multiple_of(2)
    {
        return false;
    }
    if !parts.iter().all(|part| tftp_text_field_is_safe(part)) {
        return false;
    }
    let filename = String::from_utf8_lossy(parts[0]);
    if filename.starts_with(['/', '\\']) || filename.contains(':') {
        return false;
    }
    if filename
        .split(['/', '\\'])
        .any(|segment| matches!(segment, "." | ".."))
    {
        return false;
    }
    if !tftp_options_are_well_formed(&parts[2..]) {
        return false;
    }

    let mode = String::from_utf8_lossy(parts[1]).to_ascii_lowercase();
    matches!(mode.as_str(), "netascii" | "octet" | "mail")
}

fn tftp_options_are_well_formed(parts: &[&[u8]]) -> bool {
    let mut names = std::collections::HashSet::new();
    for pair in parts.chunks_exact(2) {
        let [name, value] = pair else {
            return false;
        };
        if name.is_empty() || value.is_empty() {
            return false;
        }
        let normalized_name = String::from_utf8_lossy(name).to_ascii_lowercase();
        if !names.insert(normalized_name) {
            return false;
        }
    }
    true
}

pub(crate) fn tftp_text_field_is_safe(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| !byte.is_ascii_control() && byte.is_ascii())
}

pub(crate) fn looks_like_smb_message(data: &[u8]) -> bool {
    if let Some((payload, frame_end)) = smb_netbios_frame(data) {
        return frame_end == data.len() && looks_like_direct_smb_payload(payload);
    }
    looks_like_direct_smb_payload(data)
}

fn smb_netbios_frame(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.len() < 4 || data[0] != 0x00 || data[1] & 0xfe != 0 {
        return None;
    }
    let payload_len =
        (((data[1] as usize) & 0x01) << 16) | ((data[2] as usize) << 8) | data[3] as usize;
    if payload_len < 4 {
        return None;
    }
    let end = 4usize.checked_add(payload_len)?;
    if end > data.len() {
        return None;
    }
    Some((&data[4..end], end))
}

pub(crate) fn looks_like_direct_smb_payload(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    if data[0..4] == *b"\xffSMB" {
        return data.len() >= 36;
    }
    if data[0..4] == *b"\xfeSMB" {
        return data.len() >= 68
            && u16::from_le_bytes([data[4], data[5]]) == 64
            && u32::from_le_bytes([data[16], data[17], data[18], data[19]]) & 0x0000_0001 == 0;
    }
    false
}

pub(crate) fn looks_like_rdp_tpkt(data: &[u8]) -> bool {
    let Some(frame_end) = rdp_tpkt_frame_end(data) else {
        return false;
    };
    frame_end == data.len()
}

fn rdp_tpkt_frame_end(data: &[u8]) -> Option<usize> {
    if data.len() < 7 || data[0] != 0x03 || data[1] != 0x00 {
        return None;
    }
    let tpkt_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if tpkt_len < 7 || tpkt_len > data.len() {
        return None;
    }
    let frame = &data[..tpkt_len];
    let x224_len = frame[4] as usize;
    if x224_len < 2 || 5 + x224_len != frame.len() {
        return None;
    }
    let valid = match frame[5] >> 4 {
        0x0E => frame.get(10).copied() == Some(0x00),
        0x0F => true,
        _ => false,
    };
    valid.then_some(tpkt_len)
}

const REDIS_TASTE_MAX_ARRAY_COUNT: usize = 1024;
const REDIS_TASTE_MAX_BULK_SIZE: usize = 64 * 1024;

pub(crate) fn looks_like_resp_array(data: &[u8]) -> bool {
    let Some(frame_end) = redis_resp_array_end(data) else {
        return false;
    };
    redis_sample_tail_is_plausible(data, frame_end)
}

fn redis_resp_array_end(data: &[u8]) -> Option<usize> {
    if !data.starts_with(b"*") {
        return None;
    }
    let header_end = find_crlf_from(data, 0)?;
    let Ok(count_text) = std::str::from_utf8(&data[1..header_end]) else {
        return None;
    };
    let count = parse_redis_resp_array_count(count_text)?;
    if count == 0 || count > REDIS_TASTE_MAX_ARRAY_COUNT {
        return None;
    }

    let mut pos = header_end + 2;
    for _ in 0..count {
        if data.get(pos) != Some(&b'$') {
            return None;
        }
        let bulk_header_end = find_crlf_from(data, pos)?;
        let Ok(bulk_len_text) = std::str::from_utf8(&data[pos + 1..bulk_header_end]) else {
            return None;
        };
        let bulk_len = parse_redis_resp_bulk_len(bulk_len_text)?;

        pos = bulk_header_end + 2;
        let bulk_len = bulk_len?;
        if bulk_len > REDIS_TASTE_MAX_BULK_SIZE {
            return None;
        }
        let data_end = pos.checked_add(bulk_len)?;
        let frame_end = data_end.checked_add(2)?;
        if frame_end > data.len() || &data[data_end..frame_end] != b"\r\n" {
            return None;
        }
        pos = frame_end;
    }

    Some(pos)
}

fn redis_sample_tail_is_plausible(data: &[u8], frame_end: usize) -> bool {
    if frame_end > data.len() {
        return false;
    }
    let tail = redis_skip_blank_lines(&data[frame_end..]);
    if tail.is_empty() {
        return true;
    }
    if let Some(next_frame_end) = redis_resp_array_end(tail) {
        return redis_sample_tail_is_plausible(tail, next_frame_end);
    }
    if let Some(next_frame_end) = redis_inline_request_end(tail) {
        return redis_sample_tail_is_plausible(tail, next_frame_end);
    }
    false
}

fn redis_skip_blank_lines(mut data: &[u8]) -> &[u8] {
    while data.starts_with(b"\r\n") {
        data = &data[2..];
    }
    data
}

pub(crate) fn find_crlf_from(data: &[u8], start: usize) -> Option<usize> {
    data.get(start..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
}

pub(crate) fn parse_redis_resp_array_count(text: &str) -> Option<usize> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

pub(crate) fn parse_redis_resp_bulk_len(text: &str) -> Option<Option<usize>> {
    if text == "-1" {
        return Some(None);
    }
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok().map(Some)
}

pub(crate) fn ldap_app_tag_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 7 || data[0] != 0x30 {
        return None;
    }

    let (seq_len, seq_len_bytes) = ber_length(&data[1..])?;
    let msg_id_pos = 1usize.checked_add(seq_len_bytes)?;
    let seq_end = msg_id_pos.checked_add(seq_len)?;
    if seq_end != data.len() || msg_id_pos >= seq_end || data[msg_id_pos] != 0x02 {
        return None;
    }

    let id_len_pos = msg_id_pos + 1;
    let (id_len, id_len_bytes) = ber_length(&data[id_len_pos..seq_end])?;
    if id_len == 0 || id_len > 4 {
        return None;
    }
    let id_start = id_len_pos.checked_add(id_len_bytes)?;
    let id_end = id_start.checked_add(id_len)?;
    if id_end > seq_end || !ldap_message_id_is_valid(&data[id_start..id_end]) {
        return None;
    }
    let app_tag_pos = id_end;
    if app_tag_pos >= seq_end {
        return None;
    }
    if !matches!(data[app_tag_pos], 0x60 | 0x63 | 0x42) {
        return None;
    }

    let (op_len, op_len_bytes) = ber_length(&data[app_tag_pos + 1..seq_end])?;
    let op_start = app_tag_pos + 1 + op_len_bytes;
    let op_end = op_start.checked_add(op_len)?;
    if op_end > seq_end || !ldap_message_tail_is_plausible(data, op_end, seq_end) {
        return None;
    }
    if data[app_tag_pos] == 0x60 {
        if op_len == 0 || !ldap_bind_request_is_plausible(&data[op_start..op_end]) {
            return None;
        }
    } else if data[app_tag_pos] == 0x63 && op_len == 0 {
        return None;
    }

    Some(app_tag_pos)
}

fn ldap_message_tail_is_plausible(data: &[u8], tail_start: usize, seq_end: usize) -> bool {
    if tail_start == seq_end {
        return true;
    }
    if tail_start >= seq_end || data[tail_start] != 0xa0 {
        return false;
    }

    let mut pos = tail_start + 1;
    let Some((controls_len, controls_len_bytes)) = ber_length(&data[pos..seq_end]) else {
        return false;
    };
    pos += controls_len_bytes;
    let Some(controls_end) = pos.checked_add(controls_len) else {
        return false;
    };
    controls_end == seq_end && ldap_controls_are_plausible(&data[pos..controls_end])
}

fn ldap_controls_are_plausible(data: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos < data.len() {
        let Some(control) = read_ber_tlv(data, &mut pos, data.len(), 0x30) else {
            return false;
        };
        if !ldap_control_is_plausible(control) {
            return false;
        }
    }
    true
}

fn ldap_control_is_plausible(data: &[u8]) -> bool {
    let mut pos = 0usize;
    let Some(control_type) = read_ber_tlv(data, &mut pos, data.len(), 0x04) else {
        return false;
    };
    if control_type.is_empty() {
        return false;
    }
    if pos == data.len() {
        return true;
    }
    if data[pos] == 0x01 {
        let Some(criticality) = read_ber_tlv(data, &mut pos, data.len(), 0x01) else {
            return false;
        };
        if criticality.len() != 1 {
            return false;
        }
        if pos == data.len() {
            return true;
        }
    }
    read_ber_tlv(data, &mut pos, data.len(), 0x04).is_some() && pos == data.len()
}

fn ldap_bind_request_is_plausible(value: &[u8]) -> bool {
    let mut pos = 0usize;
    let Some(version) = read_ber_tlv(value, &mut pos, value.len(), 0x02) else {
        return false;
    };
    if !ldap_message_id_is_valid(version) {
        return false;
    }
    if read_ber_tlv(value, &mut pos, value.len(), 0x04).is_none() {
        return false;
    }
    let Some(tag) = value.get(pos).copied() else {
        return false;
    };
    if !matches!(tag, 0x80 | 0xa3) {
        return false;
    }
    pos += 1;
    let Some((auth_len, auth_len_bytes)) = ber_length(&value[pos..]) else {
        return false;
    };
    pos += auth_len_bytes;
    let Some(auth_end) = pos.checked_add(auth_len) else {
        return false;
    };
    if auth_end != value.len() {
        return false;
    }
    tag == 0x80 || ldap_sasl_auth_choice_is_plausible(&value[pos..auth_end])
}

fn ldap_sasl_auth_choice_is_plausible(value: &[u8]) -> bool {
    let mut pos = 0usize;
    let Some(mechanism) = read_ber_tlv(value, &mut pos, value.len(), 0x04) else {
        return false;
    };
    if mechanism.is_empty() || std::str::from_utf8(mechanism).is_err() {
        return false;
    }
    if pos == value.len() {
        return true;
    }
    read_ber_tlv(value, &mut pos, value.len(), 0x04).is_some() && pos == value.len()
}

pub(crate) fn ldap_message_id_is_valid(value: &[u8]) -> bool {
    if value.is_empty() || value.len() > 4 {
        return false;
    }
    if value[0] & 0x80 != 0 {
        return false;
    }
    if value.len() > 1 && value[0] == 0x00 && value[1] & 0x80 == 0 {
        return false;
    }
    value.iter().any(|byte| *byte != 0)
}

pub(crate) fn ber_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }

    let len_bytes = (first & 0x7f) as usize;
    if len_bytes == 0 || len_bytes > 4 || data.len() < 1 + len_bytes {
        return None;
    }
    if len_bytes == 1 {
        if data[1] < 128 {
            return None;
        }
    } else if data[1] == 0 {
        return None;
    }
    let mut len = 0usize;
    for byte in &data[1..1 + len_bytes] {
        len = (len << 8) | *byte as usize;
    }
    Some((len, 1 + len_bytes))
}

pub(crate) fn looks_like_snmp_request(data: &[u8]) -> bool {
    if data.len() < 10 || data[0] != 0x30 {
        return false;
    }

    let mut pos = 0usize;
    let Some(message) = read_ber_tlv(data, &mut pos, data.len(), 0x30) else {
        return false;
    };
    if pos != data.len() {
        return false;
    }

    let mut msg_pos = 0usize;
    let Some(version) = read_ber_tlv(message, &mut msg_pos, message.len(), 0x02) else {
        return false;
    };
    if !matches!(version, [0] | [1]) {
        return false;
    }
    let Some(community) = read_ber_tlv(message, &mut msg_pos, message.len(), 0x04) else {
        return false;
    };
    if community.len() > MAX_SNMP_COMMUNITY_BYTES {
        return false;
    }

    let Some(&pdu_tag) = message.get(msg_pos) else {
        return false;
    };
    if !matches!(pdu_tag, 0xa0 | 0xa1 | 0xa3 | 0xa5) {
        return false;
    }
    if pdu_tag == 0xa5 && version == [0] {
        return false;
    }
    msg_pos += 1;
    let Some((pdu_len, pdu_len_bytes)) = ber_length(&message[msg_pos..]) else {
        return false;
    };
    msg_pos += pdu_len_bytes;
    let Some(pdu_end) = msg_pos.checked_add(pdu_len) else {
        return false;
    };
    if pdu_end > message.len() {
        return false;
    }
    let pdu = &message[msg_pos..pdu_end];
    if pdu_end != message.len() {
        return false;
    }

    let mut pdu_pos = 0usize;
    let Some(request_id) = read_ber_tlv(pdu, &mut pdu_pos, pdu.len(), 0x02) else {
        return false;
    };
    if !snmp_canonical_integer_is_valid(request_id) {
        return false;
    }
    let Some(error_status) = read_ber_tlv(pdu, &mut pdu_pos, pdu.len(), 0x02) else {
        return false;
    };
    if pdu_tag != 0xa5 {
        if !snmp_zero_integer_is_valid(error_status) {
            return false;
        }
    } else if !snmp_nonnegative_canonical_integer_is_valid(error_status) {
        return false;
    }
    let Some(error_index) = read_ber_tlv(pdu, &mut pdu_pos, pdu.len(), 0x02) else {
        return false;
    };
    if pdu_tag != 0xa5 {
        if !snmp_zero_integer_is_valid(error_index) {
            return false;
        }
    } else if !snmp_nonnegative_canonical_integer_is_valid(error_index) {
        return false;
    }
    read_ber_tlv(pdu, &mut pdu_pos, pdu.len(), 0x30).is_some() && pdu_pos == pdu.len()
}

fn read_ber_tlv<'a>(
    data: &'a [u8],
    pos: &mut usize,
    limit: usize,
    expected_tag: u8,
) -> Option<&'a [u8]> {
    if limit > data.len() || *pos >= limit || data[*pos] != expected_tag {
        return None;
    }
    *pos += 1;
    let (len, len_bytes) = ber_length(&data[*pos..limit])?;
    *pos += len_bytes;
    let end = (*pos).checked_add(len)?;
    if end > limit {
        return None;
    }
    let value = &data[*pos..end];
    *pos = end;
    Some(value)
}

pub(crate) fn snmp_zero_integer_is_valid(value: &[u8]) -> bool {
    matches!(value, [0])
}

fn snmp_canonical_integer_is_valid(value: &[u8]) -> bool {
    if value.is_empty() || value.len() > 4 {
        return false;
    }
    if value.len() == 1 {
        return value[0] & 0x80 == 0;
    }
    if value[0] == 0x00 && value[1] & 0x80 == 0 {
        return false;
    }
    if value[0] == 0xff && value[1] & 0x80 != 0 {
        return false;
    }
    true
}

fn snmp_nonnegative_canonical_integer_is_valid(value: &[u8]) -> bool {
    snmp_canonical_integer_is_valid(value) && value.first().is_some_and(|byte| byte & 0x80 == 0)
}

pub(crate) fn looks_like_socks_message(data: &[u8]) -> bool {
    match data.first().copied() {
        Some(0x04) => looks_like_socks4_request(data),
        Some(0x05) => looks_like_socks5_message(data),
        _ => false,
    }
}

fn looks_like_socks4_request(data: &[u8]) -> bool {
    if data.len() < 9 || !matches!(data[1], 0x01 | 0x02) {
        return false;
    }
    if !socks_port_is_present(data, 2) {
        return false;
    }

    let Some(user_end) = data[8..].iter().position(|&byte| byte == 0) else {
        return false;
    };
    let after_user = &data[8 + user_end + 1..];
    let is_socks4a = data[4] == 0 && data[5] == 0 && data[6] == 0 && data[7] != 0;
    if !is_socks4a
        && !socks5_ipv4_is_usable(std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]))
    {
        return false;
    }
    if !is_socks4a {
        return after_user.is_empty();
    }

    let Some(domain_end) = after_user.iter().position(|&byte| byte == 0) else {
        return false;
    };
    domain_end + 1 == after_user.len() && socks_domain_name_is_valid(&after_user[..domain_end])
}

fn looks_like_socks5_message(data: &[u8]) -> bool {
    socks5_greeting_len(data).is_some_and(|greeting_len| greeting_len == data.len())
        || socks5_request_is_well_formed(data)
}

fn socks5_greeting_len(data: &[u8]) -> Option<usize> {
    if data.len() < 3 || data == [0x05, 0x00] {
        return None;
    }
    let nmethods = data[1] as usize;
    if nmethods == 0 {
        return None;
    }
    let greeting_len = 2usize.checked_add(nmethods)?;
    data.get(2..greeting_len).map(|_| greeting_len)
}

fn socks5_request_is_well_formed(data: &[u8]) -> bool {
    if data.len() < 7 || data[2] != 0 || !matches!(data[1], 0x01..=0x03) {
        return false;
    }

    match data[3] {
        0x01 => {
            data.len() == 10
                && socks_port_is_present(data, 8)
                && socks5_ipv4_is_usable(std::net::Ipv4Addr::new(
                    data[4], data[5], data[6], data[7],
                ))
        }
        0x03 => {
            if data.len() < 7 {
                return false;
            }
            let domain_len = data[4] as usize;
            let Some(total_len) = 7usize.checked_add(domain_len) else {
                return false;
            };
            domain_len > 0
                && data.len() == total_len
                && socks_port_is_present(data, 5 + domain_len)
                && socks_domain_name_is_valid(&data[5..5 + domain_len])
        }
        0x04 => {
            if data.len() != 22 || !socks_port_is_present(data, 20) {
                return false;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            socks5_ipv6_is_usable(std::net::Ipv6Addr::from(octets))
        }
        _ => false,
    }
}

fn socks5_ipv4_is_usable(ip: std::net::Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
}

fn socks5_ipv6_is_usable(ip: std::net::Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return socks5_ipv4_is_usable(mapped);
    }
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
}

pub(crate) fn socks_domain_name_is_valid(domain: &[u8]) -> bool {
    let Ok(domain) = std::str::from_utf8(domain) else {
        return false;
    };
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    !domain.is_empty()
        && domain.len() <= 253
        && domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
        && !domain
            .split('.')
            .all(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
}

pub(crate) fn looks_like_memcached_binary_request(data: &[u8]) -> bool {
    let Some(request_end) = memcached_binary_request_end(data) else {
        return false;
    };
    request_end == data.len()
}

fn memcached_binary_request_end(data: &[u8]) -> Option<usize> {
    if data.len() < 24 || data[0] != 0x80 {
        return None;
    }
    if data[5] != 0 || data[6] != 0 || data[7] != 0 {
        return None;
    }
    let key_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let extras_len = data[4] as usize;
    let body_len = u32::from_be_bytes([data[8], data[9], data[10], data[11]]) as usize;
    let total_len = 24usize.checked_add(body_len)?;
    if total_len > data.len() {
        return None;
    }
    let opcode = data[1];
    let valid_shape = if memcached_binary_opcode_is_known(opcode) {
        memcached_binary_request_shape_is_valid(opcode, extras_len, key_len, body_len)
    } else {
        memcached_unknown_binary_request_shape_is_valid(extras_len, key_len, body_len)
    };
    valid_shape.then_some(total_len)
}

pub(crate) fn memcached_binary_opcode_is_known(opcode: u8) -> bool {
    matches!(opcode, 0x00..=0x1e)
}

fn memcached_binary_request_shape_is_valid(
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
            extras_len == 0 && (1..=MAX_MEMCACHED_KEY_BYTES).contains(&key_len) && value_len == 0
        }
        0x01 | 0x02 | 0x03 | 0x11 | 0x12 | 0x13 => {
            extras_len == 8 && (1..=MAX_MEMCACHED_KEY_BYTES).contains(&key_len)
        }
        0x05 | 0x06 | 0x15 | 0x16 => {
            extras_len == 20 && (1..=MAX_MEMCACHED_KEY_BYTES).contains(&key_len) && value_len == 0
        }
        0x07 | 0x0a | 0x0b | 0x17 => extras_len == 0 && key_len == 0 && value_len == 0,
        0x08 | 0x18 => matches!(extras_len, 0 | 4) && key_len == 0 && value_len == 0,
        0x0e | 0x0f | 0x19 | 0x1a => {
            extras_len == 0 && (1..=MAX_MEMCACHED_KEY_BYTES).contains(&key_len)
        }
        0x10 => extras_len == 0 && key_len == 0 && value_len == 0,
        0x1b => extras_len == 4 && key_len == 0 && value_len == 0,
        0x1c..=0x1e => {
            extras_len == 4 && (1..=MAX_MEMCACHED_KEY_BYTES).contains(&key_len) && value_len == 0
        }
        _ => false,
    }
}

fn memcached_unknown_binary_request_shape_is_valid(
    extras_len: usize,
    key_len: usize,
    body_len: usize,
) -> bool {
    extras_len
        .checked_add(key_len)
        .is_some_and(|metadata_len| metadata_len <= body_len && key_len <= MAX_MEMCACHED_KEY_BYTES)
}

pub(crate) fn looks_like_ssdp_request(data: &[u8]) -> bool {
    let Some(line) = first_text_line(data) else {
        return false;
    };
    let Some(header_end) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    if header_end + 4 != data.len() {
        return false;
    }
    let mut parts = line.split(' ');
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(target) = parts.next() else {
        return false;
    };
    let Some(version) = parts.next() else {
        return false;
    };
    if parts.next().is_some() || target != "*" || version != "HTTP/1.1" {
        return false;
    }
    if !headers_are_well_formed(data) || !ssdp_host_is_valid(data) {
        return false;
    }
    if method.eq_ignore_ascii_case("M-SEARCH") {
        return header_value(data, "MAN")
            .is_some_and(|value| value.eq_ignore_ascii_case("\"ssdp:discover\""))
            && header_value(data, "ST").is_some_and(ssdp_search_target_is_supported)
            && header_value(data, "MX").is_some_and(ssdp_mx_value_is_valid);
    }
    false
}

pub(crate) fn headers_are_well_formed(data: &[u8]) -> bool {
    if !header_line_endings_are_plausible(data) {
        return false;
    }
    for line in data.split(|&byte| byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            return true;
        }
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            return false;
        };
        let Ok(key) = std::str::from_utf8(&line[..colon]) else {
            return false;
        };
        if !is_valid_header_name(key) {
            return false;
        }
    }
    false
}

fn header_value<'a>(data: &'a [u8], name: &str) -> Option<&'a str> {
    let mut selected = None;
    for line in data.split(|&byte| byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            continue;
        };
        let Ok(key) = std::str::from_utf8(&line[..colon]) else {
            return None;
        };
        if !is_valid_header_name(key) || !key.eq_ignore_ascii_case(name) {
            continue;
        }
        let value = trim_ascii_ows(&line[colon + 1..]);
        if value.is_empty() || value.iter().any(|byte| !matches!(byte, b'!'..=b'~')) {
            return None;
        }
        let Ok(value) = std::str::from_utf8(value) else {
            return None;
        };
        match selected {
            Some(_) => return None,
            None => selected = Some(value),
        }
    }
    selected
}

fn trim_ascii_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name == name.trim_matches([' ', '\t'])
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

fn ssdp_mx_value_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u32>().is_ok_and(|mx| mx > 0)
}

fn ssdp_search_target_is_supported(value: &str) -> bool {
    value.eq_ignore_ascii_case("ssdp:all")
        || value.eq_ignore_ascii_case("upnp:rootdevice")
        || value.eq_ignore_ascii_case("uuid:nettrap")
        || value.eq_ignore_ascii_case("urn:schemas-upnp-org:device:InternetGatewayDevice:1")
        || value.eq_ignore_ascii_case("urn:schemas-upnp-org:service:WANIPConnection:1")
}

fn ssdp_host_is_valid(data: &[u8]) -> bool {
    const SSDP_IPV4_HOST: &str = "239.255.255.250";
    const SSDP_PORT: u16 = 1900;
    const SSDP_IPV6_MULTICAST: std::net::Ipv6Addr =
        std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000c);

    let Some(host) = header_value(data, "HOST") else {
        return false;
    };
    let Some((base, port)) = host.rsplit_once(':') else {
        return false;
    };
    if parse_unsigned_decimal::<u16>(port) != Some(SSDP_PORT) {
        return false;
    }

    if let Some(inner) = base
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip == SSDP_IPV6_MULTICAST);
    }

    base == SSDP_IPV4_HOST
}

pub(crate) fn looks_like_ntp_client_request(data: &[u8]) -> bool {
    if data.len() < 48 || !data.len().is_multiple_of(4) {
        return false;
    }
    let version = (data[0] >> 3) & 0x07;
    let mode = data[0] & 0x07;
    (3..=4).contains(&version) && mode == 3
}

pub(crate) fn looks_like_plain_coap_request(data: &[u8]) -> bool {
    if data.len() < 4 || (data[0] >> 6) != 1 {
        return false;
    }
    let msg_type = (data[0] >> 4) & 0x03;
    let tkl = (data[0] & 0x0F) as usize;
    let code_class = data[1] >> 5;
    let code_detail = data[1] & 0x1F;
    if msg_type == 0 && code_class == 0 && code_detail == 0 {
        return tkl == 0 && data.len() == 4;
    }
    if code_class == 0 && code_detail == 0 {
        return tkl == 0 && data.len() == 4 && matches!(msg_type, 2 | 3);
    }
    let Some(options_start) = 4usize.checked_add(tkl) else {
        return false;
    };
    msg_type <= 1
        && tkl <= 8
        && data.len() >= options_start
        && code_class == 0
        && matches!(code_detail, 1..=31)
        && coap_options_are_well_formed(&data[options_start..])
}

fn coap_options_are_well_formed(data: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos < data.len() {
        let header = data[pos];
        pos += 1;
        if header == 0xff {
            return pos < data.len();
        }

        let delta = header >> 4;
        let option_len = header & 0x0f;
        if read_coap_option_component(delta, data, &mut pos).is_none() {
            return false;
        }
        let Some(option_len) = read_coap_option_component(option_len, data, &mut pos) else {
            return false;
        };
        let Some(next_pos) = pos.checked_add(option_len) else {
            return false;
        };
        if next_pos > data.len() {
            return false;
        }
        pos = next_pos;
    }
    true
}

fn read_coap_option_component(nibble: u8, data: &[u8], pos: &mut usize) -> Option<usize> {
    match nibble {
        0..=12 => Some(nibble as usize),
        13 => {
            let value = *data.get(*pos)? as usize;
            *pos += 1;
            Some(13 + value)
        }
        14 => {
            let bytes = data.get(*pos..(*pos).checked_add(2)?)?;
            *pos += 2;
            Some(269 + u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
        }
        _ => None,
    }
}

pub(crate) fn ident_port_text_is_valid(value: &str) -> bool {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    value.parse::<u16>().is_ok_and(|port| port != 0)
}

fn socks_port_is_present(data: &[u8], offset: usize) -> bool {
    data.get(offset..offset + 2).is_some()
}

pub(crate) fn looks_like_syslog_pri(data: &[u8]) -> bool {
    if data.len() > MAX_SYSLOG_PACKET_BYTES {
        return false;
    }
    let data = if let Some(data) = data.strip_suffix(b"\r\n") {
        data
    } else if data.ends_with(b"\r") || data.ends_with(b"\n") {
        return false;
    } else {
        data
    };
    if data.iter().any(|&byte| matches!(byte, 0 | b'\r' | b'\n')) {
        return false;
    }
    if data.first() != Some(&b'<') {
        return looks_like_bsd_syslog_timestamp(data);
    }
    let Some(end) = data.iter().take(6).position(|&byte| byte == b'>') else {
        return false;
    };
    if end <= 1 {
        return false;
    }
    let pri = &data[1..end];
    if pri.len() > 3
        || !pri.iter().all(|byte| byte.is_ascii_digit())
        || (pri.len() > 1 && pri.first() == Some(&b'0'))
    {
        return syslog_tail_is_present(data, end);
    }
    let Ok(pri_text) = std::str::from_utf8(pri) else {
        return syslog_tail_is_present(data, end);
    };
    let Ok(pri) = pri_text.parse::<u16>() else {
        return syslog_tail_is_present(data, end);
    };
    if pri > 191 {
        return syslog_tail_is_present(data, end);
    }
    syslog_tail_is_present(data, end)
}

fn syslog_tail_is_present(data: &[u8], end: usize) -> bool {
    data.get(end + 1..).is_some_and(|tail| !tail.is_empty())
}

fn looks_like_bsd_syslog_timestamp(data: &[u8]) -> bool {
    const MONTHS: [&[u8; 3]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];

    data.len() > 15
        && MONTHS
            .iter()
            .any(|month| data.starts_with(month.as_slice()))
        && data[3] == b' '
        && (data[4] == b' ' || data[4].is_ascii_digit())
        && data[5].is_ascii_digit()
        && data[6] == b' '
        && data[7].is_ascii_digit()
        && data[8].is_ascii_digit()
        && data[9] == b':'
        && data[10].is_ascii_digit()
        && data[11].is_ascii_digit()
        && data[12] == b':'
        && data[13].is_ascii_digit()
        && data[14].is_ascii_digit()
        && data[15] == b' '
}

#[cfg(test)]
#[path = "heuristics_tests.rs"]
mod tests;
