use nettrap_core::error::{Error, Result};
use nettrap_core::parse::absolute_http_authority as absolute_form_authority;
use nettrap_core::parse::nonzero_port as parse_http_port;
use nettrap_core::sanitize::trim_http_ows_bytes;

use nettrap_core::sanitize::{
    has_numeric_domain_labels, has_valid_domain_label_lengths, has_valid_domain_labels,
};

pub(crate) const MAX_HEADER_SIZE: usize = 64 * 1024; // 64KB max headers
pub(crate) const MAX_TOTAL_SIZE: usize = 10 * 1024 * 1024; // 10MB max total request

pub(crate) struct ParsedHttpRequest {
    pub method: String,
    pub target: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub(crate) fn parse_http_request_bytes(data: &[u8]) -> Result<Option<ParsedHttpRequest>> {
    if data.len() > MAX_TOTAL_SIZE {
        return Err(Error::Parse("HTTP request exceeds maximum size".into()));
    }

    let header_end =
        match data.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(pos) => pos,
            None => {
                if data
                    .iter()
                    .enumerate()
                    .any(|(idx, &byte)| byte == b'\n' && (idx == 0 || data[idx - 1] != b'\r'))
                {
                    return Err(Error::Parse("Invalid HTTP line endings".into()));
                }
                if data.iter().enumerate().any(|(idx, &byte)| {
                    byte == b'\r' && idx + 1 < data.len() && data[idx + 1] != b'\n'
                }) {
                    return Err(Error::Parse("Invalid HTTP line endings".into()));
                }
                if data.len() > MAX_HEADER_SIZE {
                    return Err(Error::Parse("HTTP headers exceed maximum size".into()));
                }
                return Ok(None);
            }
        };

    if header_end > MAX_HEADER_SIZE {
        return Err(Error::Parse("HTTP headers exceed maximum size".into()));
    }

    let header_block = data
        .get(..header_end)
        .ok_or_else(|| Error::Parse(format!("Invalid HTTP header boundary at {header_end}")))?;

    if header_block
        .iter()
        .enumerate()
        .any(|(idx, &byte)| byte == b'\n' && (idx == 0 || header_block[idx - 1] != b'\r'))
    {
        return Err(Error::Parse("Invalid HTTP line endings".into()));
    }

    let request_line_end = header_block
        .windows(2)
        .position(|window| window == b"\r\n")
        .unwrap_or(header_block.len());
    let request_line = std::str::from_utf8(&header_block[..request_line_end])
        .map_err(|e| Error::Parse(e.to_string()))?;
    let (method, path, version) = parse_request_line(request_line)?;

    let mut headers = Vec::new();
    let header_lines = if request_line_end == header_block.len() {
        &[][..]
    } else {
        &header_block[request_line_end + 2..]
    };
    for line in header_lines.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon_pos) = line.iter().position(|&byte| byte == b':') else {
            return Err(Error::Parse("Invalid HTTP header".into()));
        };
        let key = &line[..colon_pos];
        let value = trim_http_ows_bytes(&line[colon_pos + 1..]);
        let Ok(key) = std::str::from_utf8(key) else {
            return Err(Error::Parse("Invalid HTTP header".into()));
        };
        if key.is_empty() || key != key.trim_matches([' ', '\t']) {
            return Err(Error::Parse("Invalid HTTP header".into()));
        }
        if !is_http_token(key) {
            return Err(Error::Parse("Invalid HTTP header".into()));
        }

        if key.contains('\r')
            || key.contains('\n')
            || key.contains('\0')
            || !value.iter().all(|byte| is_http_field_value_byte(*byte))
        {
            tracing::warn!("HTTP header contains CRLF or NUL");
            return Err(Error::Parse("Invalid HTTP header".into()));
        }

        headers.push((key.to_string(), latin1_to_string(value)));
    }

    if version == "HTTP/1.1" && !has_valid_host_header(&headers) {
        return Err(Error::Parse("Invalid or missing HTTP Host header".into()));
    }

    if has_conflicting_content_length(&headers) {
        return Err(Error::Parse("Conflicting HTTP Content-Length".into()));
    }

    let body_start = header_end + 4;
    let body = if has_header(&headers, "Transfer-Encoding") {
        if has_header(&headers, "Content-Length") {
            return Err(Error::Parse(
                "Conflicting HTTP Transfer-Encoding and Content-Length".into(),
            ));
        }
        if !transfer_encoding_is_supported(&headers) {
            return Err(Error::Parse("Unsupported HTTP Transfer-Encoding".into()));
        }

        let body_payload = match data.get(body_start..) {
            Some(body_payload) => body_payload,
            None => return Ok(None),
        };
        let Some((consumed, body)) = decode_chunked_body(body_payload)? else {
            return Ok(None);
        };

        let max_body_len = MAX_TOTAL_SIZE.saturating_sub(body_start);
        if consumed != body_payload.len() || consumed > max_body_len || body.len() > max_body_len {
            return Ok(None);
        }

        body
    } else if let Some(content_length_raw) = find_header_value(&headers, "Content-Length") {
        let Some(content_length) = parse_http_content_length(content_length_raw) else {
            return Err(Error::Parse("Invalid HTTP Content-Length".into()));
        };

        let max_body_len = MAX_TOTAL_SIZE.saturating_sub(body_start);
        if content_length > max_body_len {
            return Err(Error::Parse("HTTP Content-Length exceeds maximum".into()));
        }

        let available = data.len().saturating_sub(body_start);
        if available < content_length {
            return Ok(None);
        }
        if available != content_length {
            return Ok(None);
        }

        let body_slice = data
            .get(body_start..body_start + content_length)
            .ok_or_else(|| Error::Parse("Content-Length exceeds available body".into()))?;
        body_slice.to_vec()
    } else {
        if data.len() != body_start {
            return Ok(None);
        }
        Vec::new()
    };

    Ok(Some(ParsedHttpRequest {
        method: method.to_string(),
        target: path.to_string(),
        path: normalize_request_target(path),
        version: version.to_string(),
        headers,
        body,
    }))
}

pub(crate) fn parse_http_content_length(value: &str) -> Option<usize> {
    let value = value.trim_matches([' ', '\t']);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn parse_http_chunk_size(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut pos = 0usize;
    while pos < bytes.len() && bytes[pos].is_ascii_hexdigit() {
        pos += 1;
    }
    if pos == 0 {
        return None;
    }

    let size = usize::from_str_radix(&value[..pos], 16).ok()?;
    pos = skip_http_bws(bytes, pos);
    if pos == bytes.len() {
        return Some(size);
    }

    while pos < bytes.len() {
        if bytes[pos] != b';' {
            return None;
        }
        pos += 1;
        pos = skip_http_bws(bytes, pos);
        if pos == bytes.len() {
            return None;
        }

        let name_start = pos;
        while pos < bytes.len() && is_http_token_byte(bytes[pos]) {
            pos += 1;
        }
        if pos == name_start {
            return None;
        }

        pos = skip_http_bws(bytes, pos);
        if pos < bytes.len() && bytes[pos] == b'=' {
            pos += 1;
            pos = skip_http_bws(bytes, pos);
            if pos >= bytes.len() {
                return None;
            }
            if bytes[pos] == b'"' {
                pos += 1;
                let mut escaped = false;
                let mut closed = false;
                while pos < bytes.len() {
                    let byte = bytes[pos];
                    pos += 1;
                    if escaped {
                        if !is_http_quoted_pair_byte(byte) {
                            return None;
                        }
                        escaped = false;
                        continue;
                    }
                    match byte {
                        b'\\' => escaped = true,
                        b'"' => {
                            closed = true;
                            break;
                        }
                        0x20..=0x7E | 0x80..=0xFF => {}
                        _ => return None,
                    }
                }
                if escaped || !closed {
                    return None;
                }
            } else {
                let value_start = pos;
                while pos < bytes.len() && is_http_token_byte(bytes[pos]) {
                    pos += 1;
                }
                if pos == value_start {
                    return None;
                }
            }
        }

        pos = skip_http_bws(bytes, pos);
        if pos == bytes.len() {
            return Some(size);
        }
    }

    Some(size)
}

fn is_http_token_byte(byte: u8) -> bool {
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
}

fn is_http_quoted_pair_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' ' | 0x21..=0x7e | 0x80..=0xff)
}

fn skip_http_bws(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t') {
        pos += 1;
    }
    pos
}

fn parse_request_line(line: &str) -> Result<(&str, &str, &str)> {
    let mut parts = line.split(' ');
    let method = parts
        .next()
        .ok_or_else(|| Error::Parse("Invalid request line".into()))?;
    let target = parts
        .next()
        .ok_or_else(|| Error::Parse("Invalid request line".into()))?;
    let version = parts
        .next()
        .ok_or_else(|| Error::Parse("Invalid request line".into()))?;
    if parts.next().is_some()
        || !is_http_token(method)
        || !is_valid_http_target_for_method(method, target)
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return Err(Error::Parse("Invalid request line".into()));
    }

    Ok((method, target, version))
}

fn normalize_request_target(target: &str) -> String {
    if target == "*" {
        return target.to_string();
    }

    if !target.contains('/')
        && !target.contains('\\')
        && !target.contains('?')
        && !target.contains('#')
        && !target.contains("://")
        && target.contains(':')
    {
        return target.to_string();
    }

    let target = target.replace('\\', "/");
    let path = if let Some(scheme_pos) = target.find("://") {
        let scheme = &target[..scheme_pos];
        if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
            let rest = &target[scheme_pos + 3..];
            rest.find('/').map(|pos| &rest[pos..]).unwrap_or("/")
        } else {
            target.as_str()
        }
    } else {
        target.as_str()
    };

    let path = path.split('#').next().unwrap_or(path);
    let path = path.split('?').next().unwrap_or(path);

    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            _ => components.push(component),
        }
    }

    if components.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", components.join("/"))
    }
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

    if method.eq_ignore_ascii_case("CONNECT") {
        return is_authority_form_target(value);
    }

    if is_authority_form_target(value) {
        return false;
    }

    if let Some(authority) = absolute_form_authority(value) {
        if !is_valid_authority_port(authority) {
            return false;
        }
    } else if value.contains("://") {
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
                .is_ok_and(|ip| is_usable_ip_literal(&std::net::IpAddr::V6(ip)))
            && suffix.is_empty();
    }

    !host.contains(':')
        && !host.contains('@')
        && !host.contains('/')
        && !host.contains('\\')
        && !host.contains('?')
        && !host.contains('#')
        && (host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(is_usable_ipv4_literal)
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
                .is_ok_and(|ip| is_usable_ip_literal(&std::net::IpAddr::V6(ip)));
        }
        if suffix[1..].contains(':') {
            return false;
        }
        return inner
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| is_usable_ip_literal(&std::net::IpAddr::V6(ip)))
            && parse_http_port(&suffix[1..]).is_some();
    }

    if let Some((host, port)) = authority.rsplit_once(':') {
        if host.is_empty() {
            return false;
        }
        return (host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(is_usable_ipv4_literal)
            || host_is_valid_authority_host(host))
            && parse_http_port(port).is_some();
    }

    authority
        .parse::<std::net::Ipv4Addr>()
        .is_ok_and(is_usable_ipv4_literal)
        || host_is_valid_authority_host(authority)
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
        && has_valid_domain_label_lengths(host)
        && !has_numeric_domain_labels(host)
}

fn is_usable_ip_literal(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => is_usable_ipv4_literal(*ip),
        std::net::IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_usable_ipv4_literal(mapped);
            }
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
        }
    }
}

fn is_usable_ipv4_literal(ip: std::net::Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
}

fn find_header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case(name))
}

fn has_valid_host_header(headers: &[(String, String)]) -> bool {
    let mut host_values = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("Host"))
        .map(|(_, value)| value);
    let Some(host) = host_values.next() else {
        return false;
    };
    let host = host.trim_matches([' ', '\t']);
    if host.is_empty() || host_values.next().is_some() {
        return false;
    }
    if host.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return false;
    }
    if let Some(rest) = host.strip_prefix('[') {
        let Some((inner, suffix)) = rest.split_once(']') else {
            return false;
        };
        let Ok(ip) = inner.parse::<std::net::Ipv6Addr>() else {
            return false;
        };
        if !is_usable_ip_literal(&std::net::IpAddr::V6(ip)) {
            return false;
        }
        if suffix.is_empty() {
            return true;
        }
        let Some(port) = suffix.strip_prefix(':') else {
            return false;
        };
        parse_http_port(port).is_some()
    } else if host.contains(':') {
        let Some((name, port)) = host.rsplit_once(':') else {
            return false;
        };
        (name
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(is_usable_ipv4_literal)
            || is_valid_http_host_name(name)
                && !is_numeric_domain_name(name)
                && !is_trailing_dot_ipv4_literal(name))
            && parse_http_port(port).is_some()
    } else {
        host.parse::<std::net::Ipv4Addr>()
            .is_ok_and(is_usable_ipv4_literal)
            || is_valid_http_host_name(host)
                && !has_numeric_domain_labels(host)
                && !is_trailing_dot_ipv4_literal(host)
    }
}

pub(crate) fn is_valid_http_host_name(host: &str) -> bool {
    let host = if let Some(host) = host.strip_suffix('.') {
        if host.is_empty() || host.ends_with('.') {
            return false;
        }
        host
    } else {
        host
    };
    !host.is_empty()
        && !host.contains(':')
        && !host.contains('@')
        && !host.contains('/')
        && !host.contains('\\')
        && !host.contains('?')
        && !host.contains('#')
        && host.len() <= 253
        && has_valid_domain_labels(host)
        && has_valid_domain_label_lengths(host)
        && !has_numeric_domain_labels(host)
}

fn is_trailing_dot_ipv4_literal(host: &str) -> bool {
    host.strip_suffix('.')
        .is_some_and(|host| host.parse::<std::net::Ipv4Addr>().is_ok())
}

fn is_numeric_domain_name(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    has_numeric_domain_labels(host)
}

fn chunk_trailers_are_well_formed(trailers: &[u8]) -> Result<()> {
    if trailers
        .iter()
        .enumerate()
        .any(|(idx, &byte)| byte == b'\n' && (idx == 0 || trailers[idx - 1] != b'\r'))
    {
        return Err(Error::Parse("Invalid HTTP chunk trailer".into()));
    }

    for line in trailers.split(|&byte| byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let (line, had_cr) = if let Some(line) = line.strip_suffix(b"\r") {
            (line, true)
        } else {
            (line, false)
        };
        if !had_cr && line.contains(&b'\r') {
            return Err(Error::Parse("Invalid HTTP chunk trailer".into()));
        }
        let Some(colon_pos) = line.iter().position(|&byte| byte == b':') else {
            return Err(Error::Parse("Invalid HTTP chunk trailer".into()));
        };
        let key = &line[..colon_pos];
        let value = trim_http_ows_bytes(&line[colon_pos + 1..]);
        let Ok(key) = std::str::from_utf8(key) else {
            return Err(Error::Parse("Invalid HTTP chunk trailer".into()));
        };
        if key.is_empty()
            || key != key.trim_matches([' ', '\t'])
            || !is_http_token(key)
            || key.chars().any(|ch| ch.is_control() || ch.is_whitespace())
            || !value.iter().all(|byte| is_http_field_value_byte(*byte))
        {
            return Err(Error::Parse("Invalid HTTP chunk trailer".into()));
        }
    }

    Ok(())
}

fn is_http_field_value_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff)
}

fn latin1_to_string(value: &[u8]) -> String {
    value.iter().map(|&byte| char::from(byte)).collect()
}

fn transfer_encoding_is_supported(headers: &[(String, String)]) -> bool {
    let mut codings = Vec::new();
    for (_, value) in headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("Transfer-Encoding"))
    {
        for coding in value
            .split(',')
            .map(|coding| coding.trim_matches([' ', '\t']))
        {
            if coding.is_empty() {
                return false;
            }
            codings.push(coding);
        }
    }

    let chunked_count = codings
        .iter()
        .filter(|coding| coding.eq_ignore_ascii_case("chunked"))
        .count();

    chunked_count == 1 && codings.len() == 1
}

fn has_conflicting_content_length(headers: &[(String, String)]) -> bool {
    let mut seen = None;
    let mut count = 0usize;
    let mut saw_invalid = false;
    for (_, value) in headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("Content-Length"))
    {
        count += 1;
        let Some(parsed) = parse_http_content_length(value) else {
            saw_invalid = true;
            continue;
        };
        match seen {
            Some(previous) if previous != parsed => return true,
            None => seen = Some(parsed),
            _ => {}
        }
    }
    saw_invalid && count > 1
}

fn decode_chunked_body(data: &[u8]) -> Result<Option<(usize, Vec<u8>)>> {
    let mut pos = 0usize;
    let mut body = Vec::new();

    loop {
        let Some(remaining) = data.get(pos..) else {
            return Ok(None);
        };
        let Some(rel_end) = remaining.windows(2).position(|window| window == b"\r\n") else {
            if remaining.iter().enumerate().any(|(idx, &byte)| {
                byte == b'\n' && (idx == 0 || remaining[idx - 1] != b'\r')
                    || byte == b'\r' && idx + 1 < remaining.len() && remaining[idx + 1] != b'\n'
            }) {
                return Err(Error::Parse("Invalid HTTP chunked body".into()));
            }
            return Ok(None);
        };
        let line_end = pos + rel_end;
        let Some(chunk_header_bytes) = data.get(pos..line_end) else {
            return Ok(None);
        };
        let chunk_header = std::str::from_utf8(chunk_header_bytes)
            .map_err(|_| Error::Parse("Invalid HTTP chunked body".into()))?;
        let Some(chunk_size) = parse_http_chunk_size(chunk_header) else {
            return Err(Error::Parse("Invalid HTTP chunked body".into()));
        };
        pos = line_end + 2;

        if chunk_size == 0 {
            let Some(trailers) = data.get(pos..) else {
                return Ok(None);
            };
            if trailers.starts_with(b"\r\n") {
                return Ok(Some((pos + 2, body)));
            }
            if trailers.iter().enumerate().any(|(idx, &byte)| {
                byte == b'\n' && (idx == 0 || trailers[idx - 1] != b'\r')
                    || byte == b'\r' && idx + 1 < trailers.len() && trailers[idx + 1] != b'\n'
            }) {
                return Err(Error::Parse("Invalid HTTP chunk trailer".into()));
            }

            let Some(trailer_end) = trailers.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                return Ok(None);
            };
            let Some(trailer_block) = trailers.get(..trailer_end) else {
                return Ok(None);
            };
            chunk_trailers_are_well_formed(trailer_block)?;
            return Ok(Some((pos + trailer_end + 4, body)));
        }

        let Some(data_end) = pos.checked_add(chunk_size) else {
            return Ok(None);
        };
        let Some(chunk_end) = data_end.checked_add(2) else {
            return Ok(None);
        };
        let Some(terminator) = data.get(data_end..chunk_end) else {
            return Ok(None);
        };

        if terminator != b"\r\n" {
            return Err(Error::Parse("Invalid HTTP chunked body".into()));
        }

        let Some(chunk_data) = data.get(pos..data_end) else {
            return Ok(None);
        };
        body.extend_from_slice(chunk_data);
        pos = chunk_end;
    }
}

#[cfg(test)]
#[path = "parser_tests.rs"]
mod tests;
