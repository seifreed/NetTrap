use nettrap_core::parse::absolute_http_authority as absolute_form_authority;
use nettrap_core::parse::nonzero_port as parse_http_port;
use nettrap_core::sanitize::trim_http_ows_bytes;
use nettrap_core::sanitize::{
    has_numeric_domain_labels, has_valid_domain_label_lengths, has_valid_domain_labels,
};

/// Extract the Host header from HTTP request data.
///
/// Parses HTTP headers and returns the value of the Host header.
///
/// # Arguments
///
/// * `data` - Raw HTTP request bytes
///
/// # Returns
///
/// The Host header value, or `None` if the request is malformed or the header
/// is absent.
#[cfg(test)]
pub fn extract_http_host(data: &[u8]) -> Option<String> {
    let first_line = request_line(data)?;
    let (_, target, _) = parse_request_line(first_line)?;
    let header_end = find_subslice(data, b"\r\n\r\n")?;
    let headers = &data[..header_end + 4];
    if !http_headers_are_well_formed(headers) {
        return None;
    }

    let mut host_value = None;
    let mut host_count = 0usize;
    let mut pos = 0usize;
    loop {
        let line_end = find_subslice(&headers[pos..], b"\r\n")?;
        let line = &headers[pos..pos + line_end];
        pos += line_end + 2;
        if line.is_empty() {
            if pos == headers.len() {
                break;
            }
            continue;
        }
        let Some(colon_pos) = line.iter().position(|&byte| byte == b':') else {
            continue;
        };
        let name = &line[..colon_pos];
        if !ascii_eq_ignore_case_bytes(name, b"Host") || name != trim_http_ows_bytes(name) {
            continue;
        }
        host_count += 1;
        if host_count == 1 {
            host_value = Some(trim_http_ows_bytes(&line[colon_pos + 1..]));
        }
    }

    if host_count != 1 {
        if host_count == 0 {
            return request_target_host(target);
        }
        return None;
    }

    let value = std::str::from_utf8(host_value?).ok()?;
    normalize_http_host_header_value(value)
}
#[cfg(test)]
fn request_target_host(target: &str) -> Option<String> {
    if let Some(authority) = absolute_form_authority(target) {
        return normalize_http_authority_value(authority);
    }

    if is_authority_form_target(target) {
        return normalize_http_authority_value(target);
    }

    None
}

/// Extract the HTTP method from request data (GET, POST, etc.).
///
/// # Arguments
///
/// * `data` - Raw HTTP request bytes
///
/// # Returns
///
/// The HTTP method, or `None` if parsing fails.
#[cfg(test)]
pub fn extract_http_method(data: &[u8]) -> Option<String> {
    let first_line = request_line(data)?;
    let (method, _, _) = parse_request_line(first_line)?;
    Some(method.to_string())
}

/// Extract the HTTP path from request data.
///
/// # Arguments
///
/// * `data` - Raw HTTP request bytes
///
/// # Returns
///
/// The request target, or `None` if parsing fails.
#[cfg(test)]
pub fn extract_http_target(data: &[u8]) -> Option<String> {
    let first_line = request_line(data)?;
    let (_, target, _) = parse_request_line(first_line)?;
    Some(target.to_string())
}

#[cfg(test)]
pub fn extract_http_path(data: &[u8]) -> Option<String> {
    let method = extract_http_method(data)?;
    let target = extract_http_target(data)?;
    if !is_valid_http_target_for_method(&method, &target) {
        return None;
    }

    Some(normalize_http_path(&target))
}

/// Extract the HTTP body from a complete request.
///
/// Returns `None` when the request is incomplete or uses invalid body framing.
/// Requests without explicit body framing are treated as headers-only only
/// when no extra bytes follow the header terminator.
#[cfg(test)]
pub fn extract_http_body(data: &[u8]) -> Option<Vec<u8>> {
    let header_end = find_subslice(data, b"\r\n\r\n")?;
    let body_start = header_end + 4;
    let headers = &data[..body_start];

    if !http_headers_are_well_formed(headers) {
        return None;
    }

    if find_header_value(headers, "Transfer-Encoding").is_some() {
        if find_header_value(headers, "Content-Length").is_some()
            || !transfer_encoding_is_supported(headers)
        {
            return None;
        }
        let (consumed, body) = decode_chunked_body(&data[body_start..])?;
        if consumed != data.len() - body_start {
            return None;
        }
        return Some(body);
    }

    if has_conflicting_content_length(headers) {
        return None;
    }

    if let Some(content_length_raw) = find_header_value(headers, "Content-Length") {
        let content_length = parse_http_content_length(content_length_raw)?;
        let body_end = body_start.checked_add(content_length)?;
        if data.len() < body_end {
            return None;
        }
        if data.len() != body_end {
            return None;
        }
        return Some(data[body_start..body_end].to_vec());
    }

    if data.len() != body_start {
        return None;
    }

    Some(Vec::new())
}

#[cfg(test)]
fn http_headers_are_well_formed(headers: &[u8]) -> bool {
    if headers
        .iter()
        .enumerate()
        .any(|(idx, &byte)| byte == b'\n' && (idx == 0 || headers[idx - 1] != b'\r'))
    {
        return false;
    }

    let mut pos = 0usize;
    let mut is_request_line = true;
    loop {
        let Some(line_end) = find_subslice(&headers[pos..], b"\r\n") else {
            return false;
        };
        let line = &headers[pos..pos + line_end];
        pos += line_end + 2;
        if line.is_empty() {
            return pos == headers.len();
        }
        if is_request_line {
            is_request_line = false;
            continue;
        }
        let Some(colon_pos) = line.iter().position(|&byte| byte == b':') else {
            return false;
        };
        let header_name = &line[..colon_pos];
        let value = &line[colon_pos + 1..];
        if header_name.is_empty()
            || header_name != trim_http_ows_bytes(header_name)
            || !header_name.iter().copied().all(is_http_token_byte)
            || !value.iter().copied().all(is_http_field_value_byte)
        {
            return false;
        }
    }
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
fn is_http_field_value_byte(byte: u8) -> bool {
    matches!(byte, b' ' | b'!'..=b'~' | 0x80..=0xff)
}

#[cfg(test)]
fn ascii_eq_ignore_case_bytes(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .copied()
            .zip(right.iter().copied())
            .all(|(lhs, rhs)| lhs.eq_ignore_ascii_case(&rhs))
}

#[cfg(test)]
pub(crate) fn normalize_http_path(target: &str) -> String {
    if target == "*" {
        return target.to_string();
    }

    if is_authority_form_target(target) {
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

#[cfg(test)]
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

#[cfg(test)]
fn request_line(data: &[u8]) -> Option<&str> {
    let line = find_subslice(data, b"\r\n").map_or(data, |pos| &data[..pos]);
    let text = std::str::from_utf8(line).ok()?;
    if nettrap_core::sanitize::contains_unicode_line_separator(text) {
        return None;
    }
    if line.iter().any(|&byte| matches!(byte, b'\r' | b'\n')) {
        return None;
    }
    Some(text)
}

#[cfg(test)]
fn parse_request_line(line: &str) -> Option<(&str, &str, &str)> {
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some()
        || !is_http_token(method)
        || !is_valid_http_target_for_method(method, target)
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return None;
    }

    Some((method, target, version))
}

#[cfg(test)]
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

#[cfg(test)]
#[cfg(test)]
fn is_authority_form_target(value: &str) -> bool {
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if host.is_empty()
        || port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || port.parse::<u16>().ok().filter(|port| *port != 0).is_none()
    {
        return false;
    }

    if let Some(rest) = host.strip_prefix('[') {
        let Some((inner, suffix)) = rest.split_once(']') else {
            return false;
        };
        let Ok(ip) = inner.parse::<std::net::Ipv6Addr>() else {
            return false;
        };
        return !inner.is_empty()
            && is_usable_http_authority_ip_literal(&std::net::IpAddr::V6(ip))
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
            .is_ok_and(is_usable_http_authority_ipv4_literal)
            || is_valid_http_host_name(host))
}

#[cfg(test)]
fn is_valid_http_host_header_value(host: &str) -> bool {
    if host.is_empty() || host.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return false;
    }

    if let Some(rest) = host.strip_prefix('[') {
        let Some((inner, suffix)) = rest.split_once(']') else {
            return false;
        };
        let Ok(ip) = inner.parse::<std::net::Ipv6Addr>() else {
            return false;
        };
        if is_special_http_host_header_ip_literal(&std::net::IpAddr::V6(ip)) {
            return false;
        }
        if suffix.is_empty() {
            return true;
        }
        let Some(port) = suffix.strip_prefix(':') else {
            return false;
        };
        return parse_http_port(port).is_some();
    }

    if let Some((name, port)) = host.rsplit_once(':') {
        if name.is_empty() || parse_http_port(port).is_none() {
            return false;
        }
        return name
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| !is_special_http_authority_ipv4_literal(ip))
            || is_valid_http_host_name(name);
    }

    host.parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| !is_special_http_authority_ipv4_literal(ip))
        || is_valid_http_host_name(host)
}

#[cfg(test)]
fn normalize_http_host_header_value(host: &str) -> Option<String> {
    if !is_valid_http_host_header_value(host) {
        return None;
    }

    if let Some(rest) = host.strip_prefix('[') {
        let (inner, suffix) = rest.split_once(']')?;
        let Ok(ip) = inner.parse::<std::net::Ipv6Addr>() else {
            return None;
        };
        let inner = canonicalize_http_authority_ip(std::net::IpAddr::V6(ip));
        return if suffix.is_empty() {
            Some(match inner {
                std::net::IpAddr::V4(ip) => ip.to_string(),
                std::net::IpAddr::V6(ip) => format!("[{}]", ip),
            })
        } else {
            let port = suffix.strip_prefix(':')?;
            let port = parse_http_port(port)?;
            Some(match inner {
                std::net::IpAddr::V4(ip) => format!("{}:{}", ip, port),
                std::net::IpAddr::V6(ip) => format!("[{}]:{}", ip, port),
            })
        };
    }

    if let Some((name, port)) = host.rsplit_once(':')
        && !name.contains(':')
    {
        let port = parse_http_port(port)?;
        if let Ok(ip) = name.parse::<std::net::Ipv4Addr>() {
            if is_special_http_authority_ipv4_literal(ip) {
                return None;
            }
            return Some(format!("{}:{}", ip, port));
        }
        return normalize_http_host_name(name).map(|name| format!("{name}:{port}"));
    }

    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return (!is_special_http_authority_ipv4_literal(ip)).then(|| ip.to_string());
    }

    normalize_http_host_name(host)
}

#[cfg(test)]
fn normalize_http_authority_value(host: &str) -> Option<String> {
    if !is_valid_http_authority_value(host) {
        return None;
    }

    if let Some(rest) = host.strip_prefix('[') {
        let (inner, suffix) = rest.split_once(']')?;
        let Ok(ip) = inner.parse::<std::net::Ipv6Addr>() else {
            return None;
        };
        let inner = canonicalize_http_authority_ip(std::net::IpAddr::V6(ip));
        return if suffix.is_empty() {
            Some(match inner {
                std::net::IpAddr::V4(ip) => ip.to_string(),
                std::net::IpAddr::V6(ip) => format!("[{}]", ip),
            })
        } else {
            let port = suffix.strip_prefix(':')?;
            let port = parse_http_port(port)?;
            Some(match inner {
                std::net::IpAddr::V4(ip) => format!("{}:{}", ip, port),
                std::net::IpAddr::V6(ip) => format!("[{}]:{}", ip, port),
            })
        };
    }

    if let Some((name, port)) = host.rsplit_once(':')
        && !name.contains(':')
    {
        let port = parse_http_port(port)?;
        if let Ok(ip) = name.parse::<std::net::Ipv4Addr>() {
            if is_special_http_authority_ipv4_literal(ip) {
                return None;
            }
            return Some(format!("{}:{}", ip, port));
        }
        return normalize_http_host_name(name).map(|name| format!("{name}:{port}"));
    }

    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return (!is_special_http_authority_ipv4_literal(ip)).then(|| ip.to_string());
    }

    normalize_http_host_name(host)
}

#[cfg(test)]
fn canonicalize_http_authority_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V4(ip) => std::net::IpAddr::V4(ip),
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
    }
}

#[cfg(test)]
fn normalize_http_host_name(host: &str) -> Option<String> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.ends_with('.') {
        return None;
    }
    if nettrap_core::sanitize::has_numeric_domain_labels(host) {
        return None;
    }

    Some(host.to_ascii_lowercase())
}

#[cfg(test)]
fn is_valid_http_host_name(host: &str) -> bool {
    let host = if let Some(host) = host.strip_suffix('.') {
        if host.is_empty() || host.ends_with('.') {
            return false;
        }
        host
    } else {
        host
    };

    host.len() <= 253
        && has_valid_domain_labels(host)
        && has_valid_domain_label_lengths(host)
        && !has_numeric_domain_labels(host)
}

#[cfg(test)]
fn is_special_http_host_header_ip_literal(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => is_special_http_authority_ipv4_literal(*ip),
        std::net::IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_special_http_authority_ipv4_literal(mapped);
            }

            ip.is_unspecified() || ip.is_loopback() || ip.is_multicast()
        }
    }
}

#[cfg(test)]
fn is_special_http_authority_ipv4_literal(ip: std::net::Ipv4Addr) -> bool {
    ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()
}

#[cfg(test)]
fn is_valid_http_authority_value(host: &str) -> bool {
    if host.is_empty() || host.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return false;
    }

    if let Some(rest) = host.strip_prefix('[') {
        let Some((inner, suffix)) = rest.split_once(']') else {
            return false;
        };
        let Ok(ip) = inner.parse::<std::net::Ipv6Addr>() else {
            return false;
        };
        if is_special_http_authority_ip_literal(&std::net::IpAddr::V6(ip)) {
            return false;
        }
        if suffix.is_empty() {
            return true;
        }
        let Some(port) = suffix.strip_prefix(':') else {
            return false;
        };
        return parse_http_port(port).is_some();
    }

    if let Some((name, port)) = host.rsplit_once(':') {
        if name.is_empty() || parse_http_port(port).is_none() {
            return false;
        }
        return name
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| !is_special_http_authority_ipv4_literal(ip))
            || is_valid_http_host_name(name);
    }

    host.parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| !is_special_http_authority_ipv4_literal(ip))
        || is_valid_http_host_name(host)
}

#[cfg(test)]
fn is_usable_http_authority_ip_literal(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => is_usable_http_authority_ipv4_literal(*ip),
        std::net::IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_usable_http_authority_ipv4_literal(mapped);
            }

            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
        }
    }
}

#[cfg(test)]
fn is_usable_http_authority_ipv4_literal(ip: std::net::Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
}

#[cfg(test)]
fn is_special_http_authority_ip_literal(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => is_special_http_authority_ipv4_literal(*ip),
        std::net::IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_special_http_authority_ipv4_literal(mapped);
            }

            ip.is_unspecified() || ip.is_loopback() || ip.is_multicast()
        }
    }
}

#[cfg(test)]
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
                .is_ok_and(|ip| is_usable_http_authority_ip_literal(&std::net::IpAddr::V6(ip)));
        }
        if suffix[1..].contains(':') {
            return false;
        }
        return inner
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| is_usable_http_authority_ip_literal(&std::net::IpAddr::V6(ip)))
            && parse_http_port(&suffix[1..]).is_some();
    }

    if let Some((host, port)) = authority.rsplit_once(':') {
        if host.is_empty() {
            return false;
        }
        if host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(is_usable_http_authority_ipv4_literal)
        {
            return parse_http_port(port).is_some();
        }
        return is_valid_http_host_name(host) && parse_http_port(port).is_some();
    }

    if authority
        .parse::<std::net::Ipv4Addr>()
        .is_ok_and(is_usable_http_authority_ipv4_literal)
    {
        return true;
    }
    is_valid_http_host_name(authority)
}

#[cfg(test)]
fn find_header_value<'a>(headers: &'a [u8], name: &str) -> Option<&'a str> {
    let mut pos = 0usize;
    loop {
        let line_end = find_subslice(&headers[pos..], b"\r\n")?;
        let line = &headers[pos..pos + line_end];
        pos += line_end + 2;
        if line.is_empty() {
            break;
        }
        let Some(colon_pos) = line.iter().position(|&byte| byte == b':') else {
            continue;
        };
        let header_name = &line[..colon_pos];
        if header_name.is_empty()
            || header_name != trim_http_ows_bytes(header_name)
            || !header_name.iter().copied().all(is_http_token_byte)
            || !ascii_eq_ignore_case_bytes(header_name, name.as_bytes())
        {
            continue;
        }
        let value = trim_http_ows_bytes(&line[colon_pos + 1..]);
        let value = std::str::from_utf8(value).ok()?;
        return Some(value);
    }
    None
}

#[cfg(test)]
fn parse_http_content_length(value: &str) -> Option<usize> {
    let value = value.trim_matches([' ', '\t']);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

#[cfg(test)]
fn has_conflicting_content_length(headers: &[u8]) -> bool {
    let mut seen = None;
    let mut count = 0usize;
    let mut saw_invalid = false;
    let mut pos = 0usize;
    while let Some(line_end) = find_subslice(&headers[pos..], b"\r\n") {
        let line = &headers[pos..pos + line_end];
        pos += line_end + 2;
        if line.is_empty() {
            break;
        }
        let Some(colon_pos) = line.iter().position(|&byte| byte == b':') else {
            continue;
        };
        let header_name = &line[..colon_pos];
        if !ascii_eq_ignore_case_bytes(header_name, b"Content-Length") {
            continue;
        }

        count += 1;
        let value = trim_http_ows_bytes(&line[colon_pos + 1..]);
        let Ok(value) = std::str::from_utf8(value) else {
            saw_invalid = true;
            continue;
        };
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

#[cfg(test)]
fn parse_http_chunk_size(value: &str) -> Option<usize> {
    let (size, extension) = value.split_once(';').unwrap_or((value, ""));
    let has_extension = value.contains(';');
    if size.is_empty()
        || size.chars().any(|ch| ch.is_whitespace() || ch.is_control())
        || !size.bytes().all(|byte| byte.is_ascii_hexdigit())
        || (has_extension && extension.is_empty())
        || extension
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return None;
    }
    usize::from_str_radix(size, 16).ok()
}

#[cfg(test)]
fn transfer_encoding_is_supported(headers: &[u8]) -> bool {
    let mut codings = Vec::new();
    let mut pos = 0usize;
    while let Some(line_end) = find_subslice(&headers[pos..], b"\r\n") {
        let line = &headers[pos..pos + line_end];
        pos += line_end + 2;
        if line.is_empty() {
            break;
        }
        let Some(colon_pos) = line.iter().position(|&byte| byte == b':') else {
            continue;
        };
        let header_name = &line[..colon_pos];
        if header_name.is_empty()
            || header_name != trim_http_ows_bytes(header_name)
            || !ascii_eq_ignore_case_bytes(header_name, b"Transfer-Encoding")
        {
            continue;
        }

        let value = trim_http_ows_bytes(&line[colon_pos + 1..]);
        let Ok(value) = std::str::from_utf8(value) else {
            return false;
        };
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

#[cfg(test)]
fn decode_chunked_body(data: &[u8]) -> Option<(usize, Vec<u8>)> {
    let mut pos = 0usize;
    let mut body = Vec::new();

    loop {
        let line_end = pos + find_subslice(&data[pos..], b"\r\n")?;
        let chunk_header = std::str::from_utf8(&data[pos..line_end]).ok()?;
        let chunk_size = parse_http_chunk_size(chunk_header)?;
        pos = line_end + 2;

        if chunk_size == 0 {
            let trailers = &data[pos..];
            if trailers.starts_with(b"\r\n") {
                return Some((pos + 2, body));
            }

            let trailer_end = find_subslice(trailers, b"\r\n\r\n")?;
            let trailer_block = &trailers[..trailer_end];
            if !chunk_trailers_are_well_formed(trailer_block) {
                return None;
            }
            return Some((pos + trailer_end + 4, body));
        }

        let data_end = pos.checked_add(chunk_size)?;
        let chunk_end = data_end.checked_add(2)?;
        if data.len() < chunk_end {
            return None;
        }

        if &data[data_end..chunk_end] != b"\r\n" {
            return None;
        }

        body.extend_from_slice(&data[pos..data_end]);
        pos = chunk_end;
    }
}

#[cfg(test)]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
fn chunk_trailers_are_well_formed(trailers: &[u8]) -> bool {
    if trailers
        .iter()
        .enumerate()
        .any(|(idx, &byte)| byte == b'\n' && (idx == 0 || trailers[idx - 1] != b'\r'))
    {
        return false;
    }

    let Ok(trailers) = std::str::from_utf8(trailers) else {
        return false;
    };

    for line in trailers.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((header_name, value)) = line.split_once(':') else {
            return false;
        };
        if header_name.is_empty()
            || header_name != header_name.trim_matches([' ', '\t'])
            || !is_http_token(header_name)
            || header_name.bytes().any(|byte| byte.is_ascii_control())
            || !value
                .bytes()
                .all(|byte| matches!(byte, b'\t' | b' '..=b'~'))
        {
            return false;
        }
    }

    true
}
