pub struct UpnpHandler {
    listen_ip: String,
    now: fn() -> chrono::DateTime<chrono::Utc>,
}

use nettrap_core::sanitize::trim_http_ows_bytes;

const DEFAULT_LISTEN_HOST: &str = "192.168.1.1";
const MAX_UPNP_HEADER_BYTES: usize = 64 * 1024;
const MAX_UPNP_BODY_BYTES: usize = 1024 * 1024;

fn safe_listen_host(value: &str) -> Option<String> {
    let host = value;
    if host.is_empty()
        || host.chars().next().is_some_and(char::is_whitespace)
        || host.chars().last().is_some_and(char::is_whitespace)
        || host
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return None;
    }
    let parse_host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);

    if let Ok(ip) = parse_host.parse::<std::net::IpAddr>() {
        if is_unacceptable_listen_ip(&ip) {
            return None;
        }
        return Some(match ip {
            std::net::IpAddr::V4(ip) => ip.to_string(),
            std::net::IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map_or_else(|| format!("[{}]", ip), |mapped| mapped.to_string()),
        });
    }

    if host.contains(':') {
        return None;
    }

    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
        || nettrap_core::sanitize::has_numeric_domain_labels(host.strip_suffix('.').unwrap_or(host))
    {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn is_unacceptable_listen_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()
        }
        std::net::IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.to_ipv4_mapped().is_some_and(|mapped| {
                    mapped.is_unspecified()
                        || mapped.is_loopback()
                        || mapped.is_multicast()
                        || mapped.is_broadcast()
                })
        }
    }
}

impl UpnpHandler {
    pub fn new() -> Self {
        Self {
            listen_ip: DEFAULT_LISTEN_HOST.to_string(),
            now: chrono::Utc::now,
        }
    }

    pub fn with_listen_ip(mut self, ip: impl Into<String>) -> Result<Self, String> {
        self.listen_ip =
            safe_listen_host(&ip.into()).ok_or_else(|| "invalid UPnP listen IP".to_string())?;
        Ok(self)
    }

    /// Inject the clock used for SSDP and HTTP `DATE` headers so FakeTime mode
    /// reaches UPnP responses as well.
    pub fn with_now(mut self, now: fn() -> chrono::DateTime<chrono::Utc>) -> Self {
        self.now = now;
        self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        self.handle_ssdp(data)
    }

    pub fn handle_ssdp(&self, data: &[u8]) -> Vec<u8> {
        let Some((text, _body_start, _body_len)) = bounded_upnp_request_text(data, 0) else {
            return Vec::new();
        };

        if headers_are_well_formed(&text) && text.ends_with("\r\n\r\n") && is_ssdp_m_search(&text) {
            let Some(st) = header_value(&text, "ST") else {
                return Vec::new();
            };
            tracing::warn!("SSDP M-SEARCH discovery attempt");
            self.ssdp_discovery_response(st)
        } else {
            Vec::new()
        }
    }

    pub fn handle_http(&self, data: &[u8]) -> Vec<u8> {
        let Some((text, body_start, body_len)) = bounded_upnp_request_text(data, usize::MAX) else {
            return Vec::new();
        };
        if !headers_are_well_formed(&text) {
            return Vec::new();
        }
        if has_header(&text, "Transfer-Encoding") {
            if has_header(&text, "Content-Length") {
                return Vec::new();
            }
            if !transfer_encoding_is_supported(&text) {
                return Vec::new();
            }
            let Some((consumed, body)) =
                decode_chunked_body(&data[body_start..], MAX_UPNP_BODY_BYTES)
            else {
                return Vec::new();
            };
            if consumed != data.len().saturating_sub(body_start) || body.len() > MAX_UPNP_BODY_BYTES
            {
                return Vec::new();
            }
        } else if !content_length_matches_body(&text, body_len) || body_len > MAX_UPNP_BODY_BYTES {
            return Vec::new();
        }
        let Some((method, path, version)) = request_line(&text) else {
            return Vec::new();
        };
        if version == "HTTP/1.1" && header_value(&text, "Host").is_none_or(str::is_empty) {
            return Vec::new();
        }

        if method.eq_ignore_ascii_case("GET") && path == "/desc.xml" {
            tracing::warn!("UPnP device description request");
            return http_xml_response(&self.device_description());
        }

        if method.eq_ignore_ascii_case("GET") && path == "/wanipconnSCPD.xml" {
            tracing::warn!("UPnP WANIPConnection SCPD request");
            return http_xml_response(wanipconn_scpd());
        }

        if !method.eq_ignore_ascii_case("POST") {
            return Vec::new();
        }

        if path != "/upnp/control/WANIPConn1" {
            return Vec::new();
        }

        let Some(action) = strict_header_value(&text, "SOAPAction") else {
            return Vec::new();
        };

        if action_matches(action, "DeletePortMapping") {
            tracing::warn!(
                "UPnP delete port mapping attempt: {}",
                request_log_preview(&text)
            );
            http_xml_response(delete_port_mapping_response())
        } else if action_matches(action, "GetExternalIPAddress") {
            tracing::warn!(
                "UPnP external IP address request: {}",
                request_log_preview(&text)
            );
            http_xml_response(&get_external_ip_address_response(&self.listen_ip))
        } else if action_matches(action, "AddPortMapping") {
            tracing::warn!(
                "UPnP add port mapping attempt: {}",
                request_log_preview(&text)
            );
            http_xml_response(add_port_mapping_response())
        } else {
            Vec::new()
        }
    }

    fn ssdp_discovery_response(&self, search_target: &str) -> Vec<u8> {
        let (st, usn) = ssdp_response_identity(search_target);
        format!(
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nDATE: {}\r\nEXT:\r\nST: {}\r\nUSN: {}\r\nLOCATION: http://{}:49152/desc.xml\r\nSERVER: Linux/3.14 UPnP/1.1 NetTrap/1.0\r\n\r\n",
            http_date_at((self.now)()),
            st,
            usn,
            self.listen_ip
        )
        .into_bytes()
    }

    fn device_description(&self) -> String {
        format!(
            "<?xml version=\"1.0\"?><root xmlns=\"urn:schemas-upnp-org:device-1-0\"><specVersion><major>1</major><minor>0</minor></specVersion><URLBase>http://{}:49152/</URLBase><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>NetTrap UPnP Gateway</friendlyName><manufacturer>NetTrap</manufacturer><modelName>NetTrap</modelName><UDN>uuid:nettrap</UDN><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>/upnp/control/WANIPConn1</controlURL><SCPDURL>/wanipconnSCPD.xml</SCPDURL></service></serviceList></device></root>",
            self.listen_ip
        )
    }
}

impl Default for UpnpHandler {
    fn default() -> Self {
        Self::new()
    }
}

fn bounded_upnp_request_text(data: &[u8], max_body_bytes: usize) -> Option<(String, usize, usize)> {
    let header_end = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)?;
    if header_end > MAX_UPNP_HEADER_BYTES {
        return None;
    }
    if data.len().saturating_sub(header_end) > max_body_bytes {
        return None;
    }
    Some((
        latin1_decode(data.get(..header_end)?),
        header_end,
        data.len().saturating_sub(header_end),
    ))
}

fn request_line(text: &str) -> Option<(&str, &str, &str)> {
    let line_end = text.find("\r\n").unwrap_or(text.len());
    let line = &text[..line_end];
    if line
        .as_bytes()
        .iter()
        .any(|&byte| matches!(byte, b'\r' | b'\n' | b'\0'))
    {
        return None;
    }
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let path = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some()
        || method.is_empty()
        || path.is_empty()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return None;
    }
    Some((method, path, version))
}

fn is_ssdp_m_search(text: &str) -> bool {
    let Some((method, path, _version)) = request_line(text) else {
        return false;
    };
    let Some(st) = header_value(text, "ST") else {
        return false;
    };
    let Some(host) = header_value(text, "HOST") else {
        return false;
    };
    let Some(mx) = header_value(text, "MX") else {
        return false;
    };
    method.eq_ignore_ascii_case("M-SEARCH")
        && path == "*"
        && is_valid_ssdp_host(host)
        && parse_ssdp_mx(mx).is_some()
        && header_value(text, "MAN")
            .is_some_and(|value| value.eq_ignore_ascii_case("\"ssdp:discover\""))
        && is_supported_search_target(st)
}

fn is_supported_search_target(value: &str) -> bool {
    matches!(
        value,
        v if v.eq_ignore_ascii_case("ssdp:all")
            || v.eq_ignore_ascii_case("upnp:rootdevice")
            || v.eq_ignore_ascii_case("uuid:nettrap")
            || v.eq_ignore_ascii_case("urn:schemas-upnp-org:device:InternetGatewayDevice:1")
            || v.eq_ignore_ascii_case("urn:schemas-upnp-org:service:WANIPConnection:1")
    )
}

fn is_valid_ssdp_host(value: &str) -> bool {
    const SSDP_IPV4_HOST: &str = "239.255.255.250";
    const SSDP_PORT: u16 = 1900;
    const SSDP_IPV6_MULTICAST: std::net::Ipv6Addr =
        std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000c);

    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if parse_ssdp_port(port) != Some(SSDP_PORT) {
        return false;
    }

    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip == SSDP_IPV6_MULTICAST);
    }

    host == SSDP_IPV4_HOST
}

fn header_value<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let header_section = text
        .split_once("\r\n\r\n")
        .map_or(text, |(headers, _)| headers);
    let mut value = None;
    for line in header_section.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((key, candidate)) = line.split_once(':') else {
            continue;
        };
        if is_http_token(key) && key.eq_ignore_ascii_case(name) {
            let candidate = candidate.trim_matches([' ', '\t']);
            if candidate.chars().any(|ch| !is_upnp_header_value_char(ch)) {
                return None;
            }
            match value {
                Some(_) => return None,
                None => value = Some(candidate),
            }
        }
    }
    value
}

fn strict_header_value<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let header_section = text
        .split_once("\r\n\r\n")
        .map_or(text, |(headers, _)| headers);
    let mut selected = None;
    for line in header_section.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((key, candidate)) = line.split_once(':') else {
            continue;
        };
        if is_http_token(key) && key.eq_ignore_ascii_case(name) {
            if candidate != candidate.trim_end() {
                return None;
            }
            if candidate.chars().any(|ch| !is_upnp_header_value_char(ch)) {
                return None;
            }
            match selected {
                Some(_) => return None,
                None => selected = Some(candidate),
            }
        }
    }
    selected
}

fn has_header(text: &str, name: &str) -> bool {
    let header_section = text
        .split_once("\r\n\r\n")
        .map_or(text, |(headers, _)| headers);
    header_section.split("\r\n").skip(1).any(|line| {
        line.split_once(':')
            .is_some_and(|(key, _)| is_http_token(key) && key.eq_ignore_ascii_case(name))
    })
}

fn content_length_matches_body(text: &str, body_len: usize) -> bool {
    let Some((headers, _)) = text.split_once("\r\n\r\n") else {
        return false;
    };

    let mut content_length = None;
    for line in headers.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }

        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if !key.eq_ignore_ascii_case("Content-Length") {
            continue;
        }

        let Some(parsed) = parse_content_length(value) else {
            return false;
        };
        match content_length {
            Some(_) => return false,
            None => content_length = Some(parsed),
        }
    }

    match content_length {
        Some(expected) => body_len == expected,
        None => body_len == 0,
    }
}

fn parse_content_length(value: &str) -> Option<usize> {
    let value = value.trim_matches([' ', '\t']);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn is_http_field_value_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff)
}

fn transfer_encoding_is_supported(text: &str) -> bool {
    let header_section = text
        .split_once("\r\n\r\n")
        .map_or(text, |(headers, _)| headers);
    let mut codings = Vec::new();
    for line in header_section.split("\r\n").skip(1) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if !key.eq_ignore_ascii_case("Transfer-Encoding") {
            continue;
        }
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

    codings.len() == 1 && codings[0].eq_ignore_ascii_case("chunked")
}

fn decode_chunked_body(data: &[u8], max_body_bytes: usize) -> Option<(usize, Vec<u8>)> {
    let mut pos = 0usize;
    let mut body = Vec::new();

    loop {
        let remaining = data.get(pos..)?;
        let rel_end = remaining.windows(2).position(|window| window == b"\r\n")?;
        if rel_end > MAX_UPNP_HEADER_BYTES {
            return None;
        }
        let line_end = pos + rel_end;
        let chunk_header_bytes = data.get(pos..line_end)?;
        let chunk_header = std::str::from_utf8(chunk_header_bytes).ok()?;
        let chunk_size = parse_chunk_size(chunk_header)?;
        pos = line_end + 2;

        if chunk_size == 0 {
            let trailers = data.get(pos..)?;
            if trailers.starts_with(b"\r\n") {
                return Some((pos + 2, body));
            }
            let trailer_end = trailers
                .windows(4)
                .position(|window| window == b"\r\n\r\n")?;
            if trailer_end > MAX_UPNP_HEADER_BYTES {
                return None;
            }
            let trailer_block = trailers.get(..trailer_end)?;
            if !chunk_trailers_are_well_formed(trailer_block) {
                return None;
            }
            return Some((pos + trailer_end + 4, body));
        }

        let data_end = pos.checked_add(chunk_size)?;
        let chunk_end = data_end.checked_add(2)?;
        let terminator = data.get(data_end..chunk_end)?;
        if terminator != b"\r\n" {
            return None;
        }

        let chunk_data = data.get(pos..data_end)?;
        if body.len().checked_add(chunk_size)? > max_body_bytes {
            return None;
        }
        body.extend_from_slice(chunk_data);
        pos = chunk_end;
    }
}

fn parse_chunk_size(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut pos = 0usize;
    while pos < bytes.len() && bytes[pos].is_ascii_hexdigit() {
        pos += 1;
    }
    if pos == 0 {
        return None;
    }

    let size = usize::from_str_radix(&value[..pos], 16).ok()?;
    pos = skip_chunk_bws(bytes, pos);
    if pos == bytes.len() {
        return Some(size);
    }

    while pos < bytes.len() {
        if bytes[pos] != b';' {
            return None;
        }
        pos += 1;
        pos = skip_chunk_bws(bytes, pos);
        if pos == bytes.len() {
            return None;
        }

        let name_start = pos;
        while pos < bytes.len() && is_chunk_token_byte(bytes[pos]) {
            pos += 1;
        }
        if pos == name_start {
            return None;
        }

        pos = skip_chunk_bws(bytes, pos);
        if pos < bytes.len() && bytes[pos] == b'=' {
            pos += 1;
            pos = skip_chunk_bws(bytes, pos);
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
                        if !is_chunk_quoted_pair_byte(byte) {
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
                while pos < bytes.len() && is_chunk_token_byte(bytes[pos]) {
                    pos += 1;
                }
                if pos == value_start {
                    return None;
                }
            }
        }

        pos = skip_chunk_bws(bytes, pos);
        if pos == bytes.len() {
            return Some(size);
        }
    }

    Some(size)
}

fn is_chunk_token_byte(byte: u8) -> bool {
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

fn is_chunk_quoted_pair_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' ' | 0x21..=0x7e | 0x80..=0xff)
}

fn skip_chunk_bws(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t') {
        pos += 1;
    }
    pos
}

fn chunk_trailers_are_well_formed(trailers: &[u8]) -> bool {
    if trailers
        .iter()
        .enumerate()
        .any(|(idx, &byte)| byte == b'\n' && (idx == 0 || trailers[idx - 1] != b'\r'))
    {
        return false;
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
            return false;
        }
        let Some(colon_pos) = line.iter().position(|&byte| byte == b':') else {
            return false;
        };
        let key = &line[..colon_pos];
        let value = trim_http_ows_bytes(&line[colon_pos + 1..]);
        let Ok(key) = std::str::from_utf8(key) else {
            return false;
        };
        if key.is_empty()
            || key != key.trim_matches([' ', '\t'])
            || !is_http_token(key)
            || key.chars().any(|ch| ch.is_control() || ch.is_whitespace())
            || !value.iter().all(|byte| is_http_field_value_byte(*byte))
        {
            return false;
        }
    }

    true
}

fn parse_ssdp_mx(value: &str) -> Option<u32> {
    let value = value.trim_matches([' ', '\t']);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u32>().ok().filter(|mx| *mx > 0)
}

fn parse_ssdp_port(value: &str) -> Option<u16> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u16>().ok().filter(|port| *port == 1900)
}

fn headers_are_well_formed(text: &str) -> bool {
    // The bare-LF check only applies to the HTTP header section. The message
    // body (after the \r\n\r\n separator) may legitimately contain bare
    // LF characters — e.g. XML/SOAP bodies with Unix line endings — and must
    // not cause the request to be rejected.
    let header_section = text
        .split_once("\r\n\r\n")
        .map_or(text, |(headers, _)| headers);
    if header_section
        .as_bytes()
        .iter()
        .enumerate()
        .any(|(idx, &byte)| byte == b'\r' && header_section.as_bytes().get(idx + 1) != Some(&b'\n'))
    {
        return false;
    }
    if header_section
        .as_bytes()
        .iter()
        .enumerate()
        .any(|(idx, &byte)| {
            byte == b'\n' && (idx == 0 || header_section.as_bytes()[idx - 1] != b'\r')
        })
    {
        return false;
    }

    for line in header_section.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let Some((key, _)) = line.split_once(':') else {
            return false;
        };
        let Some((_, value)) = line.split_once(':') else {
            return false;
        };
        if !is_http_token(key) || value.chars().any(|ch| !is_upnp_header_value_char(ch)) {
            return false;
        }
    }
    true
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

fn action_matches(action: &str, operation: &str) -> bool {
    let action = action.trim_start_matches([' ', '\t']);
    let action = if let Some(inner) = action.strip_prefix('"') {
        let Some(inner) = inner.strip_suffix('"') else {
            return false;
        };
        if inner.is_empty() || inner.contains('"') {
            return false;
        }
        inner
    } else {
        if action.contains('"') {
            return false;
        }
        action
    };
    if action != action.trim_end_matches([' ', '\t']) {
        return false;
    }
    let Some((service, action_name)) = action.rsplit_once('#') else {
        return false;
    };
    service == "urn:schemas-upnp-org:service:WANIPConnection:1" && action_name == operation
}

fn is_upnp_header_value_char(ch: char) -> bool {
    matches!(ch, ' ' | '\t')
        || matches!(ch as u32, 0x80..=0xff)
        || ((ch as u32) < 0x80 && !ch.is_control() && !ch.is_whitespace())
}

fn latin1_decode(data: &[u8]) -> String {
    data.iter().map(|&byte| char::from(byte)).collect()
}

fn request_log_preview(text: &str) -> String {
    nettrap_core::sanitize::single_line(&text.split("\r\n").take(3).collect::<Vec<_>>().join(" | "))
}

fn http_xml_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nServer: Linux/3.14 UPnP/1.1 NetTrap/1.0\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

fn add_port_mapping_response() -> &'static str {
    "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:AddPortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"></u:AddPortMappingResponse></s:Body></s:Envelope>"
}

fn delete_port_mapping_response() -> &'static str {
    "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:DeletePortMappingResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"></u:DeletePortMappingResponse></s:Body></s:Envelope>"
}

fn wanipconn_scpd() -> &'static str {
    "<?xml version=\"1.0\"?><scpd xmlns=\"urn:schemas-upnp-org:service-1-0\"><specVersion><major>1</major><minor>0</minor></specVersion><actionList><action><name>GetExternalIPAddress</name></action><action><name>AddPortMapping</name></action><action><name>DeletePortMapping</name></action></actionList><serviceStateTable><stateVariable sendEvents=\"no\"><name>NewRemoteHost</name><dataType>string</dataType></stateVariable><stateVariable sendEvents=\"no\"><name>NewExternalPort</name><dataType>ui2</dataType></stateVariable><stateVariable sendEvents=\"no\"><name>NewProtocol</name><dataType>string</dataType></stateVariable><stateVariable sendEvents=\"no\"><name>NewInternalPort</name><dataType>ui2</dataType></stateVariable><stateVariable sendEvents=\"no\"><name>NewInternalClient</name><dataType>string</dataType></stateVariable><stateVariable sendEvents=\"no\"><name>NewEnabled</name><dataType>boolean</dataType></stateVariable><stateVariable sendEvents=\"no\"><name>NewPortMappingDescription</name><dataType>string</dataType></stateVariable><stateVariable sendEvents=\"no\"><name>NewLeaseDuration</name><dataType>ui4</dataType></stateVariable></serviceStateTable></scpd>"
}

fn http_date_at(now: chrono::DateTime<chrono::Utc>) -> String {
    now.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn get_external_ip_address_response(listen_ip: &str) -> String {
    let external_ip = external_ip_address_value(listen_ip);
    format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:GetExternalIPAddressResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewExternalIPAddress>{}</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>",
        external_ip
    )
}

fn external_ip_address_value(listen_ip: &str) -> String {
    let value = listen_ip.trim_matches(['[', ']']);
    let Ok(ip) = value.parse::<std::net::IpAddr>() else {
        return DEFAULT_LISTEN_HOST.to_string();
    };
    match ip {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or_else(|| ip.to_string(), |mapped| mapped.to_string()),
    }
}

fn ssdp_response_identity(search_target: &str) -> (&'static str, &'static str) {
    if search_target.eq_ignore_ascii_case("ssdp:all")
        || search_target.eq_ignore_ascii_case("upnp:rootdevice")
    {
        return ("upnp:rootdevice", "uuid:nettrap::upnp:rootdevice");
    }
    if search_target.eq_ignore_ascii_case("uuid:nettrap") {
        return ("uuid:nettrap", "uuid:nettrap");
    }
    if search_target.eq_ignore_ascii_case("urn:schemas-upnp-org:device:InternetGatewayDevice:1") {
        return (
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            "uuid:nettrap::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        );
    }
    if search_target.eq_ignore_ascii_case("urn:schemas-upnp-org:service:WANIPConnection:1") {
        return (
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "uuid:nettrap::urn:schemas-upnp-org:service:WANIPConnection:1",
        );
    }

    ("upnp:rootdevice", "uuid:nettrap::upnp:rootdevice")
}

#[cfg(test)]
#[path = "handler_tests.rs"]
mod tests;
