use nettrap_core::error::{Error, Result};

pub(crate) const MAX_HEADER_SIZE: usize = 64 * 1024; // 64KB max headers
pub(crate) const MAX_TOTAL_SIZE: usize = 10 * 1024 * 1024; // 10MB max total request

pub(crate) struct ParsedHttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub(crate) fn parse_http_request_bytes(data: &[u8]) -> Result<Option<ParsedHttpRequest>> {
    if data.len() > MAX_TOTAL_SIZE {
        return Ok(None);
    }

    let header_end = match data.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(pos) => pos,
        None => return Ok(None),
    };

    if header_end > MAX_HEADER_SIZE {
        return Ok(None);
    }

    let header_str =
        std::str::from_utf8(&data[..header_end]).map_err(|e| Error::Parse(e.to_string()))?;

    let mut lines = header_str.lines();

    let request_line = lines
        .next()
        .ok_or_else(|| Error::Parse("No request line".into()))?;
    let (method, path, version) = parse_request_line(request_line)?;

    let mut headers = Vec::new();
    for line in lines {
        let Some(colon_pos) = line.find(':') else {
            continue;
        };
        let key = line[..colon_pos].trim().to_string();
        let value = line[colon_pos + 1..].trim().to_string();

        if key.contains('\r') || key.contains('\n') || value.contains('\r') || value.contains('\n')
        {
            tracing::warn!("HTTP header contains CRLF, rejecting request");
            return Ok(None);
        }

        headers.push((key, value));
    }

    let body_start = header_end + 4;
    let body = if let Some(transfer_encoding) = find_header_value(&headers, "Transfer-Encoding") {
        if !transfer_encoding
            .split(',')
            .any(|value| value.trim().eq_ignore_ascii_case("chunked"))
        {
            return Ok(None);
        }

        let Some((consumed, body)) = decode_chunked_body(&data[body_start..]) else {
            return Ok(None);
        };

        let max_body_len = MAX_TOTAL_SIZE.saturating_sub(body_start);
        if consumed > max_body_len || body.len() > max_body_len {
            return Ok(None);
        }

        body
    } else if let Some(content_length_raw) = find_header_value(&headers, "Content-Length") {
        let Ok(content_length) = content_length_raw.parse::<usize>() else {
            return Ok(None);
        };

        let max_body_len = MAX_TOTAL_SIZE.saturating_sub(body_start);
        if content_length > max_body_len {
            return Ok(None);
        }

        let available = data.len().saturating_sub(body_start);
        if available < content_length {
            return Ok(None);
        }

        data[body_start..body_start + content_length].to_vec()
    } else {
        Vec::new()
    };

    Ok(Some(ParsedHttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        version: version.to_string(),
        headers,
        body,
    }))
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
        || !is_valid_http_target(target)
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return Err(Error::Parse("Invalid request line".into()));
    }

    Ok((method, target, version))
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

fn is_valid_http_target(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace())
}

fn find_header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn decode_chunked_body(data: &[u8]) -> Option<(usize, Vec<u8>)> {
    let mut pos = 0usize;
    let mut body = Vec::new();

    loop {
        let line_end = pos
            + data[pos..]
                .windows(2)
                .position(|window| window == b"\r\n")?;
        let chunk_header = std::str::from_utf8(&data[pos..line_end]).ok()?;
        let chunk_size = usize::from_str_radix(chunk_header.split(';').next()?.trim(), 16).ok()?;
        pos = line_end + 2;

        if chunk_size == 0 {
            let trailers = &data[pos..];
            if trailers.starts_with(b"\r\n") {
                return Some((pos + 2, body));
            }

            let trailer_end = trailers
                .windows(4)
                .position(|window| window == b"\r\n\r\n")?;
            return Some((pos + trailer_end + 4, body));
        }

        let data_end = pos.checked_add(chunk_size)?;
        if data.len() < data_end + 2 {
            return None;
        }

        if &data[data_end..data_end + 2] != b"\r\n" {
            return None;
        }

        body.extend_from_slice(&data[pos..data_end]);
        pos = data_end + 2;
    }
}
