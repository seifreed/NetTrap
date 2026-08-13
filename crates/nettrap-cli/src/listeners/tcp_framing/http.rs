//! HTTP request framing: header/body delimitation, chunked transfer

use super::{MAX_HTTP_HEADER_SIZE, MAX_HTTP_REQUEST_SIZE, TcpFrameResult, find_subslice};

pub(crate) fn extract_http_request(buffer: &mut Vec<u8>) -> TcpFrameResult {
    let Some(header_end) = find_subslice(buffer, b"\r\n\r\n") else {
        if buffer.len() > MAX_HTTP_HEADER_SIZE {
            buffer.clear();
            return TcpFrameResult::TooLarge {
                response: Some(http_error_response(431, "Request Header Fields Too Large")),
            };
        }
        return TcpFrameResult::Incomplete;
    };

    let headers_end = header_end + 4;
    let headers = &buffer[..headers_end];

    if header_end > MAX_HTTP_HEADER_SIZE {
        buffer.clear();
        return TcpFrameResult::TooLarge {
            response: Some(http_error_response(431, "Request Header Fields Too Large")),
        };
    }

    if !valid_http_request_line(&headers[..header_end]) {
        buffer.clear();
        return TcpFrameResult::Invalid {
            response: Some(http_error_response(400, "Bad Request")),
        };
    }

    match http_body_framing(headers) {
        Ok(framing) => extract_http_request_with_framing(buffer, headers_end, framing),
        Err(HttpFrameError::Invalid) => {
            buffer.clear();
            TcpFrameResult::Invalid {
                response: Some(http_error_response(400, "Bad Request")),
            }
        }
        Err(HttpFrameError::TooLarge) => {
            buffer.clear();
            TcpFrameResult::TooLarge {
                response: Some(http_error_response(413, "Payload Too Large")),
            }
        }
    }
}

pub(crate) fn valid_http_request_line(headers_without_terminator: &[u8]) -> bool {
    // When the request carries no header fields (e.g. `GET / HTTP/1.0\r\n\r\n`),
    // the slice before the blank-line terminator is the request line alone, with
    // no trailing CRLF. Treat the whole slice as the request line in that case
    // rather than rejecting an otherwise-valid header-less request.
    if headers_without_terminator
        .iter()
        .enumerate()
        .any(|(idx, &byte)| {
            byte == b'\n' && (idx == 0 || headers_without_terminator[idx - 1] != b'\r')
        })
    {
        return false;
    }

    let line_end = find_subslice(headers_without_terminator, b"\r\n")
        .unwrap_or(headers_without_terminator.len());
    let request_line = &headers_without_terminator[..line_end];
    if request_line.contains(&b'\r') {
        return false;
    }
    let mut parts = request_line.split(|&byte| byte == b' ');
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(target) = parts.next() else {
        return false;
    };
    let Some(version) = parts.next() else {
        return false;
    };

    if parts.next().is_some() {
        return false;
    }

    !method.is_empty()
        && method.iter().copied().all(is_http_token_byte)
        && !target.is_empty()
        && target
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_graphic() && byte != b' ')
        && matches!(version, b"HTTP/1.0" | b"HTTP/1.1")
}

pub(crate) fn is_http_token_byte(byte: u8) -> bool {
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

pub(crate) fn extract_http_request_with_framing(
    buffer: &mut Vec<u8>,
    headers_end: usize,
    framing: HttpBodyFraming,
) -> TcpFrameResult {
    match framing {
        HttpBodyFraming::Chunked => match extract_chunked_http_body_len(buffer, headers_end) {
            Ok(Some(total_len)) => TcpFrameResult::Complete(buffer.drain(..total_len).collect()),
            Ok(None) => TcpFrameResult::Incomplete,
            Err(HttpFrameError::Invalid) => {
                buffer.clear();
                TcpFrameResult::Invalid {
                    response: Some(http_error_response(400, "Bad Request")),
                }
            }
            Err(HttpFrameError::TooLarge) => {
                buffer.clear();
                TcpFrameResult::TooLarge {
                    response: Some(http_error_response(413, "Payload Too Large")),
                }
            }
        },
        HttpBodyFraming::ContentLength(content_length) => {
            let Some(total_len) = headers_end.checked_add(content_length) else {
                buffer.clear();
                return TcpFrameResult::TooLarge {
                    response: Some(http_error_response(413, "Payload Too Large")),
                };
            };
            if total_len > MAX_HTTP_REQUEST_SIZE {
                buffer.clear();
                return TcpFrameResult::TooLarge {
                    response: Some(http_error_response(413, "Payload Too Large")),
                };
            }
            if buffer.len() < total_len {
                return TcpFrameResult::Incomplete;
            }
            TcpFrameResult::Complete(buffer.drain(..total_len).collect())
        }
        HttpBodyFraming::HeadersOnly => {
            TcpFrameResult::Complete(buffer.drain(..headers_end).collect())
        }
    }
}

pub(crate) fn extract_chunked_http_body_len(
    buffer: &[u8],
    mut pos: usize,
) -> std::result::Result<Option<usize>, HttpFrameError> {
    loop {
        let Some(line_offset) = find_subslice(&buffer[pos..], b"\r\n") else {
            if has_invalid_http_line_ending(&buffer[pos..]) {
                return Err(HttpFrameError::Invalid);
            }
            return if buffer.len() > MAX_HTTP_REQUEST_SIZE {
                Err(HttpFrameError::TooLarge)
            } else {
                Ok(None)
            };
        };
        let line_end = pos + line_offset;
        let chunk_header =
            std::str::from_utf8(&buffer[pos..line_end]).map_err(|_| HttpFrameError::Invalid)?;
        let chunk_size = parse_http_chunk_size(chunk_header).ok_or(HttpFrameError::Invalid)?;
        pos = line_end + 2;

        if chunk_size == 0 {
            let trailers = &buffer[pos..];
            if trailers.starts_with(b"\r\n") {
                return Ok(Some(pos + 2));
            }

            let Some(trailer_end) = find_subslice(trailers, b"\r\n\r\n") else {
                if has_invalid_http_line_ending(trailers) {
                    return Err(HttpFrameError::Invalid);
                }
                return if buffer.len() > MAX_HTTP_REQUEST_SIZE {
                    Err(HttpFrameError::TooLarge)
                } else {
                    Ok(None)
                };
            };
            let trailer_block = &trailers[..trailer_end];
            if !chunk_trailers_are_well_formed(trailer_block) {
                return Err(HttpFrameError::Invalid);
            }
            let total_len = pos + trailer_end + 4;
            return if total_len > MAX_HTTP_REQUEST_SIZE {
                Err(HttpFrameError::TooLarge)
            } else {
                Ok(Some(total_len))
            };
        }

        let data_end = pos
            .checked_add(chunk_size)
            .ok_or(HttpFrameError::TooLarge)?;
        let frame_end = data_end.checked_add(2).ok_or(HttpFrameError::TooLarge)?;
        if frame_end > MAX_HTTP_REQUEST_SIZE {
            return Err(HttpFrameError::TooLarge);
        }
        if buffer.len() < frame_end {
            return Ok(None);
        }

        if &buffer[data_end..data_end + 2] != b"\r\n" {
            return Err(HttpFrameError::Invalid);
        }

        pos = frame_end;
    }
}

fn has_invalid_http_line_ending(data: &[u8]) -> bool {
    data.iter().enumerate().any(|(idx, &byte)| {
        byte == b'\n' && (idx == 0 || data[idx - 1] != b'\r')
            || byte == b'\r' && idx + 1 < data.len() && data[idx + 1] != b'\n'
    })
}

fn chunk_trailers_are_well_formed(trailers: &[u8]) -> bool {
    if trailers
        .iter()
        .enumerate()
        .any(|(idx, &byte)| byte == b'\n' && (idx == 0 || trailers[idx - 1] != b'\r'))
    {
        return false;
    }

    let mut pos = 0;
    loop {
        let Some(line_offset) = find_subslice(&trailers[pos..], b"\r\n") else {
            let line = &trailers[pos..];
            if line.is_empty() {
                return true;
            }
            let Some(colon) = line.iter().position(|&byte| byte == b':') else {
                return false;
            };
            let key = &line[..colon];
            let value = &line[colon + 1..];
            return !key.is_empty()
                && key == trim_ascii_space_tab(key)
                && key.iter().copied().all(is_http_token_byte)
                && value.iter().copied().all(is_http_field_value_byte);
        };
        let line = &trailers[pos..pos + line_offset];
        pos += line_offset + 2;
        if line.is_empty() {
            if pos == trailers.len() {
                return true;
            }
            continue;
        }
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            return false;
        };
        let key = &line[..colon];
        let value = &line[colon + 1..];
        if key.is_empty()
            || key != trim_ascii_space_tab(key)
            || !key.iter().copied().all(is_http_token_byte)
            || !value.iter().copied().all(is_http_field_value_byte)
        {
            return false;
        }
        if pos == trailers.len() {
            return true;
        }
    }
}

fn next_crlf_line(bytes: &[u8], start: usize) -> Option<(&[u8], usize)> {
    let relative_end = bytes[start..]
        .windows(2)
        .position(|window| window == b"\r\n")?;
    let end = start + relative_end;
    Some((&bytes[start..end], end + 2))
}

fn trim_ascii_space_tab(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && matches!(bytes[start], b' ' | b'\t') {
        start += 1;
    }
    while end > start && matches!(bytes[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    &bytes[start..end]
}

fn is_http_field_value_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' '..=b'~' | 0x80..=0xff)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpBodyFraming {
    HeadersOnly,
    ContentLength(usize),
    Chunked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpFrameError {
    Invalid,
    TooLarge,
}

pub(crate) fn http_body_framing(
    headers: &[u8],
) -> std::result::Result<HttpBodyFraming, HttpFrameError> {
    if headers
        .iter()
        .enumerate()
        .any(|(idx, &byte)| byte == b'\n' && (idx == 0 || headers[idx - 1] != b'\r'))
    {
        return Err(HttpFrameError::Invalid);
    }

    let Some((request_line, mut pos)) = next_crlf_line(headers, 0) else {
        return Err(HttpFrameError::Invalid);
    };
    if request_line.is_empty() {
        return Err(HttpFrameError::Invalid);
    }
    let mut transfer_codings = Vec::new();
    let mut content_length = None;

    loop {
        let Some((line, next_pos)) = next_crlf_line(headers, pos) else {
            return Err(HttpFrameError::Invalid);
        };
        pos = next_pos;
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            return Err(HttpFrameError::Invalid);
        };
        let name = &line[..colon];
        let value = &line[colon + 1..];
        if name.is_empty()
            || name != trim_ascii_space_tab(name)
            || !name.iter().copied().all(is_http_token_byte)
            || !value.iter().copied().all(is_http_field_value_byte)
        {
            return Err(HttpFrameError::Invalid);
        }

        if name.eq_ignore_ascii_case(b"Transfer-Encoding") {
            for coding in value.split(|byte| *byte == b',').map(trim_ascii_space_tab) {
                if coding.is_empty() {
                    return Err(HttpFrameError::Invalid);
                }
                let Ok(coding) = std::str::from_utf8(coding) else {
                    return Err(HttpFrameError::Invalid);
                };
                transfer_codings.push(coding);
            }
        } else if name.eq_ignore_ascii_case(b"Content-Length") {
            let value = trim_ascii_space_tab(value);
            let Ok(value) = std::str::from_utf8(value) else {
                return Err(HttpFrameError::Invalid);
            };
            let Some(length) = parse_http_content_length(value) else {
                return Err(HttpFrameError::Invalid);
            };
            match content_length {
                Some(previous) if previous != length => return Err(HttpFrameError::Invalid),
                None => content_length = Some(length),
                _ => {}
            }
        }
    }

    if !transfer_codings.is_empty() {
        if content_length.is_some() {
            return Err(HttpFrameError::Invalid);
        }
        let chunked_count = transfer_codings
            .iter()
            .filter(|coding| coding.eq_ignore_ascii_case("chunked"))
            .count();

        if chunked_count == 1 && transfer_codings.len() == 1 {
            return Ok(HttpBodyFraming::Chunked);
        }
        return Err(HttpFrameError::Invalid);
    }

    if let Some(length) = content_length {
        if length > MAX_HTTP_REQUEST_SIZE {
            return Err(HttpFrameError::TooLarge);
        }
        return Ok(HttpBodyFraming::ContentLength(length));
    }

    Ok(HttpBodyFraming::HeadersOnly)
}

pub(crate) fn parse_http_content_length(value: &str) -> Option<usize> {
    let value = value.trim_matches([' ', '\t']);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

pub(crate) fn parse_http_chunk_size(value: &str) -> Option<usize> {
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
            if bytes[pos] == b'\"' {
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
                        b'\"' => {
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

pub(crate) fn http_error_response(status_code: u16, reason: &str) -> Vec<u8> {
    let body = format!("{status_code} {reason}\r\n");
    format!(
        "HTTP/1.1 {status_code} {reason}\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn skip_http_bws(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t') {
        pos += 1;
    }
    pos
}

fn is_http_quoted_pair_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' ' | 0x21..=0x7E | 0x80..=0xFF)
}

#[cfg(test)]
mod tests {
    use super::{
        HttpBodyFraming, TcpFrameResult, extract_http_request, http_body_framing,
        parse_http_chunk_size, parse_http_content_length,
    };

    #[test]
    fn extract_http_request_rejects_headers_with_leading_whitespace() {
        let mut buffer =
            b"POST / HTTP/1.1\r\n Host: example.test\r\nContent-Length: 0\r\n\r\n".to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Invalid { .. }));
        assert!(buffer.is_empty());
    }

    #[test]
    fn extract_http_request_rejects_bare_lf_in_request_line() {
        let mut buffer =
            b"POST / HTTP/1.1\nHost: example.test\r\nContent-Length: 0\r\n\r\n".to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Invalid { .. }));
        assert!(buffer.is_empty());
    }

    #[test]
    fn extract_http_request_rejects_headers_with_unicode_whitespace_in_name() {
        let mut buffer =
            "POST / HTTP/1.1\r\nHost\u{00a0}: example.test\r\nContent-Length: 0\r\n\r\n"
                .as_bytes()
                .to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Invalid { .. }));
        assert!(buffer.is_empty());
    }

    #[test]
    fn extract_http_request_rejects_headers_without_colons() {
        let mut buffer =
            b"POST / HTTP/1.1\r\nHost: example.test\r\nBroken-Header\r\nContent-Length: 0\r\n\r\n"
                .to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Invalid { .. }));
        assert!(buffer.is_empty());
    }

    #[test]
    fn extract_http_request_rejects_headers_with_spaces_in_names() {
        let mut buffer =
            b"POST / HTTP/1.1\r\nHost: example.test\r\nBad Header: value\r\nContent-Length: 0\r\n\r\n"
                .to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Invalid { .. }));
        assert!(buffer.is_empty());
    }

    #[test]
    fn extract_http_request_rejects_headers_with_invalid_token_names() {
        let mut buffer =
            b"POST / HTTP/1.1\r\nHost: example.test\r\nBad@Header: value\r\nContent-Length: 0\r\n\r\n"
                .to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Invalid { .. }));
        assert!(buffer.is_empty());
    }

    #[test]
    fn extract_http_request_rejects_headers_with_control_bytes_in_values() {
        let mut buffer =
            b"POST / HTTP/1.1\r\nHost: example.test\r\nX-Test: hello\x0bworld\r\nContent-Length: 0\r\n\r\n"
                .to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Invalid { .. }));
        assert!(buffer.is_empty());
    }

    #[test]
    fn extract_http_request_rejects_chunked_trailers_with_invalid_header_names() {
        let mut buffer = b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nBad Header: value\r\n\r\n".to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Invalid { .. }));
        assert!(buffer.is_empty());
    }

    #[test]
    fn extract_http_request_rejects_chunked_trailers_with_invalid_token_header_names() {
        let mut buffer = b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nBad@Header: value\r\n\r\n".to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Invalid { .. }));
        assert!(buffer.is_empty());
    }

    #[test]
    fn extract_http_request_rejects_line_feed_only_chunk_headers() {
        let mut buffer =
            b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\ntest\r\n0\r\n\r\n"
                .to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Invalid { .. }));
        assert!(buffer.is_empty());
    }

    #[test]
    fn extract_http_request_rejects_line_feed_only_chunk_trailers() {
        let mut buffer =
            b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nBad-Trailer: value\n\r\n"
                .to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Invalid { .. }));
        assert!(buffer.is_empty());
    }

    #[test]
    fn extract_http_request_accepts_chunked_trailers_with_ascii_ows_values() {
        let mut buffer = b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nDigest: sha-256=abc123\r\nX-Note:\tchunk complete\r\n\r\n".to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Complete(frame) if frame.ends_with(b"\r\n\r\n")));
        assert!(buffer.is_empty());
    }

    #[test]
    fn extract_http_request_accepts_chunked_trailers_with_unicode_whitespace_bytes() {
        let mut buffer =
            "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nBad-Trailer: \u{00a0}value\r\n\r\n"
                .as_bytes()
                .to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Complete(frame) if frame.ends_with(b"\r\n\r\n")));
        assert!(buffer.is_empty());
    }

    #[test]
    fn extract_http_request_accepts_chunked_trailers_with_c1_control_bytes() {
        let mut buffer =
            "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\nBad-Trailer: value\u{009f}\r\n\r\n"
                .as_bytes()
                .to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Complete(frame) if frame.ends_with(b"\r\n\r\n")));
        assert!(buffer.is_empty());
    }

    #[test]
    fn content_length_and_chunk_sizes_reject_unicode_whitespace_padding() {
        assert_eq!(parse_http_content_length(" 5"), Some(5));
        assert_eq!(parse_http_content_length("5\u{00a0}"), None);
        assert_eq!(parse_http_chunk_size(" a"), None);
        assert_eq!(parse_http_chunk_size("a\u{00a0}"), None);
    }

    #[test]
    fn parse_http_chunk_size_accepts_chunk_extensions_after_size() {
        assert_eq!(parse_http_chunk_size("1a;foo=bar"), Some(26));
    }

    #[test]
    fn parse_http_chunk_size_rejects_empty_chunk_extension_segments() {
        assert_eq!(parse_http_chunk_size("1a;"), None);
        assert_eq!(parse_http_chunk_size("1a; foo=bar"), Some(26));
    }

    #[test]
    fn parse_http_chunk_size_accepts_bws_and_quoted_extensions() {
        assert_eq!(parse_http_chunk_size("1a ; foo = bar"), Some(26));
        assert_eq!(parse_http_chunk_size("4;foo=\"bar baz\""), Some(4));
    }

    #[test]
    fn parse_http_chunk_size_rejects_invalid_escaped_extension_byte() {
        assert_eq!(parse_http_chunk_size("4;foo=\"bar\0\""), None);
    }

    #[test]
    fn extract_http_request_accepts_chunk_extensions_with_bws_and_quoted_values() {
        let mut buffer =
            b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4 ; foo = bar\r\ntest\r\n0\r\n\r\n".to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Complete(frame) if frame.ends_with(b"\r\n\r\n")));
        assert!(buffer.is_empty());
    }

    #[test]
    fn extract_http_request_rejects_invalid_chunk_extension_escape() {
        let mut buffer =
            b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=\"bar\x00\"\r\ntest\r\n0\r\n\r\n".to_vec();

        let result = extract_http_request(&mut buffer);

        assert!(matches!(result, TcpFrameResult::Invalid { .. }));
        assert!(buffer.is_empty());
    }

    #[test]
    fn http_body_framing_accepts_equivalent_duplicate_content_length_values() {
        let headers =
            b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 05\r\nContent-Length: 5\r\n\r\n";

        let framing = http_body_framing(headers).expect("framing should be valid");

        assert_eq!(framing, HttpBodyFraming::ContentLength(5));
    }

    #[test]
    fn http_body_framing_rejects_duplicate_chunked_values() {
        let headers = b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n";

        let result = http_body_framing(headers);

        assert!(matches!(result, Err(super::HttpFrameError::Invalid)));
    }

    #[test]
    fn http_body_framing_rejects_chunked_when_not_final_coding() {
        let headers =
            b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked, gzip\r\n\r\n";

        let result = http_body_framing(headers);

        assert!(matches!(result, Err(super::HttpFrameError::Invalid)));
    }

    #[test]
    fn http_body_framing_rejects_mixed_transfer_codings_with_chunked() {
        let headers =
            b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";

        let result = http_body_framing(headers);

        assert!(matches!(result, Err(super::HttpFrameError::Invalid)));
    }

    #[test]
    fn http_body_framing_rejects_mixed_line_endings_in_headers() {
        let headers = b"POST / HTTP/1.1\r\nHost: example.test\nContent-Length: 0\r\n\r\n";

        let result = http_body_framing(headers);

        assert!(matches!(result, Err(super::HttpFrameError::Invalid)));
    }

    #[test]
    fn http_body_framing_rejects_double_carriage_returns_in_headers() {
        let headers = b"POST / HTTP/1.1\r\nHost: example.test\r\r\nContent-Length: 0\r\n\r\n";

        let result = http_body_framing(headers);

        assert!(matches!(result, Err(super::HttpFrameError::Invalid)));
    }

    #[test]
    fn http_body_framing_accepts_obs_text_bytes_in_headers() {
        let headers =
            b"POST / HTTP/1.1\r\nHost: example.test\r\nX-Test: hi\xff\r\nContent-Length: 0\r\n\r\n";

        let result = http_body_framing(headers);

        assert!(matches!(result, Ok(HttpBodyFraming::ContentLength(0))));
    }

    #[test]
    fn chunk_trailers_accept_obs_text_bytes() {
        let trailers = b"Trailer: value\xff\r\n\r\n";

        assert!(super::chunk_trailers_are_well_formed(trailers));
    }
}
