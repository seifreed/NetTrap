pub struct SipHandler {
    domain: String,
}

const MAX_SIP_HEADER_BYTES: usize = 64 * 1024;
const MAX_SIP_BODY_BYTES: usize = 1024 * 1024;

impl SipHandler {
    pub fn new() -> Self {
        Self {
            domain: "nettrap.local".to_string(),
        }
    }

    /// Case-insensitive SIP header extraction (RFC 3261 §7.3.1)
    /// Handles optional whitespace before the colon per RFC 3261 SWS rules.
    fn extract_header<'a>(text: &'a str, name: &str) -> Option<&'a str> {
        let lower_name = name.to_ascii_lowercase();
        text.lines()
            .find(|l| {
                let Some((key, _)) = l.split_once(':') else {
                    return false;
                };
                !key.is_empty()
                    && !key.chars().next().is_some_and(char::is_whitespace)
                    && sip_header_name_matches(key.trim_matches([' ', '\t']), &lower_name)
            })
            .and_then(|l| l.split_once(':'))
            .and_then(|(_, v)| {
                let value = v.trim_matches([' ', '\t']);
                if value
                    .chars()
                    .any(|ch| matches!(ch, '\r' | '\n' | '\u{0085}' | '\u{2028}' | '\u{2029}'))
                {
                    None
                } else {
                    Some(value)
                }
            })
    }

    fn extract_unique_header<'a>(text: &'a str, name: &str) -> Result<Option<&'a str>, ()> {
        let lower_name = name.to_ascii_lowercase();
        let mut value = None;

        for line in text.lines() {
            let Some((key, candidate)) = line.split_once(':') else {
                continue;
            };
            if key.is_empty()
                || key.chars().next().is_some_and(char::is_whitespace)
                || !sip_header_name_matches(key.trim_matches([' ', '\t']), &lower_name)
            {
                continue;
            }

            let candidate = candidate.trim_matches([' ', '\t']);
            if candidate
                .chars()
                .any(|ch| matches!(ch, '\r' | '\n' | '\u{0085}' | '\u{2028}' | '\u{2029}'))
            {
                return Err(());
            }
            if value.is_some() {
                return Err(());
            }
            value = Some(candidate);
        }

        Ok(value)
    }

    /// Sanitize a SIP header value to prevent header injection via CRLF
    fn sanitize_header_value(value: &str) -> String {
        value
            .chars()
            .map(|ch| {
                if ch.is_control() || ch.is_whitespace() {
                    ' '
                } else {
                    ch
                }
            })
            .collect()
    }

    fn request_method(first_line: &str) -> Option<&str> {
        if nettrap_core::sanitize::contains_unicode_line_separator(first_line) {
            return None;
        }
        let mut parts = first_line.split(' ');
        let method = parts.next()?;
        let target = parts.next()?;
        let version = parts.next()?;
        if method.is_empty()
            || target.is_empty()
            || target
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace())
            || method.starts_with("SIP/")
            || !method.bytes().all(|byte| byte.is_ascii_uppercase())
            || version != "SIP/2.0"
            || parts.next().is_some()
        {
            return None;
        }
        Some(method)
    }

    fn cseq_matches_method(cseq: &str, method: &str) -> bool {
        if cseq.contains('\t') {
            return false;
        }
        let parts: Vec<&str> = cseq.split(' ').collect();
        if parts.iter().skip(1).any(|part| part.is_empty()) {
            return false;
        }
        let mut parts = parts.into_iter();
        let Some(sequence) = parts.next() else {
            return false;
        };
        let Some(cseq_method) = parts.next() else {
            return false;
        };
        matches!(
            nettrap_core::parse::unsigned_decimal::<u32>(sequence.trim_matches([' ', '\t'])),
            Some(sequence) if sequence > 0
        ) && parts.next().is_none()
            && cseq_method.eq_ignore_ascii_case(method)
    }

    fn message_sections(data: &[u8]) -> Option<(String, usize)> {
        let header_end = data
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|pos| pos + 4)?;
        if header_end > MAX_SIP_HEADER_BYTES {
            return None;
        }
        if data[..header_end]
            .iter()
            .enumerate()
            .any(|(idx, &byte)| byte == b'\n' && (idx == 0 || data[idx - 1] != b'\r'))
        {
            return None;
        }
        if data[..header_end]
            .iter()
            .enumerate()
            .any(|(idx, &byte)| byte == b'\r' && idx + 1 < data.len() && data[idx + 1] != b'\n')
        {
            return None;
        }
        let body_len = data.len() - header_end;
        if body_len > MAX_SIP_BODY_BYTES {
            return None;
        }
        let headers = std::str::from_utf8(&data[..header_end]).ok()?.to_string();
        if headers
            .chars()
            .any(|ch| matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
        {
            return None;
        }
        Some((headers, body_len))
    }

    fn content_length_matches_body(headers: &str, body_len: usize) -> bool {
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
            let Some(parsed) =
                nettrap_core::parse::unsigned_decimal::<usize>(value.trim_matches([' ', '\t']))
            else {
                return false;
            };
            match content_length {
                Some(current) if current != parsed => return false,
                Some(_) => {}
                None => content_length = Some(parsed),
            }
        }

        match content_length {
            Some(content_length) => body_len == content_length,
            None => body_len == 0,
        }
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        let Some((headers, body_len)) = Self::message_sections(data) else {
            return Vec::new();
        };
        if !Self::content_length_matches_body(&headers, body_len) {
            return Vec::new();
        }
        if !Self::headers_are_well_formed(&headers) {
            return Vec::new();
        }

        let first_line = headers.lines().next().unwrap_or("");
        if nettrap_core::sanitize::contains_unicode_line_separator(first_line) {
            return Vec::new();
        }
        let Some(method) = Self::request_method(first_line) else {
            return Vec::new();
        };
        tracing::debug!("SIP packet: {}", safe_log_line(first_line));
        tracing::warn!("SIP packet: method={}", method);

        // Extract mandatory headers (case-insensitive per RFC 3261)
        // Sanitize to prevent header injection via CRLF in attacker-controlled values
        let Some(via_raw) = Self::extract_header(&headers, "Via") else {
            return Vec::new();
        };
        let via = Self::sanitize_header_value(via_raw);
        let from = match Self::extract_unique_header(&headers, "From") {
            Ok(Some(value)) => Self::sanitize_header_value(value),
            Ok(None) => return Vec::new(),
            Err(()) => return Vec::new(),
        };
        let to = match Self::extract_unique_header(&headers, "To") {
            Ok(Some(value)) => Self::sanitize_header_value(value),
            Ok(None) => return Vec::new(),
            Err(()) => return Vec::new(),
        };
        let call_id = match Self::extract_unique_header(&headers, "Call-ID") {
            Ok(Some(value)) => Self::sanitize_header_value(value),
            Ok(None) => return Vec::new(),
            Err(()) => return Vec::new(),
        };
        let Some(cseq_raw) = (match Self::extract_unique_header(&headers, "CSeq") {
            Ok(value) => value,
            Err(()) => return Vec::new(),
        }) else {
            return Vec::new();
        };
        if !Self::cseq_matches_method(cseq_raw, method) {
            return Vec::new();
        }
        let cseq = Self::sanitize_header_value(cseq_raw);

        if matches!(method, "REGISTER" | "INVITE") {
            format!(
                "SIP/2.0 401 Unauthorized\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {}\r\nWWW-Authenticate: Digest realm=\"{}\", nonce=\"nettrap\"\r\nContent-Length: 0\r\n\r\n",
                via, from, to, call_id, cseq, self.domain
            )
            .into_bytes()
        } else if method == "OPTIONS" {
            format!(
                "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {}\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER\r\nContent-Length: 0\r\n\r\n",
                via, from, to, call_id, cseq
            )
            .into_bytes()
        } else if matches!(method, "BYE" | "ACK" | "CANCEL") {
            format!(
                "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {}\r\nContent-Length: 0\r\n\r\n",
                via, from, to, call_id, cseq
            )
            .into_bytes()
        } else {
            format!(
                "SIP/2.0 405 Method Not Allowed\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {}\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER\r\nContent-Length: 0\r\n\r\n",
                via, from, to, call_id, cseq
            )
            .into_bytes()
        }
    }

    fn headers_are_well_formed(headers: &str) -> bool {
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
}

fn sip_header_name_matches(candidate: &str, canonical_lower: &str) -> bool {
    let candidate_lower = candidate.to_ascii_lowercase();
    candidate.eq_ignore_ascii_case(canonical_lower)
        || matches!(
            (canonical_lower, candidate_lower.as_str()),
            ("via", "v") | ("from", "f") | ("to", "t") | ("call-id", "i") | ("content-length", "l")
        )
}

fn safe_log_line(value: &str) -> String {
    nettrap_core::sanitize::single_line(value)
}

impl Default for SipHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG_LINE_PREVIEW_CHARS: usize = 240;

    fn options_request(extra_headers: &str) -> Vec<u8> {
        format!(
            "OPTIONS sip:service@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:service@example.com>\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\n{extra_headers}\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn responds_to_known_sip_request() {
        let response = SipHandler::new().handle(&options_request(""));

        assert!(String::from_utf8_lossy(&response).starts_with("SIP/2.0 200 OK"));
    }

    #[test]
    fn content_length_accepts_whitespace_before_colon() {
        let response = SipHandler::new().handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:service@example.com>\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\nContent-Length : 4\r\n\r\nbody",
        );

        assert!(String::from_utf8_lossy(&response).starts_with("SIP/2.0 200 OK"));
    }

    #[test]
    fn accepts_compact_sip_headers() {
        let response = SipHandler::new().handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nv: SIP/2.0/UDP 10.0.0.1\r\nf: <sip:alice@example.com>\r\nt: <sip:service@example.com>\r\ni: abc\r\nCSeq: 1 OPTIONS\r\nl: 4\r\n\r\nbody",
        );

        assert!(String::from_utf8_lossy(&response).starts_with("SIP/2.0 200 OK"));
    }

    #[test]
    fn accepts_uppercase_compact_sip_headers() {
        let response = SipHandler::new().handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nV: SIP/2.0/UDP 10.0.0.1\r\nF: <sip:alice@example.com>\r\nT: <sip:service@example.com>\r\nI: abc\r\nCSeq: 1 OPTIONS\r\nL: 4\r\n\r\nbody",
        );

        assert!(String::from_utf8_lossy(&response).starts_with("SIP/2.0 200 OK"));
    }

    #[test]
    fn rejects_known_sip_request_without_mandatory_headers() {
        let response = SipHandler::new().handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\n\r\n",
        );

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_sip_response() {
        let response = SipHandler::new().handle(b"SIP/2.0 200 OK\r\nCall-ID: abc\r\n\r\n");

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_non_sip_payload_on_sip_port() {
        let response = SipHandler::new().handle(b"not sip");

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_unsupported_sip_request_method() {
        let response = SipHandler::new().handle(
            b"MESSAGE sip:service@example.com SIP/2.0\r\n\
                Via: SIP/2.0/TCP client.example.com;branch=z9hG4bK\r\n\
                From: <sip:alice@example.com>;tag=1\r\n\
                To: <sip:service@example.com>\r\n\
                Call-ID: abc\r\n\
                CSeq: 1 MESSAGE\r\n\
                Content-Length: 0\r\n\r\n",
        );

        let response = std::str::from_utf8(&response).expect("response is utf-8");
        assert!(response.contains("405 Method Not Allowed"));
        assert!(response.contains("Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER"));
    }

    #[test]
    fn ignores_malformed_sip_request_lines() {
        let handler = SipHandler::new();

        assert!(
            handler
                .handle(b"OPTIONS sip:service@example.com SIP/2.0 extra\r\n\r\n")
                .is_empty()
        );
        assert!(
            handler
                .handle(b"OPTIONS  sip:service@example.com SIP/2.0\r\n\r\n")
                .is_empty()
        );
        assert!(handler.handle(b"OPTIONS  SIP/2.0\r\n\r\n").is_empty());
        assert!(
            handler
                .handle(b"OPTIONS sip:service@example.com SIP/3.0\r\n\r\n")
                .is_empty()
        );
    }

    #[test]
    fn rejects_request_line_with_extra_fields_even_when_headers_are_valid() {
        let response = SipHandler::new().handle(
            b"OPTIONS sip:service@example.com SIP/2.0 extra\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:service@example.com>\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
        );

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_request_line_with_control_whitespace_in_target() {
        let handler = SipHandler::new();

        for request in [
            b"OPTIONS sip:service\talias@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:service@example.com>\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n".as_slice(),
            "OPTIONS sip:service\u{00a0}alias@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:service@example.com>\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n".as_bytes(),
        ] {
            assert!(handler.handle(request).is_empty(), "{request:?}");
        }
    }

    #[test]
    fn ignores_unicode_line_separators_in_request_line() {
        let handler = SipHandler::new();

        assert!(
            handler
                .handle(
                    "OPTIONS sip:service@example.com\u{2028}extra SIP/2.0\r\nCall-ID: abc\r\n\r\n"
                        .as_bytes()
                )
                .is_empty()
        );
    }

    #[test]
    fn ignores_unicode_line_separators_in_handler_request_line() {
        let handler = SipHandler::new();

        assert!(
            handler
                .handle(
                    "OPTIONS sip:service@example.com\u{2028}extra SIP/2.0\r\nCall-ID: abc\r\n\r\n"
                        .as_bytes()
                )
                .is_empty()
        );
    }

    #[test]
    fn rejects_unicode_line_separators_in_header_values() {
        let handler = SipHandler::new();

        assert!(
            handler
                .handle(
                    "OPTIONS sip:service@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:service@example.com>\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\nX-Test: hello\u{2028}world\r\n\r\n"
                        .as_bytes()
                )
                .is_empty()
        );
    }

    #[test]
    fn ignores_requests_without_matching_cseq_method() {
        let handler = SipHandler::new();

        assert!(
            handler
                .handle(b"OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\n\r\n")
                .is_empty()
        );
        assert!(
            handler
                .handle(
                    b"OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq: 1 INVITE\r\n\r\n"
                )
                .is_empty()
        );
        assert!(
            handler
                .handle(
                    b"OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq: one OPTIONS\r\n\r\n"
                )
                .is_empty()
        );
        assert!(
            handler
                .handle(
                    b"OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq: +1 OPTIONS\r\n\r\n"
                )
                .is_empty()
        );
        assert!(
            handler
                .handle(
                    b"OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq: 1\tOPTIONS\r\n\r\n"
                )
                .is_empty()
        );
    }

    #[test]
    fn cseq_rejects_unicode_whitespace_separators() {
        let handler = SipHandler::new();

        let response = handler.handle(
            "OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq: 1\u{00a0}OPTIONS\r\n\r\n".as_bytes(),
        );

        assert!(response.is_empty());
    }

    #[test]
    fn cseq_rejects_compressed_ascii_spaces() {
        let handler = SipHandler::new();

        let response = handler.handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq: 1  OPTIONS\r\n\r\n",
        );

        assert!(response.is_empty());
    }

    #[test]
    fn cseq_rejects_unicode_whitespace_before_method_token() {
        let handler = SipHandler::new();

        let response = handler.handle(
            "OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq: 1\u{00a0} OPTIONS\r\n\r\n"
                .as_bytes(),
        );

        assert!(response.is_empty());
    }

    #[test]
    fn cseq_rejects_unicode_whitespace_around_value() {
        let handler = SipHandler::new();

        let response = handler.handle(
            "OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq: \u{00a0}1 OPTIONS\u{00a0}\r\n\r\n"
                .as_bytes(),
        );

        assert!(response.is_empty());
    }

    #[test]
    fn cseq_rejects_zero_sequence_number() {
        let handler = SipHandler::new();

        let response = handler.handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq: 0 OPTIONS\r\n\r\n",
        );

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_headers_with_leading_whitespace() {
        let response = SipHandler::new().handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\n CSeq: 1 OPTIONS\r\n\r\n",
        );

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_headers_with_unicode_whitespace_before_colon() {
        let response = SipHandler::new().handle(
            "OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq\u{00a0}: 1 OPTIONS\r\n\r\n"
                .as_bytes(),
        );

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_malformed_header_lines_even_with_required_headers() {
        let response = SipHandler::new().handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:service@example.com>\r\nCall-ID: abc\r\nBroken-Header\r\nCSeq: 1 OPTIONS\r\n\r\n",
        );

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_sip_request_without_header_terminator() {
        let response = SipHandler::new()
            .handle(b"OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS");

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_sip_request_with_lf_only_terminator() {
        let response = SipHandler::new()
            .handle(b"OPTIONS sip:service@example.com SIP/2.0\nCall-ID: abc\nCSeq: 1 OPTIONS\n\n");

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_sip_request_with_mixed_line_endings() {
        let response = SipHandler::new().handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\nCSeq: 1 OPTIONS\r\n\r\n",
        );

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_sip_request_with_carriage_return_only_line_endings() {
        let response = SipHandler::new().handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:service@example.com>\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\r\n\r\n",
        );

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_sip_request_with_unicode_line_separators_in_headers() {
        let response = SipHandler::new().handle(
            "OPTIONS sip:service@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\u{2028}Injected: yes\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:service@example.com>\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n".as_bytes(),
        );

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_cseq_found_only_in_body() {
        let response = SipHandler::new()
            .handle(b"OPTIONS sip:service@example.com SIP/2.0\r\n\r\nCSeq: 1 OPTIONS");

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_sip_request_with_unsatisfied_content_length() {
        let handler = SipHandler::new();

        let response = handler.handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nCSeq: 1 OPTIONS\r\nContent-Length: 4\r\n\r\nab",
        );

        assert!(response.is_empty());

        let response = handler.handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nCSeq: 1 OPTIONS\r\nContent-Length: +0\r\n\r\n",
        );

        assert!(response.is_empty());
    }

    #[test]
    fn accepts_duplicate_content_length_headers_when_they_match() {
        let response = SipHandler::new().handle(&options_request(
            "Content-Length: 0\r\nContent-Length: 0\r\n",
        ));

        assert!(String::from_utf8_lossy(&response).starts_with("SIP/2.0 200 OK"));
    }

    #[test]
    fn rejects_conflicting_duplicate_content_length_headers() {
        let response = SipHandler::new().handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\nContent-Length: 4\r\n\r\n",
        );

        assert!(response.is_empty());
    }

    #[test]
    fn sip_rejects_duplicate_unique_headers() {
        let request = b"OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCall-ID: def\r\nCSeq: 1 OPTIONS\r\n\r\n";

        assert!(SipHandler::new().handle(request).is_empty());
    }

    #[test]
    fn sip_rejects_identical_duplicate_unique_headers() {
        let request = b"OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\n\r\n";

        assert!(SipHandler::new().handle(request).is_empty());
    }

    #[test]
    fn ignores_sip_request_with_extra_body_bytes() {
        let response = SipHandler::new().handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\nEXTRA",
        );

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_sip_request_with_body_missing_content_length() {
        let response = SipHandler::new()
            .handle(b"OPTIONS sip:service@example.com SIP/2.0\r\nCSeq: 1 OPTIONS\r\n\r\nBODY");

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_sip_request_with_oversized_headers() {
        let mut request = b"OPTIONS sip:service@example.com SIP/2.0\r\n".to_vec();
        request.extend_from_slice(b"Via: ");
        request.extend(std::iter::repeat_n(b'a', MAX_SIP_HEADER_BYTES));
        request.extend_from_slice(b"\r\n\r\n");

        let response = SipHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_sip_request_with_oversized_body() {
        let mut request = format!(
            "OPTIONS sip:service@example.com SIP/2.0\r\nContent-Length: {}\r\n\r\n",
            MAX_SIP_BODY_BYTES + 1
        )
        .into_bytes();
        request.extend(std::iter::repeat_n(b'a', MAX_SIP_BODY_BYTES + 1));

        let response = SipHandler::new().handle(&request);

        assert!(response.is_empty());
    }

    #[test]
    fn rejects_duplicate_content_length_headers() {
        let handler = SipHandler::new();

        let response = handler.handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nCSeq: 1 OPTIONS\r\nContent-Length: 4\r\nContent-Length: 0\r\n\r\n",
        );

        assert!(response.is_empty());
    }

    #[test]
    fn logged_request_line_is_single_line() {
        let line = safe_log_line("OPTIONS sip:svc\x1b@example SIP/2.0\r");

        assert_eq!(line, "OPTIONS sip:svc @example SIP/2.0 ");
        assert!(!line.chars().any(char::is_control));

        let long = "a".repeat(LOG_LINE_PREVIEW_CHARS + 1);
        assert_eq!(safe_log_line(&long).len(), LOG_LINE_PREVIEW_CHARS);
    }

    #[test]
    fn response_headers_strip_non_crlf_control_bytes() {
        let response = SipHandler::new().handle(
            b"REGISTER sip:service@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\x1b[31m\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:alice@example.com>\r\nCall-ID: 12345\r\nCSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n",
        );
        let text = String::from_utf8(response).expect("response should be utf-8");

        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("Via: SIP/2.0/UDP 10.0.0.1 [31m"));
    }

    #[test]
    fn response_headers_strip_unicode_whitespace() {
        let response = SipHandler::new().handle(
            "REGISTER sip:service@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\u{2028}[31m\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:alice@example.com>\r\nCall-ID: 12345\r\nCSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n"
                .as_bytes(),
        );

        assert!(response.is_empty());
    }

    #[test]
    fn invalid_utf8_request_is_rejected() {
        let handler = SipHandler::new();
        let request = b"REGISTER sip:example.com SIP/2.0\r\nVia: SIP/2.0/UDP \xff\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:alice@example.com>\r\nCall-ID: 12345\r\nCSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n";

        assert!(handler.handle(request).is_empty());
    }
}
