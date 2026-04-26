pub struct SipHandler {
    domain: String,
}

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
                let trimmed = l.trim_start().to_ascii_lowercase();
                trimmed.starts_with(&lower_name)
                    && trimmed[lower_name.len()..].trim_start().starts_with(':')
            })
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim())
    }

    /// Sanitize a SIP header value to prevent header injection via CRLF
    fn sanitize_header_value(value: &str) -> String {
        value.replace(['\r', '\n'], "")
    }

    fn request_method(first_line: &str) -> Option<&str> {
        let mut parts = first_line.split(' ');
        let method = parts.next()?;
        let target = parts.next()?;
        let version = parts.next()?;
        if method.is_empty()
            || target.is_empty()
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
        let mut parts = cseq.split_whitespace();
        let Some(sequence) = parts.next() else {
            return false;
        };
        let Some(cseq_method) = parts.next() else {
            return false;
        };
        parts.next().is_none()
            && sequence.parse::<u32>().is_ok()
            && cseq_method.eq_ignore_ascii_case(method)
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(data);
        let first_line = text.lines().next().unwrap_or("");
        tracing::warn!("SIP packet: {}", first_line);

        let Some(method) = Self::request_method(first_line) else {
            return Vec::new();
        };

        // Extract mandatory headers (case-insensitive per RFC 3261)
        // Sanitize to prevent header injection via CRLF in attacker-controlled values
        let via = Self::sanitize_header_value(
            Self::extract_header(&text, "Via").unwrap_or("SIP/2.0/UDP 0.0.0.0"),
        );
        let from = Self::sanitize_header_value(
            Self::extract_header(&text, "From").unwrap_or("<sip:unknown@unknown>"),
        );
        let to = Self::sanitize_header_value(
            Self::extract_header(&text, "To").unwrap_or("<sip:unknown@unknown>"),
        );
        let call_id = Self::sanitize_header_value(
            Self::extract_header(&text, "Call-ID").unwrap_or("unknown"),
        );
        let Some(cseq_raw) = Self::extract_header(&text, "CSeq") else {
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
            Vec::new()
        }
    }
}

impl Default for SipHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responds_to_known_sip_request() {
        let response = SipHandler::new().handle(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\n\r\n",
        );

        assert!(String::from_utf8_lossy(&response).starts_with("SIP/2.0 200 OK"));
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
        let response = SipHandler::new()
            .handle(b"MESSAGE sip:service@example.com SIP/2.0\r\nCall-ID: abc\r\n\r\n");

        assert!(response.is_empty());
    }

    #[test]
    fn ignores_malformed_sip_request_lines() {
        let handler = SipHandler::new();

        assert!(
            handler
                .handle(b"OPTIONS sip:service@example.com SIP/2.0 extra\r\n\r\n")
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
    }
}
