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
        value.replace('\r', "").replace('\n', "")
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(data);
        let first_line = text.lines().next().unwrap_or("");
        tracing::warn!("SIP request: {}", first_line);

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
        let cseq =
            Self::sanitize_header_value(Self::extract_header(&text, "CSeq").unwrap_or("1 UNKNOWN"));

        if first_line.starts_with("REGISTER ") || first_line.starts_with("INVITE ") {
            format!(
                "SIP/2.0 401 Unauthorized\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {}\r\nWWW-Authenticate: Digest realm=\"{}\", nonce=\"nettrap\"\r\nContent-Length: 0\r\n\r\n",
                via, from, to, call_id, cseq, self.domain
            )
            .into_bytes()
        } else if first_line.starts_with("OPTIONS ") {
            format!(
                "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {}\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER\r\nContent-Length: 0\r\n\r\n",
                via, from, to, call_id, cseq
            )
            .into_bytes()
        } else if first_line.starts_with("BYE ")
            || first_line.starts_with("ACK ")
            || first_line.starts_with("CANCEL ")
        {
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
}

impl Default for SipHandler {
    fn default() -> Self {
        Self::new()
    }
}
