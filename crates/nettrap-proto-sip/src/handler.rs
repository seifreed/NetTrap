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
    fn extract_header<'a>(text: &'a str, name: &str) -> Option<&'a str> {
        let lower_name = name.to_ascii_lowercase();
        text.lines()
            .find(|l| {
                let lower = l.to_ascii_lowercase();
                lower.starts_with(&format!("{}:", lower_name))
            })
            .map(|l| l[name.len() + 1..].trim())
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(data);
        let first_line = text.lines().next().unwrap_or("");
        tracing::warn!("SIP request: {}", first_line);

        // Extract mandatory headers (case-insensitive per RFC 3261)
        let via = Self::extract_header(&text, "Via").unwrap_or("SIP/2.0/UDP 0.0.0.0");
        let from = Self::extract_header(&text, "From").unwrap_or("<sip:unknown@unknown>");
        let to = Self::extract_header(&text, "To").unwrap_or("<sip:unknown@unknown>");
        let call_id = Self::extract_header(&text, "Call-ID").unwrap_or("unknown");
        let cseq = Self::extract_header(&text, "CSeq").unwrap_or("1 UNKNOWN");

        if first_line.starts_with("REGISTER") || first_line.starts_with("INVITE") {
            format!(
                "SIP/2.0 401 Unauthorized\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {}\r\nWWW-Authenticate: Digest realm=\"{}\", nonce=\"nettrap\"\r\nContent-Length: 0\r\n\r\n",
                via, from, to, call_id, cseq, self.domain
            )
            .into_bytes()
        } else if first_line.starts_with("OPTIONS") {
            format!(
                "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {}\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER\r\nContent-Length: 0\r\n\r\n",
                via, from, to, call_id, cseq
            )
            .into_bytes()
        } else if first_line.starts_with("BYE") || first_line.starts_with("ACK") || first_line.starts_with("CANCEL") {
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
