pub struct SipHandler {
    domain: String,
}

impl SipHandler {
    pub fn new() -> Self {
        Self {
            domain: "nettrap.local".to_string(),
        }
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        let text = String::from_utf8_lossy(data);
        let first_line = text.lines().next().unwrap_or("");
        tracing::warn!("SIP request: {}", first_line);

        if first_line.starts_with("REGISTER") || first_line.starts_with("INVITE") {
            format!(
                "SIP/2.0 401 Unauthorized\r\nVia: {}\r\nWWW-Authenticate: Digest realm=\"{}\", nonce=\"nettrap\"\r\nContent-Length: 0\r\n\r\n",
                text.lines()
                    .find(|l| l.starts_with("Via:"))
                    .unwrap_or("Via: SIP/2.0/UDP 0.0.0.0"),
                self.domain
            )
            .into_bytes()
        } else if first_line.starts_with("OPTIONS") {
            "SIP/2.0 200 OK\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE, REGISTER\r\nContent-Length: 0\r\n\r\n"
                .as_bytes()
                .to_vec()
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
