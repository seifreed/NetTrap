pub struct NtpHandler;

impl NtpHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 48 {
            return Vec::new();
        }
        tracing::info!("NTP request received (mode={})", data[0] & 0x07);

        // Build NTP response (mode 4 = server)
        let mut resp = vec![0u8; 48];
        resp[0] = 0x24; // LI=0, Version=4, Mode=4 (server)
        resp[1] = 1; // Stratum 1
        resp[2] = 6; // Poll interval
        resp[3] = 0xEC_u8; // Precision (-20)

        // Reference ID: "LOCL"
        resp[12..16].copy_from_slice(b"LOCL");

        // Timestamps (use current time as NTP epoch offset)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        // NTP era 0 wraps in Feb 2036 (RFC 4330); wrapping_add makes truncation explicit
        let ntp_secs = now.as_secs().wrapping_add(2_208_988_800) as u32;
        let ts = ntp_secs.to_be_bytes();
        resp[16..20].copy_from_slice(&ts); // Reference timestamp
        resp[24..28].copy_from_slice(&data[40..44]); // Origin = client's transmit
        resp[32..36].copy_from_slice(&ts); // Receive timestamp
        resp[40..44].copy_from_slice(&ts); // Transmit timestamp
        resp
    }
}

impl Default for NtpHandler {
    fn default() -> Self {
        Self::new()
    }
}
