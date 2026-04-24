pub struct NtpHandler;

impl NtpHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 48 {
            return Vec::new();
        }
        let version = (data[0] >> 3) & 0x07;
        let mode = data[0] & 0x07;
        if !(3..=4).contains(&version) || mode != 3 {
            tracing::debug!(
                "Ignoring non-client NTP packet (version={}, mode={})",
                version,
                mode
            );
            return Vec::new();
        }
        tracing::info!("NTP client request received (version={})", version);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_request_gets_server_response() {
        let mut request = vec![0u8; 48];
        request[0] = 0x23; // LI=0, version=4, mode=3
        request[40..44].copy_from_slice(&0x01020304u32.to_be_bytes());

        let response = NtpHandler::new().handle(&request);

        assert_eq!(response.len(), 48);
        assert_eq!(response[0] & 0x07, 4);
        assert_eq!(&response[24..28], &request[40..44]);
    }

    #[test]
    fn server_mode_packet_is_not_answered() {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x24; // LI=0, version=4, mode=4

        assert!(NtpHandler::new().handle(&packet).is_empty());
    }

    #[test]
    fn unsupported_version_is_not_answered() {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x03; // version=0, mode=3

        assert!(NtpHandler::new().handle(&packet).is_empty());
    }
}
