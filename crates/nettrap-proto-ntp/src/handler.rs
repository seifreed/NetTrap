pub struct NtpHandler {
    now: fn() -> chrono::DateTime<chrono::Utc>,
}

const NTP_UNIX_EPOCH_OFFSET: u64 = 2_208_988_800;

impl NtpHandler {
    pub fn new() -> Self {
        Self {
            now: chrono::Utc::now,
        }
    }

    /// Inject the clock used for the NTP server timestamp so FakeTime mode
    /// can affect the response payload.
    pub fn with_now(mut self, now: fn() -> chrono::DateTime<chrono::Utc>) -> Self {
        self.now = now;
        self
    }

    pub fn handle(&self, data: &[u8]) -> Vec<u8> {
        if data.len() < 48 || !data.len().is_multiple_of(4) {
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

        // Build NTP response (mode 4 = server). Echo the client's version
        // (RFC 5905 §7.3: the server copies VN from the request) instead of
        // hardcoding v4, so v3 clients accept the reply and the agent does not
        // advertise a version the client never used.
        let mut resp = vec![0u8; 48];
        resp[0] = (version << 3) | 0x04; // LI=0, Version=<echoed>, Mode=4 (server)
        resp[1] = 1; // Stratum 1
        resp[2] = 6; // Poll interval
        resp[3] = 0xEC_u8; // Precision (-20)

        resp[12..16].copy_from_slice(b"LOCL");

        let ts = current_ntp_timestamp_at((self.now)());
        resp[16..24].copy_from_slice(&ts); // Reference timestamp
        resp[24..32].copy_from_slice(&data[40..48]); // Origin = client's transmit
        resp[32..40].copy_from_slice(&ts); // Receive timestamp
        resp[40..48].copy_from_slice(&ts); // Transmit timestamp
        resp
    }
}

fn current_ntp_timestamp_at(now: chrono::DateTime<chrono::Utc>) -> [u8; 8] {
    let unix_secs = now.timestamp();
    let nanos = now.timestamp_subsec_nanos();
    let ntp_secs = if unix_secs >= 0 {
        unix_secs.unsigned_abs().wrapping_add(NTP_UNIX_EPOCH_OFFSET)
    } else {
        NTP_UNIX_EPOCH_OFFSET.wrapping_sub(unix_secs.unsigned_abs())
    };
    let seconds_bytes = ntp_secs.to_le_bytes();
    let seconds = u32::from_le_bytes([
        seconds_bytes[0],
        seconds_bytes[1],
        seconds_bytes[2],
        seconds_bytes[3],
    ]);
    let fraction_raw = (u128::from(nanos) << 32) / 1_000_000_000u128;
    let fraction_bytes = fraction_raw.to_be_bytes();
    let fraction = u32::from_be_bytes([
        fraction_bytes[12],
        fraction_bytes[13],
        fraction_bytes[14],
        fraction_bytes[15],
    ]);

    let mut timestamp = [0u8; 8];
    timestamp[..4].copy_from_slice(&seconds.to_be_bytes());
    timestamp[4..].copy_from_slice(&fraction.to_be_bytes());
    timestamp
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
        request[40..48].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let response = NtpHandler::new().handle(&request);

        assert_eq!(response.len(), 48);
        assert_eq!(response[0] & 0x07, 4); // mode 4 (server)
        assert_eq!((response[0] >> 3) & 0x07, 4); // version echoed (v4)
        assert_eq!(&response[24..32], &request[40..48]);
        assert_ne!(&response[16..24], &[0; 8]);
        assert_eq!(&response[32..40], &response[40..48]);
    }

    #[test]
    fn response_uses_injected_ntp_timestamp() {
        fn fixed_now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant")
        }

        let mut request = vec![0u8; 48];
        request[0] = 0x23; // LI=0, version=4, mode=3
        request[40..48].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let response = NtpHandler::new().with_now(fixed_now).handle(&request);

        assert_eq!(
            &response[16..24],
            &[0xE9, 0x3C, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(&response[32..40], &response[40..48]);
    }

    #[test]
    fn response_echoes_request_ntp_version() {
        // RFC 5905: the server copies the request version into the reply.
        for version in [3u8, 4u8] {
            let mut request = vec![0u8; 48];
            request[0] = (version << 3) | 0x03; // LI=0, version, mode=3 (client)

            let response = NtpHandler::new().handle(&request);

            assert_eq!(response.len(), 48);
            assert_eq!(
                (response[0] >> 3) & 0x07,
                version,
                "response must echo request version {version}"
            );
            assert_eq!(response[0] & 0x07, 4, "response mode must be 4 (server)");
        }
    }

    #[test]
    fn timestamp_includes_fractional_seconds() {
        let timestamp = current_ntp_timestamp_at(
            chrono::DateTime::from_timestamp(0, 500_000_000).expect("valid instant"),
        );

        assert_eq!(
            &timestamp[..4],
            &(NTP_UNIX_EPOCH_OFFSET as u32).to_be_bytes()
        );
        assert_eq!(&timestamp[4..], &0x8000_0000u32.to_be_bytes());
    }

    #[test]
    fn current_ntp_timestamp_before_unix_epoch_wraps_back_into_rfc_range() {
        let one_second_before_unix = chrono::DateTime::from_timestamp(-1, 0)
            .expect("pre-epoch time should be representable");

        assert_eq!(
            &current_ntp_timestamp_at(one_second_before_unix)[..4],
            &(NTP_UNIX_EPOCH_OFFSET.wrapping_sub(1) as u32).to_be_bytes()
        );
    }

    #[test]
    fn current_ntp_timestamp_before_unix_epoch_preserves_fractional_seconds() {
        let half_second_before_unix = chrono::DateTime::from_timestamp(-1, 500_000_000)
            .expect("pre-epoch time should be representable");

        assert_eq!(
            &current_ntp_timestamp_at(half_second_before_unix)[..4],
            &(NTP_UNIX_EPOCH_OFFSET.wrapping_sub(1) as u32).to_be_bytes()
        );
        assert_eq!(
            &current_ntp_timestamp_at(half_second_before_unix)[4..],
            &0x8000_0000u32.to_be_bytes()
        );
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

    #[test]
    fn malformed_packet_length_is_not_answered() {
        let mut packet = vec![0u8; 47];
        packet[0] = 0x23; // LI=0, version=4, mode=3

        assert!(NtpHandler::new().handle(&packet).is_empty());

        let mut unaligned = vec![0u8; 49];
        unaligned[0] = 0x23; // LI=0, version=4, mode=3

        assert!(NtpHandler::new().handle(&unaligned).is_empty());

        let mut unsupported = vec![0u8; 48];
        unsupported[0] = 0x24; // LI=0, version=4, mode=4

        assert!(NtpHandler::new().handle(&unsupported).is_empty());
    }

    #[test]
    fn extension_fields_do_not_prevent_server_response() {
        let mut packet = vec![0u8; 60];
        packet[0] = 0x23; // LI=0, version=4, mode=3
        packet[40..48].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let response = NtpHandler::new().handle(&packet);

        assert_eq!(response.len(), 48);
        assert_eq!(&response[24..32], &packet[40..48]);
    }
}
