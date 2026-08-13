/// Time protocol handler (TCP+UDP/37, RFC 868)
///
/// Returns the current time as a 32-bit big-endian value representing
/// seconds since 1900-01-01 00:00:00 UTC.
pub struct TimeHandler {
    now: fn() -> chrono::DateTime<chrono::Utc>,
}

/// Seconds between 1900-01-01 and 1970-01-01 (Unix epoch offset).
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

impl TimeHandler {
    pub fn new() -> Self {
        Self {
            now: chrono::Utc::now,
        }
    }

    pub fn with_now(mut self, now: fn() -> chrono::DateTime<chrono::Utc>) -> Self {
        self.now = now;
        self
    }

    /// Returns 4 bytes: 32-bit big-endian seconds since 1900-01-01.
    pub fn handle(&self) -> Vec<u8> {
        self.handle_at((self.now)())
    }

    /// Render the RFC 868 timestamp for an explicit instant. FakeTime mode can
    /// pass the actual shifted clock value here so pre-epoch offsets wrap the
    /// same way as the wire protocol.
    pub fn handle_at(&self, now: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
        let secs_since_1900 = rfc868_seconds_since_1900_datetime(now);
        tracing::info!("Time response: {} seconds since 1900", secs_since_1900);
        secs_since_1900.to_be_bytes().to_vec()
    }

    #[cfg(test)]
    fn handle_system_time(&self, now: std::time::SystemTime) -> Vec<u8> {
        let secs_since_1900 = match now.duration_since(std::time::UNIX_EPOCH) {
            Ok(elapsed) => rfc868_seconds_since_1900(elapsed.as_secs() as i64),
            Err(err) => {
                let before_epoch = err.duration();
                (NTP_EPOCH_OFFSET as u32)
                    .wrapping_sub(before_epoch.as_secs() as u32)
                    .wrapping_sub(u32::from(before_epoch.subsec_nanos() != 0))
            }
        };

        tracing::info!("Time response: {} seconds since 1900", secs_since_1900);
        secs_since_1900.to_be_bytes().to_vec()
    }

    /// Render the RFC 868 timestamp for an explicit Unix time. The caller
    /// injects the clock so FakeTime mode (shifting service-facing timestamps
    /// to trigger malware time-bombs) reaches the time service, not only HTTP.
    pub fn handle_at_unix(&self, unix_secs: i64) -> Vec<u8> {
        let secs_since_1900 = rfc868_seconds_since_1900(unix_secs);
        tracing::info!("Time response: {} seconds since 1900", secs_since_1900);
        secs_since_1900.to_be_bytes().to_vec()
    }
}

fn rfc868_seconds_since_1900_datetime(now: chrono::DateTime<chrono::Utc>) -> u32 {
    rfc868_seconds_since_1900(now.timestamp())
}

fn rfc868_seconds_since_1900(unix_secs: i64) -> u32 {
    // RFC 868 time wraps at u32::MAX (~2036).
    let ntp_secs = if unix_secs >= 0 {
        unix_secs.unsigned_abs().wrapping_add(NTP_EPOCH_OFFSET)
    } else {
        NTP_EPOCH_OFFSET.wrapping_sub(unix_secs.unsigned_abs())
    };
    let bytes = ntp_secs.to_le_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

impl Default for TimeHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(0, 0).expect("valid instant")
    }

    #[test]
    fn handle_at_unix_uses_the_injected_time() {
        // 1970-01-01 -> exactly NTP_EPOCH_OFFSET seconds since 1900.
        assert_eq!(
            TimeHandler::new().handle_at_unix(0),
            (NTP_EPOCH_OFFSET as u32).to_be_bytes().to_vec()
        );
        assert_ne!(
            TimeHandler::new().handle_at_unix(1_000_000_000),
            TimeHandler::new().handle_at_unix(0)
        );
    }

    #[test]
    fn handle_uses_the_injected_clock() {
        assert_eq!(
            TimeHandler::new().with_now(fixed_now).handle(),
            (NTP_EPOCH_OFFSET as u32).to_be_bytes().to_vec()
        );
    }

    #[test]
    fn handle_uses_the_injected_datetime_before_unix_epoch() {
        let before_unix_epoch = chrono::DateTime::from_timestamp(-1, 0).expect("valid instant");

        assert_eq!(
            TimeHandler::new().handle_at(before_unix_epoch),
            (NTP_EPOCH_OFFSET.wrapping_sub(1) as u32)
                .to_be_bytes()
                .to_vec()
        );
    }

    #[test]
    fn handle_system_time_before_unix_epoch_wraps_back_into_rfc_868_range() {
        let handler = TimeHandler::new();
        let one_second_before_unix = std::time::UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(1))
            .expect("time before unix epoch should be representable");

        assert_eq!(
            handler.handle_system_time(one_second_before_unix),
            (NTP_EPOCH_OFFSET.wrapping_sub(1) as u32)
                .to_be_bytes()
                .to_vec()
        );
    }

    #[test]
    fn handle_system_time_before_unix_epoch_with_fraction_borrows_one_second() {
        let handler = TimeHandler::new();
        let before_unix_epoch = std::time::UNIX_EPOCH
            .checked_sub(std::time::Duration::from_micros(1))
            .expect("time before unix epoch should be representable");

        assert_eq!(
            handler.handle_system_time(before_unix_epoch),
            (NTP_EPOCH_OFFSET.wrapping_sub(1) as u32)
                .to_be_bytes()
                .to_vec()
        );
    }

    #[test]
    fn handle_at_unix_accepts_large_wrapping_timestamps_without_panicking() {
        let handler = TimeHandler::new();

        let result = std::panic::catch_unwind(|| handler.handle_at_unix(i64::MAX));

        assert!(result.is_ok());
        assert_eq!(
            result.expect("handle_at_unix should not panic"),
            rfc868_seconds_since_1900(i64::MAX).to_be_bytes().to_vec()
        );
    }

    #[test]
    fn handle_at_unix_handles_i64_min_without_panicking() {
        let handler = TimeHandler::new();

        let result = std::panic::catch_unwind(|| handler.handle_at_unix(i64::MIN));

        assert!(result.is_ok());
        assert_eq!(
            result.expect("handle_at_unix should not panic"),
            rfc868_seconds_since_1900(i64::MIN).to_be_bytes().to_vec()
        );
    }
}
