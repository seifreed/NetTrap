/// Time protocol handler (TCP+UDP/37, RFC 868)
///
/// Returns the current time as a 32-bit big-endian value representing
/// seconds since 1900-01-01 00:00:00 UTC.
pub struct TimeHandler;

/// Seconds between 1900-01-01 and 1970-01-01 (Unix epoch offset).
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

impl TimeHandler {
    pub fn new() -> Self {
        Self
    }

    /// Returns 4 bytes: 32-bit big-endian seconds since 1900-01-01.
    pub fn handle(&self) -> Vec<u8> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        // RFC 868 time wraps at u32::MAX (~2036); wrapping_add makes truncation explicit
        let secs_since_1900 = now.as_secs().wrapping_add(NTP_EPOCH_OFFSET) as u32;
        tracing::info!("Time response: {} seconds since 1900", secs_since_1900);
        secs_since_1900.to_be_bytes().to_vec()
    }
}

impl Default for TimeHandler {
    fn default() -> Self {
        Self::new()
    }
}
