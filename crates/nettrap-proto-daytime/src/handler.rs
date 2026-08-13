/// Daytime protocol handler (TCP+UDP/13, RFC 867)
///
/// Returns the current date and time as a human-readable string.
pub struct DaytimeHandler {
    now: fn() -> chrono::DateTime<chrono::Utc>,
}

impl DaytimeHandler {
    pub fn new() -> Self {
        Self {
            now: chrono::Utc::now,
        }
    }

    pub fn with_now(mut self, now: fn() -> chrono::DateTime<chrono::Utc>) -> Self {
        self.now = now;
        self
    }

    /// Returns the current date/time as an ASCII string (RFC 867 format).
    pub fn handle(&self) -> String {
        self.handle_at((self.now)())
    }

    /// Render the RFC 867 string for an explicit instant. The caller injects
    /// the clock so FakeTime mode (which shifts service-facing timestamps to
    /// trigger malware time-bombs) reaches the daytime service, not only HTTP.
    pub fn handle_at(&self, now: chrono::DateTime<chrono::Utc>) -> String {
        let response = now.format("%A, %B %d, %Y %H:%M:%S-UTC\r\n").to_string();
        tracing::info!("Daytime response: {}", response.trim());
        response
    }
}

impl Default for DaytimeHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(2_085_000_000, 0).expect("valid instant")
    }

    #[test]
    fn handle_at_renders_the_injected_instant() {
        let out = DaytimeHandler::new().handle_at(fixed_now());
        assert!(out.contains("2036"), "expected injected year in {out:?}");
        assert!(out.ends_with("-UTC\r\n"));
    }

    #[test]
    fn handle_uses_the_injected_clock() {
        let out = DaytimeHandler::new().with_now(fixed_now).handle();

        assert!(out.contains("2036"));
        assert!(out.ends_with("-UTC\r\n"));
    }
}
