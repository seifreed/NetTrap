/// Daytime protocol handler (TCP+UDP/13, RFC 867)
///
/// Returns the current date and time as a human-readable string.
pub struct DaytimeHandler;

impl DaytimeHandler {
    pub fn new() -> Self {
        Self
    }

    /// Returns the current date/time as an ASCII string (RFC 867 format).
    pub fn handle(&self) -> String {
        let now = chrono::Utc::now();
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
