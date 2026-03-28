use std::time::Instant;

pub type Timestamp = chrono::DateTime<chrono::Utc>;

pub fn now() -> Timestamp {
    chrono::Utc::now()
}

pub fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn unix_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn unix_timestamp_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[derive(Debug, Clone, Copy)]
pub struct MonotonicTimestamp {
    instant: Instant,
}

impl MonotonicTimestamp {
    pub fn now() -> Self {
        Self {
            instant: Instant::now(),
        }
    }

    pub fn elapsed(&self) -> std::time::Duration {
        self.instant.elapsed()
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.instant.elapsed().as_millis() as u64
    }
}
