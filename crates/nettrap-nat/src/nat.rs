use nettrap_core::prelude::*;

use crate::types::Timestamp;

#[derive(Debug, Clone)]
pub struct NatEntry {
    pub original: FiveTuple,
    pub translated: FiveTuple,
    pub created_at: Timestamp,
    pub last_used: Timestamp,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl NatEntry {
    pub fn new(original: FiveTuple, translated: FiveTuple) -> Self {
        let now = crate::types::now();
        Self {
            original,
            translated,
            created_at: now,
            last_used: now,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    pub fn update_sent(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.last_used = crate::types::now();
    }

    pub fn update_received(&mut self, bytes: u64) {
        self.bytes_received += bytes;
        self.last_used = crate::types::now();
    }
}
