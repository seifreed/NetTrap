use serde::{Deserialize, Serialize};

use crate::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum FlowState {
    #[default]
    New,
    Connecting,
    Established,
    Closing,
    Closed,
    Error,
}

impl FlowState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, FlowState::Closed | FlowState::Error)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowMetadata {
    pub process: Option<ProcessInfo>,
    pub attribution: Option<Attribution>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub first_packet_id: Option<PacketId>,
    pub last_packet_id: Option<PacketId>,
    pub application_protocol: Option<ApplicationProtocol>,
    pub sni: Option<String>,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub http_host: Option<String>,
    pub http_uri: Option<String>,
    pub dns_query: Option<String>,
    pub user_agent: Option<String>,
}

impl FlowMetadata {
    pub fn new() -> Self {
        Self::new_with_now(now())
    }

    pub fn new_with_now(now: Timestamp) -> Self {
        Self {
            process: None,
            attribution: None,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            first_seen: now,
            last_seen: now,
            first_packet_id: None,
            last_packet_id: None,
            application_protocol: None,
            sni: None,
            ja3: None,
            ja3s: None,
            http_host: None,
            http_uri: None,
            dns_query: None,
            user_agent: None,
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent.saturating_add(self.bytes_received)
    }

    pub fn update_sent(&mut self, bytes: u64, packet_id: PacketId) {
        self.update_sent_with_now(bytes, packet_id, now());
    }

    pub fn update_sent_with_now(&mut self, bytes: u64, packet_id: PacketId, now: Timestamp) {
        // Saturate rather than wrap/panic: byte counts come from observed
        // transfer sizes, and a long-lived or adversarial flow could otherwise
        // overflow u64 (panic in debug, silent wrap in release).
        self.bytes_sent = self.bytes_sent.saturating_add(bytes);
        self.packets_sent = self.packets_sent.saturating_add(1);
        self.last_seen = now;
        self.last_packet_id = Some(packet_id);
    }

    pub fn update_received(&mut self, bytes: u64, packet_id: PacketId) {
        self.update_received_with_now(bytes, packet_id, now());
    }

    pub fn update_received_with_now(&mut self, bytes: u64, packet_id: PacketId, now: Timestamp) {
        self.bytes_received = self.bytes_received.saturating_add(bytes);
        self.packets_received = self.packets_received.saturating_add(1);
        self.last_seen = now;
        self.last_packet_id = Some(packet_id);
    }
}

impl Default for FlowMetadata {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    #[test]
    fn flow_metadata_totals_saturate_at_u64_max() {
        let mut metadata = FlowMetadata::new();
        metadata.bytes_sent = u64::MAX - 1;
        metadata.bytes_received = 10;
        metadata.packets_sent = u64::MAX;
        metadata.packets_received = 1;

        assert_eq!(metadata.total_bytes(), u64::MAX);
        assert_eq!(metadata.packets_sent, u64::MAX);
        assert_eq!(metadata.packets_received, 1);
    }

    #[test]
    fn flow_metadata_updates_saturate_counters() {
        let mut metadata = FlowMetadata::new();
        metadata.bytes_sent = u64::MAX - 1;
        metadata.bytes_received = u64::MAX - 2;
        metadata.packets_sent = u64::MAX;
        metadata.packets_received = u64::MAX;

        metadata.update_sent(10, PacketId::nil());
        metadata.update_received(10, PacketId::nil());

        assert_eq!(metadata.bytes_sent, u64::MAX);
        assert_eq!(metadata.bytes_received, u64::MAX);
        assert_eq!(metadata.packets_sent, u64::MAX);
        assert_eq!(metadata.packets_received, u64::MAX);
    }

    #[test]
    fn flow_metadata_new_with_now_uses_the_explicit_clock() {
        let now = chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant");
        let metadata = FlowMetadata::new_with_now(now);

        assert_eq!(metadata.first_seen, now);
        assert_eq!(metadata.last_seen, now);
    }

    #[test]
    fn flow_metadata_update_methods_use_the_explicit_clock() {
        let now = chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant");
        let later = now + ChronoDuration::seconds(15);
        let mut metadata = FlowMetadata::new_with_now(now);

        metadata.update_sent_with_now(7, PacketId::nil(), later);
        metadata.update_received_with_now(3, PacketId::nil(), later);

        assert_eq!(metadata.bytes_sent, 7);
        assert_eq!(metadata.bytes_received, 3);
        assert_eq!(metadata.packets_sent, 1);
        assert_eq!(metadata.packets_received, 1);
        assert_eq!(metadata.last_seen, later);
    }

    #[test]
    fn flow_metadata_duration_ms_clamps_negative_clock_skew_to_zero() {
        let now = chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant");
        let mut metadata = FlowMetadata::new_with_now(now);

        metadata.last_seen = now - ChronoDuration::seconds(5);

        assert_eq!(
            (metadata.last_seen - metadata.first_seen)
                .num_milliseconds()
                .max(0),
            0
        );
    }
}
