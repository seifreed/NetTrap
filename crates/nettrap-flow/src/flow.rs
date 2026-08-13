use serde::{Deserialize, Serialize};

use crate::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowDirection {
    Outbound,
    Inbound,
    Internal,
    Unknown,
}

impl std::fmt::Display for FlowDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowDirection::Outbound => write!(f, "outbound"),
            FlowDirection::Inbound => write!(f, "inbound"),
            FlowDirection::Internal => write!(f, "internal"),
            FlowDirection::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub id: FlowId,
    pub five_tuple: FiveTuple,
    pub state: FlowState,
    pub metadata: FlowMetadata,
    pub direction: FlowDirection,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub tcp_state: Option<TcpState>,
}

impl Flow {
    pub fn new(five_tuple: FiveTuple) -> Self {
        Self::new_with_now(five_tuple, now())
    }

    pub fn new_with_now(five_tuple: FiveTuple, now: Timestamp) -> Self {
        Self {
            id: FlowId::new_v4(),
            five_tuple,
            state: FlowState::New,
            metadata: FlowMetadata::new_with_now(now),
            direction: FlowDirection::Unknown,
            created_at: now,
            updated_at: now,
            tcp_state: None,
        }
    }

    pub fn with_process(mut self, process: ProcessInfo) -> Self {
        self.metadata.process = Some(process);
        self
    }

    pub fn key(&self) -> FlowKey {
        FlowKey::from_five_tuple(&self.five_tuple)
    }

    pub fn update_state_with_now(&mut self, new_state: FlowState, now: Timestamp) {
        self.state = new_state;
        self.updated_at = now;
    }

    pub fn update_sent(&mut self, bytes: u64, packet_id: PacketId) {
        self.update_sent_with_now(bytes, packet_id, now());
    }

    pub fn update_sent_with_now(&mut self, bytes: u64, packet_id: PacketId, now: Timestamp) {
        self.metadata.update_sent_with_now(bytes, packet_id, now);
        self.updated_at = now;
    }

    pub fn update_received(&mut self, bytes: u64, packet_id: PacketId) {
        self.update_received_with_now(bytes, packet_id, now());
    }

    pub fn update_received_with_now(&mut self, bytes: u64, packet_id: PacketId, now: Timestamp) {
        self.metadata
            .update_received_with_now(bytes, packet_id, now);
        self.updated_at = now;
    }

    pub fn duration_ms(&self) -> i64 {
        (self.updated_at - self.created_at)
            .num_milliseconds()
            .max(0)
    }
}

/// Wall-clock elapsed time between `now` and an earlier `past` timestamp.
///
/// When the clock has stepped backward so that `past` is *after* `now`, the
/// naive `(now - past).to_std().unwrap_or_default()` yields zero, which makes
/// expiry checks treat the entry as perpetually fresh. For eviction purposes a
/// future timestamp is implausible, so return [`Duration::MAX`] to force the
/// caller's `elapsed > timeout` check to succeed and reap the stale entry.
pub fn elapsed_since(now: Timestamp, past: Timestamp) -> std::time::Duration {
    (now - past).to_std().unwrap_or(std::time::Duration::MAX)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl TcpState {
    /// Transition when a FIN is received from the peer (passive close).
    pub fn peer_fin_received(&self) -> TcpState {
        match self {
            TcpState::Established => TcpState::CloseWait,
            TcpState::FinWait1 => TcpState::Closing,
            TcpState::FinWait2 => TcpState::TimeWait,
            _ => *self,
        }
    }
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpState::Closed => write!(f, "CLOSED"),
            TcpState::Listen => write!(f, "LISTEN"),
            TcpState::SynSent => write!(f, "SYN_SENT"),
            TcpState::SynReceived => write!(f, "SYN_RECEIVED"),
            TcpState::Established => write!(f, "ESTABLISHED"),
            TcpState::FinWait1 => write!(f, "FIN_WAIT_1"),
            TcpState::FinWait2 => write!(f, "FIN_WAIT_2"),
            TcpState::CloseWait => write!(f, "CLOSE_WAIT"),
            TcpState::Closing => write!(f, "CLOSING"),
            TcpState::LastAck => write!(f, "LAST_ACK"),
            TcpState::TimeWait => write!(f, "TIME_WAIT"),
        }
    }
}

#[cfg(test)]
mod elapsed_since_tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use std::time::Duration;

    fn fixed_now() -> Timestamp {
        chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant")
    }

    #[test]
    fn forward_elapsed_is_measured_normally() {
        let now = Utc::now();
        let past = now - ChronoDuration::seconds(30);
        let elapsed = elapsed_since(now, past);
        assert!(elapsed >= Duration::from_secs(29) && elapsed <= Duration::from_secs(31));
    }

    #[test]
    fn zero_elapsed_for_equal_timestamps() {
        let now = Utc::now();
        assert_eq!(elapsed_since(now, now), Duration::ZERO);
    }

    #[test]
    fn backward_clock_step_reports_max_so_flow_expires() {
        // updated_at is in the FUTURE relative to now (clock stepped backward).
        // A naive (now - past).to_std().unwrap_or_default() would yield ZERO,
        // pinning the flow in the map forever. We must report a huge age so the
        // `elapsed > timeout` eviction check reaps it.
        let now = Utc::now();
        let future = now + ChronoDuration::seconds(3600);
        assert_eq!(elapsed_since(now, future), Duration::MAX);
    }

    #[test]
    fn flow_update_methods_use_the_explicit_clock() {
        let five_tuple = FiveTuple::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            53000,
            443,
            Protocol::Tcp,
        );
        let now = fixed_now();
        let mut flow = Flow::new_with_now(five_tuple, now);

        assert_eq!(flow.created_at, now);
        assert_eq!(flow.updated_at, now);
        assert_eq!(flow.metadata.first_seen, now);
        assert_eq!(flow.metadata.last_seen, now);

        let later = now + ChronoDuration::seconds(30);
        flow.update_state_with_now(FlowState::Established, later);
        flow.update_sent_with_now(12, PacketId::nil(), later);
        flow.update_received_with_now(8, PacketId::nil(), later);

        assert_eq!(flow.state, FlowState::Established);
        assert_eq!(flow.updated_at, later);
        assert_eq!(flow.metadata.last_seen, later);
        assert_eq!(flow.metadata.bytes_sent, 12);
        assert_eq!(flow.metadata.bytes_received, 8);
    }
}
