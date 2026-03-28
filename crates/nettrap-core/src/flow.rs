use serde::{Deserialize, Serialize};

use crate::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derive(Default)]
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
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            FlowState::New | FlowState::Connecting | FlowState::Established
        )
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, FlowState::Closed | FlowState::Error)
    }

    pub fn can_send(&self) -> bool {
        matches!(self, FlowState::Established | FlowState::Closing)
    }

    pub fn can_receive(&self) -> bool {
        matches!(self, FlowState::Established | FlowState::Closing)
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
        let now = now();
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

    pub fn with_process(mut self, process: ProcessInfo) -> Self {
        self.process = Some(process);
        self
    }

    pub fn with_attribution(mut self, attr: Attribution) -> Self {
        self.process = Some(attr.process.clone());
        self.attribution = Some(attr);
        self
    }

    pub fn has_attribution(&self) -> bool {
        self.attribution.is_some()
    }

    pub fn attribution_confidence(&self) -> AttributionConfidence {
        self.attribution
            .as_ref()
            .map(|a| a.confidence)
            .unwrap_or(AttributionConfidence::None)
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }

    pub fn total_packets(&self) -> u64 {
        self.packets_sent + self.packets_received
    }

    pub fn duration_ms(&self) -> i64 {
        (self.last_seen - self.first_seen).num_milliseconds()
    }

    pub fn update_sent(&mut self, bytes: u64, packet_id: PacketId) {
        self.bytes_sent += bytes;
        self.packets_sent += 1;
        self.last_seen = now();
        self.last_packet_id = Some(packet_id);
    }

    pub fn update_received(&mut self, bytes: u64, packet_id: PacketId) {
        self.bytes_received += bytes;
        self.packets_received += 1;
        self.last_seen = now();
        self.last_packet_id = Some(packet_id);
    }
}

impl Default for FlowMetadata {
    fn default() -> Self {
        Self::new()
    }
}
