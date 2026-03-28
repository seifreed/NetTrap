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
        let now = now();
        Self {
            id: FlowId::new_v4(),
            five_tuple,
            state: FlowState::New,
            metadata: FlowMetadata::new(),
            direction: FlowDirection::Unknown,
            created_at: now,
            updated_at: now,
            tcp_state: None,
        }
    }

    pub fn with_direction(mut self, direction: FlowDirection) -> Self {
        self.direction = direction;
        self
    }

    pub fn with_process(mut self, process: ProcessInfo) -> Self {
        self.metadata.process = Some(process);
        self
    }

    pub fn with_attribution(mut self, attr: Attribution) -> Self {
        self.metadata.attribution = Some(attr);
        self
    }

    pub fn src(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.five_tuple.src_ip, self.five_tuple.src_port)
    }

    pub fn dst(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.five_tuple.dst_ip, self.five_tuple.dst_port)
    }

    pub fn is_tcp(&self) -> bool {
        self.five_tuple.protocol == Protocol::Tcp
    }

    pub fn is_udp(&self) -> bool {
        self.five_tuple.protocol == Protocol::Udp
    }

    pub fn key(&self) -> FlowKey {
        FlowKey::from_five_tuple(&self.five_tuple)
    }

    pub fn reverse_key(&self) -> FlowKey {
        FlowKey::from_five_tuple(&self.five_tuple.reverse())
    }

    pub fn update_state(&mut self, new_state: FlowState) {
        self.state = new_state;
        self.updated_at = now();
    }

    pub fn update_sent(&mut self, bytes: u64, packet_id: PacketId) {
        self.metadata.update_sent(bytes, packet_id);
        self.updated_at = self.metadata.last_seen;
    }

    pub fn update_received(&mut self, bytes: u64, packet_id: PacketId) {
        self.metadata.update_received(bytes, packet_id);
        self.updated_at = self.metadata.last_seen;
    }

    pub fn duration(&self) -> std::time::Duration {
        (self.updated_at - self.created_at)
            .to_std()
            .unwrap_or_default()
    }

    pub fn duration_ms(&self) -> i64 {
        (self.updated_at - self.created_at).num_milliseconds()
    }
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
    pub fn from_flags(flags: TcpFlags) -> Option<Self> {
        if flags.contains(TcpFlags::SYN) && !flags.contains(TcpFlags::ACK) {
            Some(TcpState::SynSent)
        } else if flags.contains(TcpFlags::SYN) && flags.contains(TcpFlags::ACK) {
            Some(TcpState::SynReceived)
        } else if flags.contains(TcpFlags::FIN) && !flags.contains(TcpFlags::ACK) {
            Some(TcpState::FinWait1)
        } else if flags.contains(TcpFlags::FIN) && flags.contains(TcpFlags::ACK) {
            Some(TcpState::Closing)
        } else if flags.contains(TcpFlags::ACK) {
            Some(TcpState::Established)
        } else if flags.contains(TcpFlags::RST) {
            Some(TcpState::Closed)
        } else {
            None
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
