use crate::prelude::*;

#[derive(Debug, Default)]
pub struct FlowStateConfig {
    pub tcp_timeout: std::time::Duration,
    pub udp_timeout: std::time::Duration,
    pub icmp_timeout: std::time::Duration,
}

impl FlowStateConfig {
    pub fn new() -> Self {
        Self {
            tcp_timeout: std::time::Duration::from_secs(3600),
            udp_timeout: std::time::Duration::from_secs(60),
            icmp_timeout: std::time::Duration::from_secs(30),
        }
    }

    pub fn tcp_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.tcp_timeout = timeout;
        self
    }

    pub fn udp_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.udp_timeout = timeout;
        self
    }

    pub fn icmp_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.icmp_timeout = timeout;
        self
    }

    pub fn timeout_for_protocol(&self, protocol: Protocol) -> std::time::Duration {
        match protocol {
            Protocol::Tcp => self.tcp_timeout,
            Protocol::Udp => self.udp_timeout,
            Protocol::Icmp => self.icmp_timeout,
            Protocol::Igmp => self.icmp_timeout,
            Protocol::Unknown(_) => self.udp_timeout,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowLifeCycle {
    Active,
    Idle,
    Expired,
    Closed,
}

impl FlowLifeCycle {
    pub fn is_expired(&self) -> bool {
        matches!(self, FlowLifeCycle::Expired | FlowLifeCycle::Closed)
    }

    pub fn is_active(&self) -> bool {
        matches!(self, FlowLifeCycle::Active)
    }
}

pub struct FlowStateMachine {
    config: FlowStateConfig,
}

impl FlowStateMachine {
    pub fn new(config: FlowStateConfig) -> Self {
        Self { config }
    }

    pub fn get_timeout(&self, flow: &Flow) -> std::time::Duration {
        self.config.timeout_for_protocol(flow.five_tuple.protocol)
    }

    pub fn check_lifecycle(&self, flow: &Flow) -> FlowLifeCycle {
        if flow.state.is_terminal() {
            return FlowLifeCycle::Closed;
        }

        let timeout = self.get_timeout(flow);
        let elapsed = flow.duration();

        if elapsed > timeout {
            FlowLifeCycle::Expired
        } else if flow.metadata.last_seen == flow.metadata.first_seen {
            FlowLifeCycle::Idle
        } else {
            FlowLifeCycle::Active
        }
    }

    pub fn transition_tcp(&self, flow: &Flow, packet: &Packet) -> Option<TcpState> {
        if let Some(flags) = packet.tcp_flags {
            let current = flow.tcp_state.unwrap_or(TcpState::Closed);

            let next_state = match (current, flags) {
                (TcpState::Closed, f)
                    if f.contains(TcpFlags::SYN) && !f.contains(TcpFlags::ACK) =>
                {
                    TcpState::SynSent
                }
                (TcpState::SynSent, f)
                    if f.contains(TcpFlags::SYN) && f.contains(TcpFlags::ACK) =>
                {
                    TcpState::SynReceived
                }
                (TcpState::SynReceived, f) if f.contains(TcpFlags::ACK) => TcpState::Established,
                (TcpState::Established, f) if f.contains(TcpFlags::FIN) => TcpState::FinWait1,
                (TcpState::FinWait1, f) if f.contains(TcpFlags::FIN) => TcpState::Closing,
                (TcpState::Closing, f) if f.contains(TcpFlags::ACK) => TcpState::TimeWait,
                (_, f) if f.contains(TcpFlags::RST) => TcpState::Closed,
                _ => return None,
            };

            Some(next_state)
        } else {
            None
        }
    }
}

impl Default for FlowStateMachine {
    fn default() -> Self {
        Self::new(FlowStateConfig::new())
    }
}
