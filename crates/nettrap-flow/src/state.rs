use crate::prelude::*;

#[derive(Debug)]
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

impl Default for FlowStateConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowLifeCycle {
    Active,
    Idle,
    Expired,
    Closed,
}

pub struct FlowStateMachine {
    config: FlowStateConfig,
}

impl FlowStateMachine {
    pub fn new(config: FlowStateConfig) -> Self {
        Self { config }
    }

    pub fn check_lifecycle(&self, flow: &Flow) -> FlowLifeCycle {
        if flow.state.is_terminal() {
            return FlowLifeCycle::Closed;
        }

        let timeout = self.config.timeout_for_protocol(flow.five_tuple.protocol);
        let elapsed = crate::flow::elapsed_since(chrono::Utc::now(), flow.updated_at);

        if elapsed >= timeout {
            FlowLifeCycle::Expired
        } else if flow.metadata.last_seen == flow.metadata.first_seen
            && flow.metadata.total_bytes() == 0
        {
            FlowLifeCycle::Idle
        } else {
            FlowLifeCycle::Active
        }
    }

    pub fn transition_tcp(&self, flow: &Flow, packet: &Packet) -> Option<TcpState> {
        if let Some(flags) = packet.tcp_flags {
            let current = flow.tcp_state.unwrap_or(TcpState::Closed);

            let next_state = match (current, flags) {
                (_, f) if f.contains(TcpFlags::RST) => TcpState::Closed,
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
                (TcpState::Established, f) if f.contains(TcpFlags::FIN) => {
                    if packet.direction.is_inbound() {
                        current.peer_fin_received()
                    } else {
                        TcpState::FinWait1
                    }
                }
                // RFC 793: FinWait1 → FinWait2 when receiving ACK (without FIN)
                (TcpState::FinWait1, f)
                    if f.contains(TcpFlags::ACK) && !f.contains(TcpFlags::FIN) =>
                {
                    TcpState::FinWait2
                }
                (TcpState::FinWait1, f) if f.contains(TcpFlags::FIN) => TcpState::Closing,
                (TcpState::FinWait2, f) if f.contains(TcpFlags::FIN) => TcpState::TimeWait,
                (TcpState::CloseWait, f) if f.contains(TcpFlags::FIN) => TcpState::LastAck,
                (TcpState::Closing, f) if f.contains(TcpFlags::ACK) => TcpState::TimeWait,
                (TcpState::LastAck, f) if f.contains(TcpFlags::ACK) => TcpState::Closed,
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

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use super::*;

    fn established_flow() -> Flow {
        let mut flow = Flow::new(FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            53000,
            443,
            Protocol::Tcp,
        ));
        flow.tcp_state = Some(TcpState::Established);
        flow
    }

    fn tcp_packet(direction: PacketDirection, flags: TcpFlags) -> Packet {
        Packet::new(
            FiveTuple::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
                53000,
                443,
                Protocol::Tcp,
            ),
            direction,
            Bytes::new(),
        )
        .with_tcp_flags(flags)
    }

    #[test]
    fn inbound_fin_transitions_established_to_close_wait() {
        let machine = FlowStateMachine::default();
        let flow = established_flow();
        let packet = tcp_packet(PacketDirection::Inbound, TcpFlags::FIN | TcpFlags::ACK);

        let next_state = machine.transition_tcp(&flow, &packet);

        assert_eq!(next_state, Some(TcpState::CloseWait));
    }

    #[test]
    fn outbound_fin_transitions_established_to_fin_wait_1() {
        let machine = FlowStateMachine::default();
        let flow = established_flow();
        let packet = tcp_packet(PacketDirection::Outbound, TcpFlags::FIN | TcpFlags::ACK);

        let next_state = machine.transition_tcp(&flow, &packet);

        assert_eq!(next_state, Some(TcpState::FinWait1));
    }

    #[test]
    fn unknown_direction_keeps_conservative_active_close_behavior() {
        let machine = FlowStateMachine::default();
        let flow = established_flow();
        let packet = tcp_packet(PacketDirection::Unknown, TcpFlags::FIN);

        let next_state = machine.transition_tcp(&flow, &packet);

        assert_eq!(next_state, Some(TcpState::FinWait1));
    }

    #[test]
    fn outbound_fin_transitions_close_wait_to_last_ack() {
        let machine = FlowStateMachine::default();
        let mut flow = established_flow();
        flow.tcp_state = Some(TcpState::CloseWait);
        let packet = tcp_packet(PacketDirection::Outbound, TcpFlags::FIN | TcpFlags::ACK);

        let next_state = machine.transition_tcp(&flow, &packet);

        assert_eq!(next_state, Some(TcpState::LastAck));
    }

    #[test]
    fn inbound_ack_transitions_last_ack_to_closed() {
        let machine = FlowStateMachine::default();
        let mut flow = established_flow();
        flow.tcp_state = Some(TcpState::LastAck);
        let packet = tcp_packet(PacketDirection::Inbound, TcpFlags::ACK);

        let next_state = machine.transition_tcp(&flow, &packet);

        assert_eq!(next_state, Some(TcpState::Closed));
    }

    #[test]
    fn rst_takes_precedence_over_fin_transitions() {
        let machine = FlowStateMachine::default();
        let flow = established_flow();
        let packet = tcp_packet(PacketDirection::Inbound, TcpFlags::FIN | TcpFlags::RST);

        let next_state = machine.transition_tcp(&flow, &packet);

        assert_eq!(next_state, Some(TcpState::Closed));
    }

    #[test]
    fn default_flow_state_config_uses_non_zero_protocol_timeouts() {
        let config = FlowStateConfig::default();

        assert_eq!(config.tcp_timeout, std::time::Duration::from_secs(3600));
        assert_eq!(config.udp_timeout, std::time::Duration::from_secs(60));
        assert_eq!(config.icmp_timeout, std::time::Duration::from_secs(30));
    }

    #[test]
    fn check_lifecycle_treats_exact_timeout_as_expired() {
        let machine = FlowStateMachine::new(FlowStateConfig {
            tcp_timeout: Duration::ZERO,
            ..FlowStateConfig::new()
        });
        let flow = established_flow();

        assert_eq!(machine.check_lifecycle(&flow), FlowLifeCycle::Expired);
    }
}
