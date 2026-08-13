use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PacketDirection {
    Inbound,
    Outbound,
    Unknown,
}

impl PacketDirection {
    pub fn is_inbound(&self) -> bool {
        matches!(self, PacketDirection::Inbound)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PacketType {
    Syn,
    SynAck,
    Ack,
    Fin,
    FinAck,
    Rst,
    Push,
    Data,
    Unknown,
}

impl PacketType {}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(transparent)]
    pub struct TcpFlags: u8 {
        const FIN = 0x01;
        const SYN = 0x02;
        const RST = 0x04;
        const PSH = 0x08;
        const ACK = 0x10;
        const URG = 0x20;
        const ECE = 0x40;
        const CWR = 0x80;
    }
}

impl TcpFlags {
    pub fn from_bits_truncate_value(bits: u8) -> Self {
        Self::from_bits_truncate(bits)
    }

    pub fn to_packet_type(&self) -> PacketType {
        if self.contains(Self::SYN) && !self.contains(Self::ACK) {
            PacketType::Syn
        } else if self.contains(Self::SYN) && self.contains(Self::ACK) {
            PacketType::SynAck
        } else if self.contains(Self::RST) {
            PacketType::Rst
        } else if self.contains(Self::FIN) && !self.contains(Self::ACK) {
            PacketType::Fin
        } else if self.contains(Self::FIN) && self.contains(Self::ACK) {
            PacketType::FinAck
        } else if self.contains(Self::PSH) {
            PacketType::Push
        } else if self.contains(Self::ACK) {
            PacketType::Ack
        } else {
            PacketType::Unknown
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub id: PacketId,
    pub timestamp: Timestamp,
    pub five_tuple: FiveTuple,
    pub direction: PacketDirection,
    pub packet_type: PacketType,
    pub tcp_flags: Option<TcpFlags>,
    pub payload: Bytes,
    pub length: usize,
    pub interface: Option<String>,
    pub vlan_tag: Option<u16>,
}

impl Packet {
    pub fn new(five_tuple: FiveTuple, direction: PacketDirection, payload: Bytes) -> Self {
        let length = payload.len();
        Self {
            id: PacketId::new_v4(),
            timestamp: now(),
            five_tuple,
            direction,
            packet_type: PacketType::Unknown,
            tcp_flags: None,
            payload,
            length,
            interface: None,
            vlan_tag: None,
        }
    }

    pub fn with_tcp_flags(mut self, flags: TcpFlags) -> Self {
        self.packet_type = flags.to_packet_type();
        self.tcp_flags = Some(flags);
        self
    }

    pub fn with_interface(mut self, iface: impl Into<String>) -> Self {
        self.interface = Some(iface.into());
        self
    }

    pub fn with_vlan(mut self, tag: u16) -> Self {
        self.vlan_tag = Some(tag);
        self
    }

    pub fn src(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.five_tuple.src_ip, self.five_tuple.src_port)
    }

    pub fn dst(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.five_tuple.dst_ip, self.five_tuple.dst_port)
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self::new(
            FiveTuple::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                0,
                0,
                Protocol::Tcp,
            ),
            PacketDirection::Unknown,
            Bytes::new(),
        )
    }
}
