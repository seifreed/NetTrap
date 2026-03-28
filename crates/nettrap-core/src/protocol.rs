use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Igmp,
    Unknown(u8),
}

impl Protocol {
    pub fn from_ip_protocol(proto: u8) -> Self {
        match proto {
            1 => Protocol::Icmp,
            2 => Protocol::Igmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => Protocol::Unknown(proto),
        }
    }

    pub fn to_ip_protocol(&self) -> u8 {
        match self {
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Icmp => 1,
            Protocol::Igmp => 2,
            Protocol::Unknown(p) => *p,
        }
    }

    pub fn is_stream(&self) -> bool {
        matches!(self, Protocol::Tcp)
    }

    pub fn is_datagram(&self) -> bool {
        matches!(self, Protocol::Udp | Protocol::Icmp | Protocol::Igmp)
    }

    pub fn default_port(&self) -> Option<Port> {
        None
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Igmp => write!(f, "IGMP"),
            Protocol::Unknown(p) => write!(f, "UNKNOWN({})", p),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApplicationProtocol {
    Dns,
    DnsOverTls,
    DnsOverHttps,
    Http,
    Https,
    Ftp,
    Ftps,
    Smtp,
    Smtps,
    Pop3,
    Imap,
    Ssh,
    Telnet,
    Quic,
    Tls,
    Ssl,
    Mqtt,
    Coap,
    Raw,
    Unknown(u16),
}

impl ApplicationProtocol {
    pub fn from_port(port: u16, _proto: Protocol) -> Self {
        match port {
            53 => ApplicationProtocol::Dns,
            80 => ApplicationProtocol::Http,
            443 => ApplicationProtocol::Https,
            21 => ApplicationProtocol::Ftp,
            25 => ApplicationProtocol::Smtp,
            110 => ApplicationProtocol::Pop3,
            143 => ApplicationProtocol::Imap,
            22 => ApplicationProtocol::Ssh,
            23 => ApplicationProtocol::Telnet,
            _ => ApplicationProtocol::Unknown(port),
        }
    }

    pub fn default_port(&self) -> Option<u16> {
        match self {
            ApplicationProtocol::Dns => Some(53),
            ApplicationProtocol::Http => Some(80),
            ApplicationProtocol::Https => Some(443),
            ApplicationProtocol::Ftp => Some(21),
            ApplicationProtocol::Smtp => Some(25),
            ApplicationProtocol::Pop3 => Some(110),
            ApplicationProtocol::Imap => Some(143),
            ApplicationProtocol::Ssh => Some(22),
            ApplicationProtocol::Telnet => Some(23),
            ApplicationProtocol::Quic => Some(443),
            ApplicationProtocol::Tls => Some(443),
            ApplicationProtocol::Raw => None,
            ApplicationProtocol::Unknown(p) => Some(*p),
            _ => None,
        }
    }

    pub fn is_tls(&self) -> bool {
        matches!(
            self,
            ApplicationProtocol::Tls | ApplicationProtocol::Https | ApplicationProtocol::DnsOverTls
        )
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(
            self,
            ApplicationProtocol::Https
                | ApplicationProtocol::Tls
                | ApplicationProtocol::Quic
                | ApplicationProtocol::Ssh
                | ApplicationProtocol::DnsOverTls
                | ApplicationProtocol::DnsOverHttps
        )
    }
}

impl std::fmt::Display for ApplicationProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplicationProtocol::Dns => write!(f, "DNS"),
            ApplicationProtocol::DnsOverTls => write!(f, "DoT"),
            ApplicationProtocol::DnsOverHttps => write!(f, "DoH"),
            ApplicationProtocol::Http => write!(f, "HTTP"),
            ApplicationProtocol::Https => write!(f, "HTTPS"),
            ApplicationProtocol::Ftp => write!(f, "FTP"),
            ApplicationProtocol::Ftps => write!(f, "FTPS"),
            ApplicationProtocol::Smtp => write!(f, "SMTP"),
            ApplicationProtocol::Smtps => write!(f, "SMTPS"),
            ApplicationProtocol::Pop3 => write!(f, "POP3"),
            ApplicationProtocol::Imap => write!(f, "IMAP"),
            ApplicationProtocol::Ssh => write!(f, "SSH"),
            ApplicationProtocol::Telnet => write!(f, "TELNET"),
            ApplicationProtocol::Quic => write!(f, "QUIC"),
            ApplicationProtocol::Tls => write!(f, "TLS"),
            ApplicationProtocol::Ssl => write!(f, "SSL"),
            ApplicationProtocol::Mqtt => write!(f, "MQTT"),
            ApplicationProtocol::Coap => write!(f, "CoAP"),
            ApplicationProtocol::Raw => write!(f, "RAW"),
            ApplicationProtocol::Unknown(p) => write!(f, "UNKNOWN({})", p),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FiveTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl FiveTuple {
    pub fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }

    pub fn to_flow_key(&self) -> FlowKey {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        FlowKey(hasher.finish())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey(pub u64);

impl FlowKey {
    pub fn from_five_tuple(tuple: &FiveTuple) -> Self {
        tuple.to_flow_key()
    }
}
