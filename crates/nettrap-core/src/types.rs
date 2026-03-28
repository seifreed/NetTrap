use serde::{Deserialize, Serialize};

pub type FlowId = uuid::Uuid;
pub type PacketId = uuid::Uuid;
pub type ProcessId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Port(pub u16);

impl Port {
    pub const DNS: Port = Port(53);
    pub const HTTP: Port = Port(80);
    pub const HTTPS: Port = Port(443);
    pub const FTP: Port = Port(21);
    pub const FTP_DATA: Port = Port(20);
    pub const SMTP: Port = Port(25);
    pub const SMTPS: Port = Port(465);
    pub const QUIC: Port = Port(443);

    pub fn new(port: u16) -> Self {
        Self(port)
    }

    pub fn is_well_known(&self) -> bool {
        self.0 < 1024
    }

    pub fn is_ephemeral(&self) -> bool {
        self.0 >= 49152
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IpAddress(pub std::net::IpAddr);

impl IpAddress {
    pub fn is_loopback(&self) -> bool {
        self.0.is_loopback()
    }

    pub fn is_private(&self) -> bool {
        match self.0 {
            std::net::IpAddr::V4(v4) => v4.is_private(),
            std::net::IpAddr::V6(_v6) => false,
        }
    }

    pub fn is_multicast(&self) -> bool {
        self.0.is_multicast()
    }
}

impl From<std::net::IpAddr> for IpAddress {
    fn from(addr: std::net::IpAddr) -> Self {
        Self(addr)
    }
}

impl From<IpAddress> for std::net::IpAddr {
    fn from(addr: IpAddress) -> Self {
        addr.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SocketAddr {
    pub ip: IpAddress,
    pub port: Port,
}

impl SocketAddr {
    pub fn new(ip: impl Into<IpAddress>, port: u16) -> Self {
        Self {
            ip: ip.into(),
            port: Port(port),
        }
    }

    pub fn to_std(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.ip.0, self.port.0)
    }
}

impl From<std::net::SocketAddr> for SocketAddr {
    fn from(addr: std::net::SocketAddr) -> Self {
        Self {
            ip: IpAddress(addr.ip()),
            port: Port(addr.port()),
        }
    }
}
