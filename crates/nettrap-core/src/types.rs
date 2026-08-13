use serde::{Deserialize, Serialize};

pub type FlowId = uuid::Uuid;
pub type PacketId = uuid::Uuid;
pub type ProcessId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Port(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct IpAddress(pub std::net::IpAddr);

impl From<std::net::IpAddr> for IpAddress {
    fn from(addr: std::net::IpAddr) -> Self {
        Self(canonicalize_ip(addr))
    }
}

impl From<IpAddress> for std::net::IpAddr {
    fn from(addr: IpAddress) -> Self {
        addr.0
    }
}

impl<'de> Deserialize<'de> for IpAddress {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let ip = std::net::IpAddr::deserialize(deserializer)?;
        Ok(Self(canonicalize_ip(ip)))
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
}

fn canonicalize_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V4(ip) => std::net::IpAddr::V4(ip),
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_address_from_canonicalizes_ipv4_mapped_addresses() {
        let ip = IpAddress::from("::ffff:192.0.2.10".parse::<std::net::IpAddr>().unwrap());

        assert_eq!(ip.0, "192.0.2.10".parse::<std::net::IpAddr>().unwrap());
    }

    #[test]
    fn ip_address_deserialize_canonicalizes_ipv4_mapped_addresses() {
        let ip: IpAddress = serde_json::from_str(r#""::ffff:192.0.2.10""#).unwrap();

        assert_eq!(ip.0, "192.0.2.10".parse::<std::net::IpAddr>().unwrap());
    }
}
