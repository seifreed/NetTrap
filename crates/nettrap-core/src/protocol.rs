use std::net::IpAddr;

use serde::{Deserialize, Serialize};

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
    Pop3s,
    Imap,
    Imaps,
    Ldap,
    Ssh,
    Telnet,
    Telnets,
    Ircs,
    Ldaps,
    Quic,
    Tls,
    Ssl,
    Mqtt,
    Coap,
    Raw,
    Unknown(u16),
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
            ApplicationProtocol::Ldap => write!(f, "LDAP"),
            ApplicationProtocol::Pop3s => write!(f, "POP3S"),
            ApplicationProtocol::Imap => write!(f, "IMAP"),
            ApplicationProtocol::Imaps => write!(f, "IMAPS"),
            ApplicationProtocol::Ssh => write!(f, "SSH"),
            ApplicationProtocol::Telnet => write!(f, "TELNET"),
            ApplicationProtocol::Telnets => write!(f, "TELNETS"),
            ApplicationProtocol::Ircs => write!(f, "IRCS"),
            ApplicationProtocol::Ldaps => write!(f, "LDAPS"),
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

fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(ip),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
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
            src_ip: canonicalize_ip(src_ip),
            dst_ip: canonicalize_ip(dst_ip),
            src_port,
            dst_port,
            protocol,
        }
    }

    pub fn to_flow_key(&self) -> FlowKey {
        FlowKey::from_five_tuple(self)
    }
}

#[derive(Deserialize)]
struct FiveTupleSerde {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: Protocol,
}

impl<'de> Deserialize<'de> for FiveTuple {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = FiveTupleSerde::deserialize(deserializer)?;
        Ok(Self::new(
            helper.src_ip,
            helper.dst_ip,
            helper.src_port,
            helper.dst_port,
            helper.protocol,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey(pub u64);

impl FlowKey {
    pub fn from_five_tuple(tuple: &FiveTuple) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        tuple.hash(&mut hasher);
        FlowKey(hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_tuple_new_canonicalizes_ipv4_mapped_addresses() {
        let tuple = FiveTuple::new(
            "192.0.2.10".parse().unwrap(),
            "::ffff:10.0.0.5".parse().unwrap(),
            12345,
            80,
            Protocol::Tcp,
        );

        assert_eq!(
            tuple,
            FiveTuple::new(
                "192.0.2.10".parse().unwrap(),
                "10.0.0.5".parse().unwrap(),
                12345,
                80,
                Protocol::Tcp,
            )
        );
    }

    #[test]
    fn five_tuple_deserialize_canonicalizes_ipv4_mapped_addresses() {
        let tuple: FiveTuple = serde_json::from_str(
            r#"{"src_ip":"::ffff:192.0.2.10","dst_ip":"::ffff:10.0.0.5","src_port":12345,"dst_port":80,"protocol":"tcp"}"#,
        )
        .expect("tuple should deserialize");

        assert_eq!(
            tuple,
            FiveTuple::new(
                "192.0.2.10".parse().unwrap(),
                "10.0.0.5".parse().unwrap(),
                12345,
                80,
                Protocol::Tcp,
            )
        );
    }
}
