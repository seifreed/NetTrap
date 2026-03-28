use crate::prelude::*;

pub struct DnsResponse {
    pub domain: String,
    pub query_type: u16,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: u16,
    pub ttl: u32,
    pub data: String,
}

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub wildcard_ip: std::net::Ipv4Addr,
    pub wildcard_ipv6: std::net::Ipv6Addr,
    pub default_ttl: u32,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            wildcard_ip: std::net::Ipv4Addr::new(192, 168, 100, 1),
            wildcard_ipv6: std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            default_ttl: 300,
        }
    }
}

pub fn fake_response(domain: &str, query_type: u16) -> Option<Vec<String>> {
    match query_type {
        1 => Some(vec!["192.168.100.1".to_string()]),
        28 => Some(vec!["fd00::1".to_string()]),
        _ => None,
    }
}
