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

const DEFAULT_WILDCARD_IPV4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(192, 168, 100, 1);
const DEFAULT_WILDCARD_IPV6: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            wildcard_ip: DEFAULT_WILDCARD_IPV4,
            wildcard_ipv6: DEFAULT_WILDCARD_IPV6,
            default_ttl: 300,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dns_config_matches_wildcard_constants() {
        let config = DnsConfig::default();

        assert_eq!(config.wildcard_ip, DEFAULT_WILDCARD_IPV4);
        assert_eq!(config.wildcard_ipv6, DEFAULT_WILDCARD_IPV6);
        assert_eq!(config.default_ttl, 300);
    }
}
