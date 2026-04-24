use async_trait::async_trait;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use parking_lot::RwLock;

use crate::prelude::*;

pub struct DnsHandler {
    wildcard_response: bool,
    custom_responses: RwLock<std::collections::HashMap<String, Vec<String>>>,
    // NXDomains cycling support
    nxdomains_count: RwLock<u32>,
    nxdomains_threshold: u32,
    // Per-listener default response config
    default_response_ip: Option<String>,
    default_response_mx: Option<String>,
    default_response_txt: Option<String>,
    // NCSI response IP (configurable for honeypot detection avoidance)
    // Default: Microsoft's actual NCSI IP, but operators should change this
    ncsi_response_ip: std::net::Ipv4Addr,
}

impl DnsHandler {
    pub fn new() -> Self {
        Self {
            wildcard_response: true,
            custom_responses: RwLock::new(std::collections::HashMap::new()),
            nxdomains_count: RwLock::new(0),
            nxdomains_threshold: 0,
            default_response_ip: None,
            default_response_mx: None,
            default_response_txt: None,
            // Default to Microsoft NCSI IP (131.107.255.225)
            // Operators should configure this to a local IP to avoid honeypot detection
            ncsi_response_ip: std::net::Ipv4Addr::new(131, 107, 255, 225),
        }
    }

    /// Set a custom NCSI response IP.
    /// Recommended: Use a local IP (e.g., 192.168.1.1) to avoid honeypot fingerprinting.
    /// Microsoft's NCSI servers: 131.107.255.225 (IPv4), fd00:fd00:fd00:fd00:fd00:fd00:fd00:fd00 (IPv6)
    pub fn with_ncsi_response_ip(mut self, ip: std::net::Ipv4Addr) -> Self {
        self.ncsi_response_ip = ip;
        self
    }

    pub fn with_wildcard(mut self, wildcard: bool) -> Self {
        self.wildcard_response = wildcard;
        self
    }

    pub fn with_nxdomains(mut self, n: u32) -> Self {
        self.nxdomains_threshold = n;
        self
    }

    pub fn with_default_response_ip(mut self, ip: impl Into<String>) -> Self {
        self.default_response_ip = Some(ip.into());
        self
    }

    pub fn with_default_response_mx(mut self, mx: impl Into<String>) -> Self {
        self.default_response_mx = Some(mx.into());
        self
    }

    pub fn with_default_response_txt(mut self, txt: impl Into<String>) -> Self {
        self.default_response_txt = Some(txt.into());
        self
    }

    /// Auto-detect local IP using UDP socket trick for default route
    pub fn with_auto_response_ip(mut self) -> Self {
        // Use a UDP socket trick to find our default route IP
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if socket.connect("8.8.8.8:53").is_ok() {
                if let Ok(addr) = socket.local_addr() {
                    if !addr.ip().is_loopback() {
                        self.default_response_ip = Some(addr.ip().to_string());
                        return self;
                    }
                }
            }
        }
        // Fallback
        self.default_response_ip = Some("192.168.100.1".to_string());
        self
    }

    pub fn add_custom_response(&self, domain: impl Into<String>, ips: Vec<String>) {
        self.custom_responses
            .write()
            .insert(normalize_domain_key(&domain.into()), ips);
    }

    pub fn remove_custom_response(&self, domain: &str) {
        self.custom_responses
            .write()
            .remove(&normalize_domain_key(domain));
    }

    pub fn clear_custom_responses(&self) {
        self.custom_responses.write().clear();
    }
}

impl Default for DnsHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait DnsHandlerTrait: Send + Sync {
    async fn handle_query(&self, query: &[u8], src: std::net::SocketAddr) -> Result<Vec<u8>>;
    fn name(&self) -> &'static str;
}

#[async_trait]
impl DnsHandlerTrait for DnsHandler {
    async fn handle_query(&self, query: &[u8], _src: std::net::SocketAddr) -> Result<Vec<u8>> {
        let message = hickory_proto::op::Message::from_vec(query)
            .map_err(|e| Error::Protocol(e.to_string()))?;

        let query = match message.queries().first() {
            Some(q) => q,
            None => return Err(Error::Protocol("No query in message".into())),
        };

        let domain = query.name().to_utf8();
        let query_type = query.query_type();

        tracing::debug!("DNS query: {} ({:?})", domain, query_type);

        // NCSI support - Microsoft Network Connectivity Status Indicator
        // DNS names are case-insensitive per RFC 1035 §2.3.3
        // Note: By default returns Microsoft's actual NCSI IP which can fingerprint this as a honeypot.
        // Operators should configure ncsi_response_ip to a local IP for better opsec.
        let domain_lower = domain.to_ascii_lowercase();
        if domain_lower == "dns.msftncsi.com." || domain_lower == "dns.msftncsi.com" {
            let ncsi_ip = self.ncsi_response_ip;
            let mut response = hickory_proto::op::Message::new();
            response.set_message_type(hickory_proto::op::MessageType::Response);
            response.set_op_code(hickory_proto::op::OpCode::Query);
            response.set_recursion_available(true);
            response.set_response_code(hickory_proto::op::ResponseCode::NoError);
            response.set_id(message.id());
            response.add_query(query.clone());

            if query_type == RecordType::A {
                let record = Record::from_rdata(
                    query.name().clone(),
                    300,
                    RData::A(hickory_proto::rr::rdata::A(ncsi_ip)),
                );
                response.add_answer(record);
            }

            let response_bytes = response
                .to_vec()
                .map_err(|e| Error::Protocol(e.to_string()))?;
            return Ok(response_bytes);
        }

        // NXDomains cycling: return NXDOMAIN for the first N queries per cycle,
        // then one normal response, then repeat.
        if self.nxdomains_threshold > 0 {
            let mut count = self.nxdomains_count.write();
            let should_nxdomain = *count < self.nxdomains_threshold;
            *count += 1;
            // Reset after threshold + 1 (N NXDOMAINs + 1 normal = cycle)
            if *count > self.nxdomains_threshold {
                *count = 0;
            }
            if should_nxdomain {
                let mut response = hickory_proto::op::Message::new();
                response.set_message_type(hickory_proto::op::MessageType::Response);
                response.set_op_code(hickory_proto::op::OpCode::Query);
                response.set_recursion_available(true);
                response.set_response_code(hickory_proto::op::ResponseCode::NXDomain);
                response.set_id(message.id());
                response.add_query(query.clone());

                let response_bytes = response
                    .to_vec()
                    .map_err(|e| Error::Protocol(e.to_string()))?;
                return Ok(response_bytes);
            }
        }

        let response = self.build_response(&message, query, &domain)?;

        let response_bytes = response
            .to_vec()
            .map_err(|e| Error::Protocol(e.to_string()))?;

        Ok(response_bytes)
    }

    fn name(&self) -> &'static str {
        "dns"
    }
}

impl DnsHandler {
    fn build_response(
        &self,
        original_message: &hickory_proto::op::Message,
        query: &hickory_proto::op::Query,
        domain: &str,
    ) -> Result<hickory_proto::op::Message> {
        use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};

        let mut response = Message::new();
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_recursion_available(true);
        response.set_response_code(ResponseCode::NoError);
        response.set_id(original_message.id());
        response.add_query(query.clone());

        let custom_ips = self
            .custom_responses
            .read()
            .get(&normalize_domain_key(domain))
            .cloned();

        let records = match query.query_type() {
            RecordType::A => self.build_a_records(domain, custom_ips, query.name())?,
            RecordType::AAAA => self.build_aaaa_records(domain, custom_ips, query.name())?,
            RecordType::MX => self.build_mx_records(domain, query.name())?,
            RecordType::TXT => self.build_txt_records(domain, query.name())?,
            RecordType::NS => self.build_ns_records(query.name())?,
            RecordType::CNAME => self.build_cname_records(domain, query.name())?,
            RecordType::SOA => self.build_soa_records(query.name())?,
            _ => vec![],
        };

        for record in records {
            response.add_answer(record);
        }

        Ok(response)
    }

    fn build_a_records(
        &self,
        _domain: &str,
        custom_ips: Option<Vec<String>>,
        name: &Name,
    ) -> Result<Vec<Record>> {
        let ips = if let Some(custom) = custom_ips {
            custom
                .into_iter()
                .filter_map(|ip| ip.parse().ok())
                .collect::<Vec<_>>()
        } else if let Some(ref default_ip) = self.default_response_ip {
            if let Ok(ip) = default_ip.parse::<std::net::IpAddr>() {
                vec![ip]
            } else if self.wildcard_response {
                vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    192, 168, 100, 1,
                ))]
            } else {
                vec![]
            }
        } else if self.wildcard_response {
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, 100, 1,
            ))]
        } else {
            vec![]
        };

        Ok(ips
            .into_iter()
            .filter_map(|ip| {
                if let std::net::IpAddr::V4(v4) = ip {
                    let record = Record::from_rdata(
                        name.clone(),
                        300,
                        RData::A(hickory_proto::rr::rdata::A(v4)),
                    );
                    Some(record)
                } else {
                    None
                }
            })
            .collect())
    }

    fn build_aaaa_records(
        &self,
        _domain: &str,
        custom_ips: Option<Vec<String>>,
        name: &Name,
    ) -> Result<Vec<Record>> {
        let ips = if let Some(custom) = custom_ips {
            custom
                .into_iter()
                .filter_map(|ip| ip.parse().ok())
                .collect::<Vec<_>>()
        } else if self.wildcard_response {
            vec![std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                0xfd00, 0, 0, 0, 0, 0, 0, 1,
            ))]
        } else {
            vec![]
        };

        Ok(ips
            .into_iter()
            .filter_map(|ip| {
                if let std::net::IpAddr::V6(v6) = ip {
                    let record = Record::from_rdata(
                        name.clone(),
                        300,
                        RData::AAAA(hickory_proto::rr::rdata::AAAA(v6)),
                    );
                    Some(record)
                } else {
                    None
                }
            })
            .collect())
    }

    fn build_mx_records(&self, domain: &str, name: &Name) -> Result<Vec<Record>> {
        if !self.wildcard_response {
            return Ok(vec![]);
        }
        let exchange_name = if let Some(ref mx) = self.default_response_mx {
            mx.clone()
        } else {
            format!("mail.{}", domain)
        };
        let exchange = Name::from_utf8(&exchange_name)
            .unwrap_or_else(|_| Name::from_utf8("mail.nettrap.local.").unwrap());
        let mx = hickory_proto::rr::rdata::MX::new(10, exchange);
        let record = Record::from_rdata(name.clone(), 300, RData::MX(mx));
        Ok(vec![record])
    }

    fn build_txt_records(&self, _domain: &str, name: &Name) -> Result<Vec<Record>> {
        if !self.wildcard_response {
            return Ok(vec![]);
        }
        let txt_value = if let Some(ref txt) = self.default_response_txt {
            txt.clone()
        } else {
            "v=spf1 +a +mx ~all".to_string()
        };
        let txt = hickory_proto::rr::rdata::TXT::new(vec![txt_value]);
        let record = Record::from_rdata(name.clone(), 300, RData::TXT(txt));
        Ok(vec![record])
    }

    fn build_ns_records(&self, name: &Name) -> Result<Vec<Record>> {
        if !self.wildcard_response {
            return Ok(vec![]);
        }
        let mut records = Vec::new();
        for ns_name in &["ns1.nettrap.local.", "ns2.nettrap.local."] {
            let ns = match Name::from_utf8(*ns_name) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let record = Record::from_rdata(
                name.clone(),
                300,
                RData::NS(hickory_proto::rr::rdata::NS(ns)),
            );
            records.push(record);
        }
        Ok(records)
    }

    fn build_cname_records(&self, _domain: &str, name: &Name) -> Result<Vec<Record>> {
        if !self.wildcard_response {
            return Ok(vec![]);
        }
        let target = Name::from_utf8("nettrap.local.").unwrap();
        let cname = hickory_proto::rr::rdata::CNAME(target);
        let record = Record::from_rdata(name.clone(), 300, RData::CNAME(cname));
        Ok(vec![record])
    }

    fn build_soa_records(&self, name: &Name) -> Result<Vec<Record>> {
        if !self.wildcard_response {
            return Ok(vec![]);
        }
        let mname = Name::from_utf8("ns1.nettrap.local.").unwrap_or_else(|_| Name::root());
        let rname = Name::from_utf8("admin.nettrap.local.").unwrap_or_else(|_| Name::root());
        let soa = hickory_proto::rr::rdata::SOA::new(
            mname, rname, 2024010101, // serial
            3600,       // refresh
            900,        // retry
            604800,     // expire
            300,        // minimum TTL
        );
        let record = Record::from_rdata(name.clone(), 300, RData::SOA(soa));
        Ok(vec![record])
    }
}

fn normalize_domain_key(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}
