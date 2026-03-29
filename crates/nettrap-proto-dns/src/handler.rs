use parking_lot::RwLock;
use async_trait::async_trait;
use trust_dns_proto::rr::{Name, RData, Record, RecordType};

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
        }
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
        self.custom_responses.write().insert(domain.into(), ips);
    }

    pub fn remove_custom_response(&self, domain: &str) {
        self.custom_responses.write().remove(domain);
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
        let message = trust_dns_proto::op::Message::from_vec(query)
            .map_err(|e| Error::Protocol(e.to_string()))?;

        let query = match message.queries().first() {
            Some(q) => q,
            None => return Err(Error::Protocol("No query in message".into())),
        };

        let domain = query.name().to_utf8();
        let query_type = query.query_type();

        tracing::debug!("DNS query: {} ({:?})", domain, query_type);

        // NCSI support - Microsoft Network Connectivity Status Indicator
        if domain == "dns.msftncsi.com." || domain == "dns.msftncsi.com" {
            let ncsi_ip = std::net::Ipv4Addr::new(131, 107, 255, 225);
            let mut response = trust_dns_proto::op::Message::new();
            response.set_message_type(trust_dns_proto::op::MessageType::Response);
            response.set_op_code(trust_dns_proto::op::OpCode::Query);
            response.set_recursion_available(true);
            response.set_response_code(trust_dns_proto::op::ResponseCode::NoError);
            response.set_id(message.id());
            response.add_query(query.clone());

            let mut record = Record::new();
            record.set_name(query.name().clone());
            record.set_record_type(RecordType::A);
            record.set_data(Some(RData::A(trust_dns_proto::rr::rdata::A(ncsi_ip))));
            record.set_ttl(300);
            response.add_answer(record);

            let response_bytes = response.to_vec()
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
                let mut response = trust_dns_proto::op::Message::new();
                response.set_message_type(trust_dns_proto::op::MessageType::Response);
                response.set_op_code(trust_dns_proto::op::OpCode::Query);
                response.set_recursion_available(true);
                response.set_response_code(trust_dns_proto::op::ResponseCode::NXDomain);
                response.set_id(message.id());
                response.add_query(query.clone());

                let response_bytes = response.to_vec()
                    .map_err(|e| Error::Protocol(e.to_string()))?;
                return Ok(response_bytes);
            }
        }

        let response = self.build_response(&message, query, &domain)?;

        let response_bytes = response.to_vec()
            .map_err(|e| Error::Protocol(e.to_string()))?;

        Ok(response_bytes)
    }

    fn name(&self) -> &'static str {
        "dns"
    }
}

impl DnsHandler {
    fn build_response(&self, original_message: &trust_dns_proto::op::Message, query: &trust_dns_proto::op::Query, domain: &str) -> Result<trust_dns_proto::op::Message> {
        use trust_dns_proto::op::{Message, MessageType, OpCode, ResponseCode};

        let mut response = Message::new();
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_recursion_available(true);
        response.set_response_code(ResponseCode::NoError);
        response.set_id(original_message.id());
        response.add_query(query.clone());

        let custom_ips = self.custom_responses.read().get(domain).cloned();

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

    fn build_a_records(&self, _domain: &str, custom_ips: Option<Vec<String>>, name: &Name) -> Result<Vec<Record>> {
        let ips = if let Some(custom) = custom_ips {
            custom.into_iter()
                .filter_map(|ip| ip.parse().ok())
                .collect::<Vec<_>>()
        } else if let Some(ref default_ip) = self.default_response_ip {
            if let Ok(ip) = default_ip.parse::<std::net::IpAddr>() {
                vec![ip]
            } else if self.wildcard_response {
                vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 100, 1))]
            } else {
                vec![]
            }
        } else if self.wildcard_response {
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 100, 1))]
        } else {
            vec![]
        };

        Ok(ips.into_iter()
            .filter_map(|ip| {
                if let std::net::IpAddr::V4(v4) = ip {
                    let mut record = Record::new();
                    record.set_name(name.clone());
                    record.set_record_type(RecordType::A);
                    record.set_data(Some(RData::A(trust_dns_proto::rr::rdata::A(v4))));
                    record.set_ttl(300);
                    Some(record)
                } else {
                    None
                }
            })
            .collect())
    }

    fn build_aaaa_records(&self, _domain: &str, custom_ips: Option<Vec<String>>, name: &Name) -> Result<Vec<Record>> {
        let ips = if let Some(custom) = custom_ips {
            custom.into_iter()
                .filter_map(|ip| ip.parse().ok())
                .collect::<Vec<_>>()
        } else if self.wildcard_response {
            vec![std::net::IpAddr::V6(std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))]
        } else {
            vec![]
        };

        Ok(ips.into_iter()
            .filter_map(|ip| {
                if let std::net::IpAddr::V6(v6) = ip {
                    let mut record = Record::new();
                    record.set_name(name.clone());
                    record.set_record_type(RecordType::AAAA);
                    record.set_data(Some(RData::AAAA(trust_dns_proto::rr::rdata::AAAA(v6))));
                    record.set_ttl(300);
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
        let mx = trust_dns_proto::rr::rdata::MX::new(10, exchange);
        let mut record = Record::new();
        record.set_name(name.clone());
        record.set_record_type(RecordType::MX);
        record.set_data(Some(RData::MX(mx)));
        record.set_ttl(300);
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
        let txt = trust_dns_proto::rr::rdata::TXT::new(vec![txt_value]);
        let mut record = Record::new();
        record.set_name(name.clone());
        record.set_record_type(RecordType::TXT);
        record.set_data(Some(RData::TXT(txt)));
        record.set_ttl(300);
        Ok(vec![record])
    }

    fn build_ns_records(&self, name: &Name) -> Result<Vec<Record>> {
        if !self.wildcard_response {
            return Ok(vec![]);
        }
        let mut records = Vec::new();
        for ns_name in &["ns1.nettrap.local.", "ns2.nettrap.local."] {
            let ns = trust_dns_proto::rr::rdata::NS(Name::from_utf8(ns_name).unwrap());
            let mut record = Record::new();
            record.set_name(name.clone());
            record.set_record_type(RecordType::NS);
            record.set_data(Some(RData::NS(ns)));
            record.set_ttl(300);
            records.push(record);
        }
        Ok(records)
    }

    fn build_cname_records(&self, domain: &str, name: &Name) -> Result<Vec<Record>> {
        if !self.wildcard_response {
            return Ok(vec![]);
        }
        let target = Name::from_utf8(domain)
            .unwrap_or_else(|_| Name::from_utf8("nettrap.local.").unwrap());
        let cname = trust_dns_proto::rr::rdata::CNAME(target);
        let mut record = Record::new();
        record.set_name(name.clone());
        record.set_record_type(RecordType::CNAME);
        record.set_data(Some(RData::CNAME(cname)));
        record.set_ttl(300);
        Ok(vec![record])
    }

    fn build_soa_records(&self, name: &Name) -> Result<Vec<Record>> {
        if !self.wildcard_response {
            return Ok(vec![]);
        }
        let mname = Name::from_utf8("ns1.nettrap.local.").unwrap();
        let rname = Name::from_utf8("admin.nettrap.local.").unwrap();
        let soa = trust_dns_proto::rr::rdata::SOA::new(
            mname, rname,
            2024010101, // serial
            3600,       // refresh
            900,        // retry
            604800,     // expire
            300,        // minimum TTL
        );
        let mut record = Record::new();
        record.set_name(name.clone());
        record.set_record_type(RecordType::SOA);
        record.set_data(Some(RData::SOA(soa)));
        record.set_ttl(300);
        Ok(vec![record])
    }
}
