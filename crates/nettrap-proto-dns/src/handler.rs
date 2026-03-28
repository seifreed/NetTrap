use parking_lot::RwLock;
use async_trait::async_trait;
use trust_dns_proto::rr::{Name, RData, Record, RecordType};

use crate::prelude::*;

pub struct DnsHandler {
    wildcard_response: bool,
    custom_responses: RwLock<std::collections::HashMap<String, Vec<String>>>,
}

impl DnsHandler {
    pub fn new() -> Self {
        Self {
            wildcard_response: true,
            custom_responses: RwLock::new(std::collections::HashMap::new()),
        }
    }
    
    pub fn with_wildcard(mut self, wildcard: bool) -> Self {
        self.wildcard_response = wildcard;
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
}