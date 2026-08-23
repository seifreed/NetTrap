use std::sync::LazyLock;

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use parking_lot::RwLock;

use crate::prelude::*;

const DNS_QUERY_ONLY_COUNTS: [u16; 4] = [1, 0, 0, 0];

fn dns_section_counts(data: &[u8]) -> Option<[u16; 4]> {
    let counts = data.get(4..12)?;
    Some([
        u16::from_be_bytes([counts[0], counts[1]]),
        u16::from_be_bytes([counts[2], counts[3]]),
        u16::from_be_bytes([counts[4], counts[5]]),
        u16::from_be_bytes([counts[6], counts[7]]),
    ])
}

/// Safely parse a DNS message from raw bytes, catching panics from the
/// hickory-proto library (e.g. integer-overflow in TSIG RDATA error
/// formatting on malformed input). Returns `None` when the underlying
/// parser panics, so callers' `?` / `map_err` paths degrade to a normal
/// protocol error instead of crashing the honeypot process.
fn safe_message_from_vec(data: &[u8]) -> Option<Message> {
    if dns_section_counts(data) != Some(DNS_QUERY_ONLY_COUNTS) {
        return None;
    }

    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Message::from_vec(data)))
        .ok()
        .and_then(|r| r.ok())
}

const DNS_TXT_CHARACTER_STRING_MAX_BYTES: usize = 255;
const DNS_DEFAULT_RESPONSE_TXT_MAX_BYTES: usize = 1024;
const MAX_DNS_CUSTOM_RESPONSE_DOMAINS: usize = 256;
const MAX_DNS_CUSTOM_RESPONSE_IPS: usize = 32;

fn dns_constant_name(value: &str) -> Name {
    Name::from_utf8(value).unwrap_or_else(|_| Name::root())
}

/// Parse the queried domain name and record type from a raw DNS query packet,
/// for telemetry. Returns `(domain, query_type)` using the same hickory parser
/// the handler uses, with the domain normalized to lowercase for stable NBI
/// grouping. Returns `None` when the packet is not a parseable DNS message
/// with a question.
///
/// The domain is lowercased and has its trailing root dot stripped
/// (`EVIL.Example.com.` -> `evil.example.com`); the query type is the textual
/// record type (`A`, `AAAA`, `MX`, `TXT`, ...).
pub fn parse_query_summary(query: &[u8]) -> Option<(String, String)> {
    let message = safe_message_from_vec(query)?;
    if message.metadata.message_type != MessageType::Query
        || message.metadata.op_code != OpCode::Query
        || message.queries.len() != 1
        || !message.answers.is_empty()
        || !message.authorities.is_empty()
        || !message.additionals.is_empty()
    {
        return None;
    }
    let question = message.queries.first()?;
    let domain = normalize_dns_query_domain(&question.name().to_utf8())?;
    let query_type = question.query_type().to_string();
    Some((domain, query_type))
}

/// Constant honeypot DNS names, parsed once.
static NETTRAP_LOCAL: LazyLock<Name> = LazyLock::new(|| dns_constant_name("nettrap.local."));
static NS1_NETTRAP_LOCAL: LazyLock<Name> =
    LazyLock::new(|| dns_constant_name("ns1.nettrap.local."));
static ADMIN_NETTRAP_LOCAL: LazyLock<Name> =
    LazyLock::new(|| dns_constant_name("admin.nettrap.local."));

pub struct DnsHandler {
    wildcard_response: bool,
    response_config: DnsConfig,
    custom_responses: RwLock<std::collections::HashMap<String, Vec<String>>>,
    nxdomains_count: RwLock<u32>,
    nxdomains_threshold: u32,
    default_response_ip: Option<String>,
    default_response_mx: Option<String>,
    default_response_txt: Option<String>,
    // NCSI response IP (configurable for honeypot detection avoidance)
    // Default: Microsoft's actual NCSI IP, but operators should change this
    ncsi_response_ip: std::net::Ipv4Addr,
    now: fn() -> chrono::DateTime<chrono::Utc>,
}

impl DnsHandler {
    pub fn new() -> Self {
        Self {
            wildcard_response: true,
            response_config: DnsConfig::default(),
            custom_responses: RwLock::new(std::collections::HashMap::new()),
            nxdomains_count: RwLock::new(0),
            nxdomains_threshold: 0,
            default_response_ip: None,
            default_response_mx: None,
            default_response_txt: None,
            // Default to Microsoft NCSI IP (131.107.255.225)
            // Operators should configure this to a local IP to avoid honeypot detection
            ncsi_response_ip: std::net::Ipv4Addr::new(131, 107, 255, 225),
            now: chrono::Utc::now,
        }
    }

    /// Set a custom NCSI response IP.
    /// Recommended: Use a local IP (e.g., 192.168.1.1) to avoid honeypot fingerprinting.
    /// Microsoft's NCSI servers: 131.107.255.225 (IPv4), fd00:fd00:fd00:fd00:fd00:fd00:fd00:fd00 (IPv6)
    pub fn with_ncsi_response_ip(mut self, ip: std::net::Ipv4Addr) -> Result<Self> {
        if !is_usable_dns_response_ipv4(ip) {
            return Err(Error::Config(
                "Invalid NCSI response IP: must be a usable unicast address".to_string(),
            ));
        }
        self.ncsi_response_ip = ip;
        Ok(self)
    }

    pub fn with_wildcard(mut self, wildcard: bool) -> Self {
        self.wildcard_response = wildcard;
        self
    }

    /// Inject the clock used for SOA serial generation so FakeTime mode can
    /// reach DNS zone metadata as well.
    pub fn with_now(mut self, now: fn() -> chrono::DateTime<chrono::Utc>) -> Self {
        self.now = now;
        self
    }

    pub fn with_response_config(mut self, config: DnsConfig) -> Self {
        self.response_config = config;
        self
    }

    pub fn with_nxdomains(mut self, n: u32) -> Self {
        self.nxdomains_threshold = n;
        self
    }

    pub fn with_default_response_ip(mut self, ip: impl Into<String>) -> Result<Self> {
        let ip = ip.into();
        let Some(normalized) = normalize_dns_ip(&ip) else {
            return Err(Error::Config(format!(
                "Invalid default DNS response IP '{}'",
                ip
            )));
        };
        self.default_response_ip = Some(normalized);
        Ok(self)
    }

    pub fn with_default_response_mx(mut self, mx: impl Into<String>) -> Result<Self> {
        let mx = mx.into();
        let Some(normalized) = normalize_dns_name(&mx) else {
            return Err(Error::Config(format!(
                "Invalid default DNS MX exchange name '{}'",
                mx
            )));
        };
        self.default_response_mx = Some(normalized);
        Ok(self)
    }

    pub fn with_default_response_txt(mut self, txt: impl Into<String>) -> Result<Self> {
        let txt = txt.into();
        self.default_response_txt = Some(normalize_dns_txt(&txt)?);
        Ok(self)
    }

    /// Auto-detect local IP using UDP socket trick for default route
    pub fn with_auto_response_ip(mut self) -> Result<Self> {
        if let Some(ip) = auto_detect_default_response_ip() {
            self.default_response_ip = Some(ip);
            return Ok(self);
        }

        Err(Error::Config(
            "Failed to auto-detect a default DNS response IP".to_string(),
        ))
    }

    pub fn add_custom_response(&self, domain: impl Into<String>, ips: Vec<String>) -> Result<()> {
        let domain = domain.into();
        let domain_key = normalize_domain_key(&domain);
        if domain_key.is_empty() {
            return Err(Error::Config(format!(
                "Invalid DNS custom response domain '{}'",
                domain
            )));
        }
        if ips.is_empty() {
            return Err(Error::Config(format!(
                "Invalid DNS custom response for domain '{}': at least one IP is required",
                domain_key
            )));
        }
        if ips.len() > MAX_DNS_CUSTOM_RESPONSE_IPS {
            return Err(Error::Config(format!(
                "Invalid DNS custom response for domain '{}': too many IPs ({} > {})",
                domain_key,
                ips.len(),
                MAX_DNS_CUSTOM_RESPONSE_IPS
            )));
        }
        let mut parsed_ips = Vec::with_capacity(ips.len());
        for ip in ips {
            let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() else {
                return Err(Error::Config(format!(
                    "Invalid DNS custom response for domain '{}': invalid IP '{}'",
                    domain_key, ip
                )));
            };
            if !is_usable_dns_response_ip(&ip_addr) {
                return Err(Error::Config(format!(
                    "Invalid DNS custom response for domain '{}': invalid IP '{}'",
                    domain_key, ip
                )));
            }
            parsed_ips.push(match ip_addr {
                std::net::IpAddr::V4(v4) => v4.to_string(),
                std::net::IpAddr::V6(v6) => v6
                    .to_ipv4_mapped()
                    .map_or_else(|| v6.to_string(), |mapped| mapped.to_string()),
            });
        }

        let mut custom_responses = self.custom_responses.write();
        if !custom_responses.contains_key(&domain_key)
            && custom_responses.len() >= MAX_DNS_CUSTOM_RESPONSE_DOMAINS
        {
            return Err(Error::Config(format!(
                "Invalid DNS custom response for domain '{}': too many custom domains ({} >= {})",
                domain_key,
                custom_responses.len(),
                MAX_DNS_CUSTOM_RESPONSE_DOMAINS
            )));
        }

        custom_responses.insert(domain_key, parsed_ips);
        Ok(())
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

fn is_usable_dns_response_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => is_usable_dns_response_ipv4(*ip),
        std::net::IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_usable_dns_response_ipv4(mapped);
            }
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
        }
    }
}

fn is_usable_dns_response_ipv4(ip: std::net::Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
}

fn canonical_dns_response_ip(ip: std::net::IpAddr) -> Option<String> {
    if !is_usable_dns_response_ip(&ip) {
        return None;
    }

    Some(match ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| v6.to_string(), |mapped| mapped.to_string()),
    })
}

fn auto_detect_default_response_ip() -> Option<String> {
    auto_detect_default_response_ip_with_probe(|bind_addr, connect_addr| {
        let socket = std::net::UdpSocket::bind(bind_addr).ok()?;
        socket.connect(connect_addr).ok()?;
        socket.local_addr().ok().map(|addr| addr.ip())
    })
}

fn auto_detect_default_response_ip_with_probe<F>(mut probe: F) -> Option<String>
where
    F: FnMut(&str, &str) -> Option<std::net::IpAddr>,
{
    for (bind_addr, connect_addr) in [
        ("0.0.0.0:0", "8.8.8.8:53"),
        ("[::]:0", "[2001:4860:4860::8888]:53"),
    ] {
        let Some(ip) = probe(bind_addr, connect_addr) else {
            continue;
        };
        if let Some(ip) = canonical_dns_response_ip(ip) {
            return Some(ip);
        }
    }

    None
}

impl Default for DnsHandler {
    fn default() -> Self {
        Self::new()
    }
}

fn dns_response(id: u16, response_code: ResponseCode) -> Message {
    let mut response = Message::response(id, OpCode::Query);
    response.metadata.recursion_available = true;
    response.metadata.response_code = response_code;
    response
}

#[async_trait]
pub trait DnsHandlerTrait: Send + Sync {
    async fn handle_query(&self, query: &[u8], src: std::net::SocketAddr) -> Result<Vec<u8>>;
    fn name(&self) -> &'static str;
}

#[async_trait]
impl DnsHandlerTrait for DnsHandler {
    async fn handle_query(&self, query: &[u8], _src: std::net::SocketAddr) -> Result<Vec<u8>> {
        if let Some([questions, answers, authorities, additionals]) = dns_section_counts(query) {
            if questions != 1 {
                return Err(Error::Protocol(format!(
                    "Expected exactly one DNS query, got {questions}"
                )));
            }
            if answers != 0 || authorities != 0 || additionals != 0 {
                return Err(Error::Protocol(
                    "DNS query contains unexpected resource record sections".into(),
                ));
            }
        }

        let message = safe_message_from_vec(query)
            .ok_or_else(|| Error::Protocol("DNS message parse failed or panicked".into()))?;
        if message.metadata.message_type != hickory_proto::op::MessageType::Query
            || message.metadata.op_code != OpCode::Query
        {
            return Err(Error::Protocol(
                "DNS message is not a standard query".into(),
            ));
        }

        if message.queries.len() != 1 {
            return Err(Error::Protocol(format!(
                "Expected exactly one DNS query, got {}",
                message.queries.len()
            )));
        }
        if !message.answers.is_empty()
            || !message.authorities.is_empty()
            || !message.additionals.is_empty()
        {
            return Err(Error::Protocol(
                "DNS query contains unexpected resource record sections".into(),
            ));
        }
        let query = message
            .queries
            .first()
            .ok_or_else(|| Error::Protocol("No query in message".into()))?;

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
            let mut response = dns_response(message.metadata.id, ResponseCode::NoError);
            response.add_query(query.clone());

            if query_type == RecordType::A {
                let record = Record::from_rdata(
                    query.name().clone(),
                    self.response_config.default_ttl,
                    RData::A(hickory_proto::rr::rdata::A(ncsi_ip)),
                );
                response.add_answer(record);
            }

            let response_bytes = response
                .to_vec()
                .map_err(|e| Error::Protocol(e.to_string()))?;
            return Ok(response_bytes);
        }

        // NXDomains: NXDOMAIN the first N A-record queries so malware can cycle
        // through its backup C2 list, then answer every subsequent query.
        if self.nxdomains_threshold > 0 && query_type == RecordType::A {
            let mut count = self.nxdomains_count.write();
            if *count < self.nxdomains_threshold {
                *count += 1;
                let mut response = dns_response(message.metadata.id, ResponseCode::NXDomain);
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
    ) -> Result<Message> {
        let mut response = dns_response(original_message.metadata.id, ResponseCode::NoError);
        response.add_query(query.clone());

        let custom_ips = self.custom_response_for_domain(domain);

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
        domain: &str,
        custom_ips: Option<Vec<String>>,
        name: &Name,
    ) -> Result<Vec<Record>> {
        let ips = if let Some(custom) = custom_ips {
            parse_custom_response_ips(domain, custom)?
        } else if let Some(ref default_ip) = self.default_response_ip {
            vec![default_ip.parse::<std::net::IpAddr>().map_err(|e| {
                Error::Config(format!(
                    "Invalid default DNS A response IP '{}': {}",
                    default_ip, e
                ))
            })?]
        } else if self.wildcard_response {
            vec![std::net::IpAddr::V4(self.response_config.wildcard_ip)]
        } else {
            vec![]
        };

        Ok(ips
            .into_iter()
            .filter_map(|ip| {
                if let std::net::IpAddr::V4(v4) = ip {
                    let record = Record::from_rdata(
                        name.clone(),
                        self.response_config.default_ttl,
                        RData::A(hickory_proto::rr::rdata::A(v4)),
                    );
                    Some(record)
                } else {
                    None
                }
            })
            .collect())
    }

    fn custom_response_for_domain(&self, domain: &str) -> Option<Vec<String>> {
        let domain_key = normalize_domain_key(domain);
        if domain_key.is_empty() {
            return None;
        }

        let custom_responses = self.custom_responses.read();
        if let Some(ips) = custom_responses.get(&domain_key) {
            return Some(ips.clone());
        }

        let query_labels: Vec<_> = domain_key.split('.').collect();
        let mut best_match: Option<(&String, &Vec<String>, usize)> = None;
        for (pattern, ips) in custom_responses.iter() {
            let Some(wildcard_count) = wildcard_domain_match_score(pattern, &query_labels) else {
                continue;
            };

            if best_match.is_none_or(|(best_pattern, _, best_wildcards)| {
                wildcard_count < best_wildcards
                    || (wildcard_count == best_wildcards && pattern < best_pattern)
            }) {
                best_match = Some((pattern, ips, wildcard_count));
            }
        }

        best_match.map(|(_, ips, _)| ips.clone())
    }

    fn build_aaaa_records(
        &self,
        domain: &str,
        custom_ips: Option<Vec<String>>,
        name: &Name,
    ) -> Result<Vec<Record>> {
        let ips = if let Some(custom) = custom_ips {
            parse_custom_response_ips(domain, custom)?
        } else if let Some(ref default_ip) = self.default_response_ip {
            vec![default_ip.parse::<std::net::IpAddr>().map_err(|e| {
                Error::Config(format!(
                    "Invalid default DNS AAAA response IP '{}': {}",
                    default_ip, e
                ))
            })?]
        } else if self.wildcard_response {
            vec![std::net::IpAddr::V6(self.response_config.wildcard_ipv6)]
        } else {
            vec![]
        };

        Ok(ips
            .into_iter()
            .filter_map(|ip| {
                if let std::net::IpAddr::V6(v6) = ip {
                    let record = Record::from_rdata(
                        name.clone(),
                        self.response_config.default_ttl,
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
        let exchange_name = if let Some(ref mx) = self.default_response_mx {
            if Name::from_utf8(mx).is_err() {
                return Err(Error::Config(format!(
                    "Invalid default DNS MX exchange name '{}'",
                    mx
                )));
            }
            mx.clone()
        } else if self.wildcard_response {
            if domain == "." {
                "mail.".to_string()
            } else {
                format!("mail.{}", domain)
            }
        } else {
            return Ok(vec![]);
        };
        let exchange = Name::from_utf8(&exchange_name).map_err(|e| {
            Error::Config(format!(
                "Invalid DNS MX exchange name '{}': {}",
                exchange_name, e
            ))
        })?;
        let mx = hickory_proto::rr::rdata::MX::new(10, exchange);
        let record = Record::from_rdata(
            name.clone(),
            self.response_config.default_ttl,
            RData::MX(mx),
        );
        Ok(vec![record])
    }

    fn build_txt_records(&self, _domain: &str, name: &Name) -> Result<Vec<Record>> {
        let txt_value = if let Some(ref txt) = self.default_response_txt {
            txt.clone()
        } else if self.wildcard_response {
            "v=spf1 +a +mx ~all".to_string()
        } else {
            return Ok(vec![]);
        };
        let txt = hickory_proto::rr::rdata::TXT::new(split_txt_character_strings(&txt_value));
        let record = Record::from_rdata(
            name.clone(),
            self.response_config.default_ttl,
            RData::TXT(txt),
        );
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
                self.response_config.default_ttl,
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
        let target = NETTRAP_LOCAL.clone();
        let cname = hickory_proto::rr::rdata::CNAME(target);
        let record = Record::from_rdata(
            name.clone(),
            self.response_config.default_ttl,
            RData::CNAME(cname),
        );
        Ok(vec![record])
    }

    fn build_soa_records(&self, name: &Name) -> Result<Vec<Record>> {
        if !self.wildcard_response {
            return Ok(vec![]);
        }
        let mname = NS1_NETTRAP_LOCAL.clone();
        let rname = ADMIN_NETTRAP_LOCAL.clone();
        let soa = hickory_proto::rr::rdata::SOA::new(
            mname,
            rname,
            current_soa_serial_at((self.now)().date_naive()),
            3600,   // refresh
            900,    // retry
            604800, // expire
            self.response_config.default_ttl,
        );
        let record = Record::from_rdata(
            name.clone(),
            self.response_config.default_ttl,
            RData::SOA(soa),
        );
        Ok(vec![record])
    }
}

fn parse_custom_response_ips(domain: &str, ips: Vec<String>) -> Result<Vec<std::net::IpAddr>> {
    ips.into_iter()
        .map(|ip| {
            ip.parse::<std::net::IpAddr>().map_err(|err| {
                Error::Config(format!(
                    "Invalid DNS custom response for domain '{}': invalid IP '{}': {}",
                    domain, ip, err
                ))
            })
        })
        .collect()
}

fn wildcard_domain_match_score(pattern: &str, query_labels: &[&str]) -> Option<usize> {
    let pattern_labels: Vec<_> = pattern.split('.').collect();
    if pattern_labels.len() != query_labels.len() {
        return None;
    }

    let mut wildcard_count = 0usize;
    for (pattern_label, query_label) in pattern_labels.iter().zip(query_labels) {
        if *pattern_label == "*" {
            wildcard_count += 1;
            continue;
        }
        if pattern_label != query_label {
            return None;
        }
    }

    (wildcard_count > 0).then_some(wildcard_count)
}

fn normalize_domain_key(domain: &str) -> String {
    if domain.is_empty()
        || domain.chars().next().is_some_and(char::is_whitespace)
        || domain.chars().last().is_some_and(char::is_whitespace)
        || nettrap_core::sanitize::contains_unicode_line_separator(domain)
    {
        return String::new();
    }

    let candidate = if let Some(candidate) = domain.strip_suffix('.') {
        if candidate.is_empty() {
            return ".".to_string();
        }
        if candidate.ends_with('.') {
            return String::new();
        }
        candidate
    } else {
        domain
    };
    if Name::from_utf8(candidate).is_err() {
        return String::new();
    }

    candidate.to_ascii_lowercase()
}

fn current_soa_serial_at(date: chrono::NaiveDate) -> u32 {
    soa_serial_for_date(date)
}

fn soa_serial_for_date(date: chrono::NaiveDate) -> u32 {
    use chrono::Datelike;

    if date.year() < 1970 {
        return 1970010101;
    }

    let Ok(year) = u64::try_from(date.year()) else {
        return 1970010101;
    };
    let serial =
        year * 1_000_000 + u64::from(date.month()) * 10_000 + u64::from(date.day()) * 100 + 1;
    u32::try_from(serial).unwrap_or(u32::MAX)
}

fn normalize_dns_ip(value: &str) -> Option<String> {
    let candidate = value;
    if candidate.is_empty() {
        return None;
    }
    if candidate.chars().next().is_some_and(char::is_whitespace)
        || candidate.chars().last().is_some_and(char::is_whitespace)
        || nettrap_core::sanitize::contains_unicode_line_separator(candidate)
    {
        return None;
    }
    let ip = candidate.parse::<std::net::IpAddr>().ok()?;
    if !is_usable_dns_response_ip(&ip) {
        return None;
    }
    canonical_dns_response_ip(ip)
}

fn normalize_dns_name(value: &str) -> Option<String> {
    let candidate = value;
    if candidate.is_empty() {
        return None;
    }
    if candidate.chars().next().is_some_and(char::is_whitespace)
        || candidate.chars().last().is_some_and(char::is_whitespace)
        || nettrap_core::sanitize::contains_unicode_line_separator(candidate)
    {
        return None;
    }
    let candidate = if let Some(candidate) = candidate.strip_suffix('.') {
        if candidate.is_empty() || candidate.ends_with('.') {
            return None;
        }
        candidate
    } else {
        candidate
    };
    if candidate.parse::<std::net::IpAddr>().is_ok()
        || nettrap_core::sanitize::has_numeric_domain_labels(candidate)
    {
        return None;
    }
    Name::from_utf8(candidate).ok().map(|name| name.to_utf8())
}

fn normalize_dns_query_domain(value: &str) -> Option<String> {
    let candidate = if let Some(candidate) = value.strip_suffix('.') {
        if candidate.is_empty() || candidate.ends_with('.') {
            return if candidate.is_empty() {
                Some(".".to_string())
            } else {
                None
            };
        }
        candidate
    } else {
        value
    };
    if nettrap_core::sanitize::contains_unicode_line_separator(candidate) {
        return None;
    }
    Name::from_utf8(candidate)
        .ok()
        .map(|name| name.to_utf8().trim_end_matches('.').to_ascii_lowercase())
}

fn normalize_dns_txt(value: &str) -> Result<String> {
    let candidate = value;
    if candidate.is_empty() {
        return Err(Error::Config(
            "Invalid default DNS TXT response: value is empty".to_string(),
        ));
    }
    if candidate.chars().next().is_some_and(char::is_whitespace)
        || candidate.chars().last().is_some_and(char::is_whitespace)
    {
        return Err(Error::Config(format!(
            "Invalid default DNS TXT response '{}': surrounding whitespace is not allowed",
            candidate
        )));
    }
    if contains_unsafe_dns_txt_chars(candidate) {
        return Err(Error::Config(format!(
            "Invalid default DNS TXT response '{}': contains unsafe control characters",
            candidate
        )));
    }

    if candidate.len() > DNS_DEFAULT_RESPONSE_TXT_MAX_BYTES {
        return Err(Error::Config(format!(
            "Default DNS TXT response exceeds size limit ({} > {} bytes)",
            candidate.len(),
            DNS_DEFAULT_RESPONSE_TXT_MAX_BYTES
        )));
    }

    Ok(candidate.to_string())
}

fn contains_unsafe_dns_txt_chars(text: &str) -> bool {
    text.chars()
        .any(|ch| ch.is_control() || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
}

fn split_txt_character_strings(value: &str) -> Vec<String> {
    if value.is_empty() {
        return vec![String::new()];
    }

    let mut chunks = Vec::new();
    let mut current = String::new();
    for ch in value.chars() {
        let ch_len = ch.len_utf8();
        if !current.is_empty()
            && current.len().saturating_add(ch_len) > DNS_TXT_CHARACTER_STRING_MAX_BYTES
        {
            chunks.push(current);
            current = String::new();
        }
        current.push(ch);
    }
    if !current.is_empty() {
        chunks.push(current);
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_message_from_vec_rejects_unsupported_sections_before_parsing() {
        let fuzz_regression = [
            0x3d, 0x00, 0x2c, 0x2e, 0x00, 0x00, 0xd4, 0x00, 0x01, 0x12, 0x00, 0x00,
        ];

        assert!(safe_message_from_vec(&fuzz_regression).is_none());
    }

    #[test]
    fn default_response_ip_rejects_invalid_values() {
        let err = match DnsHandler::new().with_default_response_ip("not-an-ip") {
            Ok(_) => panic!("invalid default DNS response IP should fail"),
            Err(err) => err,
        };

        assert!(
            matches!(err, Error::Config(message) if message.contains("Invalid default DNS response IP"))
        );
    }

    #[test]
    fn default_response_ip_rejects_unspecified_values() {
        for ip in ["0.0.0.0", "::", "::ffff:0.0.0.0"] {
            let err = match DnsHandler::new().with_default_response_ip(ip) {
                Ok(_) => panic!("unspecified default DNS response IP should fail"),
                Err(err) => err,
            };

            assert!(
                matches!(err, Error::Config(ref message) if message.contains("Invalid default DNS response IP")),
                "unexpected error for {ip}: {err}"
            );
        }
    }

    #[test]
    fn default_response_ip_rejects_unusable_special_values() {
        for ip in [
            "127.0.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:255.255.255.255",
        ] {
            let err = match DnsHandler::new().with_default_response_ip(ip) {
                Ok(_) => panic!("special default DNS response IP should fail"),
                Err(err) => err,
            };

            assert!(
                matches!(err, Error::Config(ref message) if message.contains("Invalid default DNS response IP")),
                "unexpected error for {ip}: {err}"
            );
        }
    }

    #[test]
    fn auto_response_ip_uses_usable_address_filter() {
        for ip in [
            "127.0.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
        ] {
            let parsed = ip
                .parse::<std::net::IpAddr>()
                .expect("test IP should parse");
            assert!(
                !is_usable_dns_response_ip(&parsed),
                "special IP should be rejected: {ip}"
            );
        }
    }

    #[test]
    fn auto_response_ip_canonicalizes_ipv4_mapped_literals() {
        let ip = std::net::IpAddr::V6(
            "::ffff:192.0.2.10"
                .parse::<std::net::Ipv6Addr>()
                .expect("test IP should parse"),
        );

        assert_eq!(
            canonical_dns_response_ip(ip),
            Some("192.0.2.10".to_string())
        );
    }

    #[test]
    fn auto_response_ip_falls_back_to_ipv6_probe_when_ipv4_probe_fails() {
        let mut seen = Vec::new();
        let detected = auto_detect_default_response_ip_with_probe(|bind_addr, connect_addr| {
            seen.push((bind_addr.to_string(), connect_addr.to_string()));
            match bind_addr {
                "0.0.0.0:0" => None,
                "[::]:0" => Some(
                    "::ffff:203.0.113.10"
                        .parse::<std::net::IpAddr>()
                        .expect("test IP should parse"),
                ),
                _ => None,
            }
        });

        assert_eq!(detected, Some("203.0.113.10".to_string()));
        assert_eq!(
            seen,
            vec![
                ("0.0.0.0:0".to_string(), "8.8.8.8:53".to_string()),
                (
                    "[::]:0".to_string(),
                    "[2001:4860:4860::8888]:53".to_string()
                ),
            ]
        );
    }

    #[test]
    fn ncsi_response_ip_rejects_unspecified_values() {
        for ip in [
            std::net::Ipv4Addr::UNSPECIFIED,
            std::net::Ipv4Addr::LOCALHOST,
            std::net::Ipv4Addr::new(255, 255, 255, 255),
            std::net::Ipv4Addr::new(224, 0, 0, 1),
        ] {
            let err = match DnsHandler::new().with_ncsi_response_ip(ip) {
                Ok(_) => panic!("special NCSI response IP should fail"),
                Err(err) => err,
            };

            assert!(
                matches!(err, Error::Config(ref message) if message.contains("Invalid NCSI response IP")),
                "unexpected error for {ip}: {err}"
            );
        }
    }

    #[test]
    fn default_response_mx_rejects_invalid_values() {
        let err = match DnsHandler::new().with_default_response_mx("bad mx name") {
            Ok(_) => panic!("invalid default DNS MX should fail"),
            Err(err) => err,
        };

        assert!(
            matches!(err, Error::Config(message) if message.contains("Invalid default DNS MX exchange name"))
        );
    }

    #[test]
    fn default_response_mx_rejects_numeric_hostnames() {
        for mx in ["12345", "192.0.2.10", "0.0.0.0"] {
            let err = match DnsHandler::new().with_default_response_mx(mx) {
                Ok(_) => panic!("numeric MX hostname should fail"),
                Err(err) => err,
            };

            assert!(
                matches!(err, Error::Config(ref message) if message.contains("Invalid default DNS MX exchange name")),
                "unexpected error for {mx}: {err}"
            );
        }
    }

    #[test]
    fn default_response_txt_rejects_invalid_values() {
        let err = match DnsHandler::new().with_default_response_txt(" payload") {
            Ok(_) => panic!("default DNS TXT with surrounding whitespace should fail"),
            Err(err) => err,
        };

        assert!(
            matches!(err, Error::Config(message) if message.contains("surrounding whitespace"))
        );
    }

    #[test]
    fn default_response_txt_rejects_control_bytes() {
        let err = match DnsHandler::new().with_default_response_txt("line1\nline2") {
            Ok(_) => panic!("default DNS TXT with control bytes should fail"),
            Err(err) => err,
        };

        assert!(
            matches!(err, Error::Config(message) if message.contains("unsafe control characters"))
        );
    }

    #[test]
    fn add_custom_response_rejects_empty_ip_list() {
        let handler = DnsHandler::new();

        let err = handler
            .add_custom_response("example.com.", Vec::new())
            .expect_err("empty custom response must fail");

        assert!(
            matches!(err, Error::Config(message) if message.contains("at least one IP is required"))
        );
    }

    #[test]
    fn add_custom_response_rejects_oversized_ip_list() {
        let handler = DnsHandler::new();
        let ips = (0..=MAX_DNS_CUSTOM_RESPONSE_IPS)
            .map(|idx| format!("192.0.2.{}", idx + 1))
            .collect();

        let err = handler
            .add_custom_response("example.com.", ips)
            .expect_err("oversized custom response must fail");

        assert!(matches!(err, Error::Config(message) if message.contains("too many IPs")));
    }

    #[test]
    fn add_custom_response_rejects_oversized_domain_map() {
        let handler = DnsHandler::new();
        for idx in 0..MAX_DNS_CUSTOM_RESPONSE_DOMAINS {
            handler
                .add_custom_response(format!("host{idx}.example."), vec!["10.0.0.1".to_string()])
                .expect("custom response within domain limit should be accepted");
        }

        let err = handler
            .add_custom_response("overflow.example.", vec!["10.0.0.1".to_string()])
            .expect_err("oversized custom response map must fail");

        assert!(
            matches!(err, Error::Config(message) if message.contains("too many custom domains"))
        );
    }

    #[test]
    fn add_custom_response_allows_update_at_domain_limit() {
        let handler = DnsHandler::new();
        for idx in 0..MAX_DNS_CUSTOM_RESPONSE_DOMAINS {
            handler
                .add_custom_response(format!("host{idx}.example."), vec!["10.0.0.1".to_string()])
                .expect("custom response within domain limit should be accepted");
        }

        handler
            .add_custom_response("host0.example.", vec!["10.0.0.2".to_string()])
            .expect("updating existing domain should not require a new map slot");
    }

    #[test]
    fn add_custom_response_rejects_invalid_domain() {
        let handler = DnsHandler::new();

        for domain in [
            " example.com.",
            "bad name.example.",
            "-bad.example.",
            "bad_label.example.",
        ] {
            let err = handler
                .add_custom_response(domain, vec!["10.0.0.1".to_string()])
                .expect_err("invalid custom response domain must fail");

            assert!(
                matches!(err, Error::Config(message) if message.contains("Invalid DNS custom response domain"))
            );
        }
    }

    #[test]
    fn add_custom_response_accepts_root_domain() {
        let handler = DnsHandler::new();

        handler
            .add_custom_response(".", vec!["10.0.0.1".to_string()])
            .expect("root custom response should validate");

        assert_eq!(
            handler.custom_response_for_domain("."),
            Some(vec!["10.0.0.1".to_string()])
        );
    }

    #[test]
    fn custom_response_for_domain_matches_wildcard_label() {
        let handler = DnsHandler::new();
        handler
            .add_custom_response("*.example.com.", vec!["10.0.0.1".to_string()])
            .expect("wildcard custom response should validate");

        assert_eq!(
            handler.custom_response_for_domain("www.example.com."),
            Some(vec!["10.0.0.1".to_string()])
        );
    }

    #[test]
    fn custom_response_for_domain_prefers_exact_match_over_wildcard() {
        let handler = DnsHandler::new();
        handler
            .add_custom_response("*.example.com.", vec!["10.0.0.1".to_string()])
            .expect("wildcard custom response should validate");
        handler
            .add_custom_response("www.example.com.", vec!["10.0.0.2".to_string()])
            .expect("exact custom response should validate");

        assert_eq!(
            handler.custom_response_for_domain("www.example.com."),
            Some(vec!["10.0.0.2".to_string()])
        );
    }

    #[test]
    fn custom_response_for_domain_requires_matching_wildcard_arity() {
        let handler = DnsHandler::new();
        handler
            .add_custom_response("*.example.com.", vec!["10.0.0.1".to_string()])
            .expect("wildcard custom response should validate");

        assert_eq!(
            handler.custom_response_for_domain("deep.www.example.com."),
            None
        );
    }

    #[test]
    fn build_a_records_rejects_invalid_custom_ip_state() {
        let handler = DnsHandler::new();
        let name = Name::from_utf8("example.com.").expect("valid name");

        let err = handler
            .build_a_records(
                "example.com.",
                Some(vec!["192.0.2.10".to_string(), "not-an-ip".to_string()]),
                &name,
            )
            .expect_err("invalid custom A state must fail closed");

        assert!(
            matches!(err, Error::Config(message) if message.contains("invalid IP 'not-an-ip'"))
        );
    }

    #[test]
    fn build_aaaa_records_rejects_invalid_custom_ip_state() {
        let handler = DnsHandler::new();
        let name = Name::from_utf8("example.com.").expect("valid name");

        let err = handler
            .build_aaaa_records(
                "example.com.",
                Some(vec!["2001:db8::10".to_string(), "not-an-ip".to_string()]),
                &name,
            )
            .expect_err("invalid custom AAAA state must fail closed");

        assert!(
            matches!(err, Error::Config(message) if message.contains("invalid IP 'not-an-ip'"))
        );
    }

    #[test]
    fn default_response_txt_rejects_oversized_values() {
        let err = match DnsHandler::new()
            .with_default_response_txt("a".repeat(DNS_DEFAULT_RESPONSE_TXT_MAX_BYTES + 1))
        {
            Ok(_) => panic!("oversized default DNS TXT should fail"),
            Err(err) => err,
        };

        assert!(matches!(err, Error::Config(message) if message.contains("exceeds size limit")));
    }

    #[test]
    fn response_config_controls_wildcard_addresses_and_ttl() {
        let handler = DnsHandler::new().with_response_config(DnsConfig {
            wildcard_ip: std::net::Ipv4Addr::new(10, 1, 2, 3),
            wildcard_ipv6: std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 42),
            default_ttl: 42,
        });
        let name = Name::from_utf8("example.com.").expect("valid name");

        let a_records = handler
            .build_a_records("example.com.", None, &name)
            .expect("wildcard A record should build");
        assert_eq!(a_records.len(), 1);
        assert_eq!(a_records[0].ttl, 42);
        assert!(matches!(
            &a_records[0].data,
            RData::A(hickory_proto::rr::rdata::A(v4))
                if *v4 == std::net::Ipv4Addr::new(10, 1, 2, 3)
        ));

        let aaaa_records = handler
            .build_aaaa_records("example.com.", None, &name)
            .expect("wildcard AAAA record should build");
        assert_eq!(aaaa_records.len(), 1);
        assert_eq!(aaaa_records[0].ttl, 42);
        assert!(matches!(
            &aaaa_records[0].data,
            RData::AAAA(hickory_proto::rr::rdata::AAAA(v6))
                if *v6 == std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 42)
        ));

        let soa_records = handler
            .build_soa_records(&name)
            .expect("SOA record should build");
        assert_eq!(soa_records.len(), 1);
        assert_eq!(soa_records[0].ttl, 42);
        assert!(matches!(
            &soa_records[0].data,
            RData::SOA(soa) if soa.minimum == 42
        ));
    }

    #[test]
    fn soa_serial_uses_supplied_date() {
        let date = chrono::NaiveDate::from_ymd_opt(2024, 1, 1).expect("valid date");

        assert_eq!(soa_serial_for_date(date), 2024010101);
    }

    #[test]
    fn soa_record_does_not_use_frozen_serial_placeholder() {
        let handler = DnsHandler::new();
        let name = Name::from_utf8("example.com.").expect("valid name");
        let soa_records = handler
            .build_soa_records(&name)
            .expect("SOA record should build");

        assert!(matches!(
            &soa_records[0].data,
            RData::SOA(soa) if soa.serial != 2024010101
        ));
    }

    #[test]
    fn soa_record_uses_injected_date_for_serial() {
        fn fixed_now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant")
        }

        let handler = DnsHandler::new().with_now(fixed_now);
        let name = Name::from_utf8("example.com.").expect("valid name");
        let soa_records = handler
            .build_soa_records(&name)
            .expect("SOA record should build");

        assert!(matches!(
            &soa_records[0].data,
            RData::SOA(soa) if soa.serial == 2024010101
        ));
    }

    #[test]
    fn soa_serial_for_date_before_unix_epoch_saturates_to_epoch_baseline() {
        let date = chrono::NaiveDate::from_ymd_opt(1969, 12, 31).expect("valid date");

        assert_eq!(soa_serial_for_date(date), 1970010101);
    }

    #[test]
    fn normalize_helpers_reject_leading_whitespace() {
        assert!(normalize_domain_key(" example.com.").is_empty());
        assert!(normalize_dns_ip(" 10.0.0.1").is_none());
        assert!(normalize_dns_name(" example.com.").is_none());
        assert!(normalize_dns_txt(" payload").is_err());
    }

    #[test]
    fn normalize_helpers_reject_unicode_line_separators() {
        assert!(normalize_domain_key("example\u{2028}.com.").is_empty());
        assert!(normalize_dns_name("example\u{2028}.com.").is_none());
        assert!(normalize_dns_txt("alpha\u{2028}beta").is_err());
    }

    #[test]
    fn normalize_domain_key_rejects_multiple_trailing_dots() {
        assert!(normalize_domain_key("example.com...").is_empty());
    }

    #[tokio::test]
    async fn handle_query_rejects_non_query_messages() {
        let handler = DnsHandler::new();
        let mut response_message =
            Message::new(1, hickory_proto::op::MessageType::Response, OpCode::Query);
        response_message.add_query(hickory_proto::op::Query::query(
            Name::from_utf8("example.com.").expect("valid name"),
            RecordType::A,
        ));
        let response_bytes = response_message
            .to_vec()
            .expect("response should serialize");

        let result = handler
            .handle_query(
                &response_bytes,
                "127.0.0.1:12345".parse().expect("valid socket addr"),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_query_rejects_non_query_opcodes() {
        let handler = DnsHandler::new();
        let mut status_message =
            Message::new(1, hickory_proto::op::MessageType::Query, OpCode::Status);
        status_message.add_query(hickory_proto::op::Query::query(
            Name::from_utf8("example.com.").expect("valid name"),
            RecordType::A,
        ));
        let status_bytes = status_message.to_vec().expect("status should serialize");

        let result = handler
            .handle_query(
                &status_bytes,
                "127.0.0.1:12345".parse().expect("valid socket addr"),
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handle_query_rejects_multiple_questions() {
        let handler = DnsHandler::new();
        let mut message = Message::new(1, hickory_proto::op::MessageType::Query, OpCode::Query);
        message.add_query(hickory_proto::op::Query::query(
            Name::from_utf8("example.com.").expect("valid name"),
            RecordType::A,
        ));
        message.add_query(hickory_proto::op::Query::query(
            Name::from_utf8("example.net.").expect("valid name"),
            RecordType::A,
        ));
        let bytes = message.to_vec().expect("query should serialize");

        let result = handler
            .handle_query(
                &bytes,
                "127.0.0.1:12345".parse().expect("valid socket addr"),
            )
            .await;

        assert!(
            matches!(result, Err(Error::Protocol(message)) if message.contains("Expected exactly one DNS query"))
        );
    }

    #[tokio::test]
    async fn handle_query_rejects_unexpected_resource_sections() {
        let handler = DnsHandler::new();
        let mut message = Message::new(1, hickory_proto::op::MessageType::Query, OpCode::Query);
        let name = Name::from_utf8("example.com.").expect("valid name");
        message.add_query(hickory_proto::op::Query::query(name.clone(), RecordType::A));
        message.add_answer(Record::from_rdata(
            name,
            60,
            RData::A(hickory_proto::rr::rdata::A(std::net::Ipv4Addr::new(
                192, 0, 2, 1,
            ))),
        ));
        let bytes = message.to_vec().expect("query should serialize");

        let result = handler
            .handle_query(
                &bytes,
                "127.0.0.1:12345".parse().expect("valid socket addr"),
            )
            .await;

        assert!(
            matches!(result, Err(Error::Protocol(message)) if message.contains("unexpected resource record sections"))
        );
    }

    #[tokio::test]
    async fn handle_query_answers_root_mx_without_invalid_exchange_error() {
        let handler = DnsHandler::new();
        let mut message = Message::new(1, hickory_proto::op::MessageType::Query, OpCode::Query);
        message.add_query(hickory_proto::op::Query::query(
            Name::from_utf8(".").expect("root name should parse"),
            RecordType::MX,
        ));
        let bytes = message.to_vec().expect("query should serialize");

        let response = handler
            .handle_query(
                &bytes,
                "127.0.0.1:12345".parse().expect("valid socket addr"),
            )
            .await
            .expect("root MX query should be answered");
        let response = Message::from_vec(&response).expect("response should parse");

        assert_eq!(response.answers.len(), 1);
    }
}

#[cfg(test)]
mod parse_query_summary_tests {
    use super::{normalize_dns_query_domain, parse_query_summary};
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    fn query_bytes(name: &str, rtype: RecordType) -> Vec<u8> {
        let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
        let q = Query::query(Name::from_utf8(name).unwrap(), rtype);
        message.add_query(q);
        message.to_vec().unwrap()
    }

    #[test]
    fn extracts_domain_and_type_without_trailing_dot() {
        let bytes = query_bytes("evil.example.com.", RecordType::A);
        let (domain, qtype) = parse_query_summary(&bytes).expect("parseable A query");
        assert_eq!(domain, "evil.example.com");
        assert_eq!(qtype, "A");
    }

    #[test]
    fn reports_non_a_record_types() {
        let bytes = query_bytes("mail.evil.test.", RecordType::MX);
        let (domain, qtype) = parse_query_summary(&bytes).expect("parseable MX query");
        assert_eq!(domain, "mail.evil.test");
        assert_eq!(qtype, "MX");
    }

    #[test]
    fn extracts_lowercased_domain_from_uppercase_query() {
        let bytes = query_bytes("EVIL.Example.COM.", RecordType::A);
        let (domain, qtype) = parse_query_summary(&bytes).expect("parseable uppercase query");
        assert_eq!(domain, "evil.example.com");
        assert_eq!(qtype, "A");
    }

    #[test]
    fn extracts_root_domain_from_query_summary() {
        let bytes = query_bytes(".", RecordType::MX);
        let (domain, qtype) = parse_query_summary(&bytes).expect("parseable root query");

        assert_eq!(domain, ".");
        assert_eq!(qtype, "MX");
    }

    #[test]
    fn rejects_multiple_trailing_dots_in_query_summary() {
        assert!(normalize_dns_query_domain("mail.evil.test...").is_none());
    }

    #[test]
    fn returns_none_for_non_dns_bytes() {
        assert!(parse_query_summary(b"not a dns packet at all").is_none());
    }

    #[test]
    fn returns_none_for_dns_response_messages() {
        let mut message = Message::new(0x1234, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            Name::from_utf8("evil.example.com.").unwrap(),
            RecordType::A,
        ));
        let bytes = message.to_vec().unwrap();

        assert!(parse_query_summary(&bytes).is_none());
    }
}
