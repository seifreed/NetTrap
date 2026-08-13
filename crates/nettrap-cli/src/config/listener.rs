use serde::{Deserialize, Serialize};

use nettrap_core::sanitize::validate_dns_custom_response_domain;

const MAX_DNS_CUSTOM_RESPONSE_ENTRIES: usize = 256;
const MAX_DNS_CUSTOM_RESPONSE_IPS: usize = 32;

// `deny_unknown_fields` so a misspelled listener key (e.g. `webroott`,
// `process_blacklis`) is a hard config error instead of being silently ignored
// — a silently-dropped setting on a deception listener means missed captures.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub name: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub emulate_response: bool,
    #[serde(default)]
    pub response_delay_ms: u64,
    #[serde(default)]
    pub custom_response: Option<String>,
    #[serde(default = "default_protocol")]
    pub protocol: nettrap_core::prelude::Protocol,
    #[serde(default)]
    pub use_ssl: bool,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub process_whitelist: Vec<String>,
    #[serde(default)]
    pub process_blacklist: Vec<String>,
    #[serde(default)]
    pub host_whitelist: Vec<String>,
    #[serde(default)]
    pub host_blacklist: Vec<String>,
    #[serde(default)]
    pub webroot: Option<String>,
    #[serde(default)]
    pub ftproot: Option<String>,
    #[serde(default)]
    pub tftproot: Option<String>,
    #[serde(default)]
    pub banner: Option<String>,
    // Supports "!gethostname" and "!random" escapes.
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub execute_cmd: Option<String>,
    #[serde(default)]
    pub dump_http_posts: bool,
    #[serde(default)]
    pub dump_http_posts_prefix: Option<String>,
    #[serde(default)]
    pub port_range: Option<String>,
    #[serde(default)]
    pub dns_response_ip: Option<String>,
    #[serde(default)]
    pub dns_response_mx: Option<String>,
    #[serde(default)]
    pub dns_response_txt: Option<String>,
    #[serde(default)]
    pub dns_nxdomains: Option<u32>,
    #[serde(default)]
    pub dns_ncsi_response_ip: Option<String>,
    #[serde(default)]
    pub dns_response_mode: Option<String>,
    #[serde(default)]
    pub server_version: Option<String>,
    #[serde(default)]
    pub pasv_ports: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: Option<u32>,
    #[serde(default)]
    pub banner_delay_ms: u64,
}

fn default_timeout() -> u64 {
    30000
}
fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}
fn default_true() -> bool {
    true
}
fn default_protocol() -> nettrap_core::prelude::Protocol {
    nettrap_core::prelude::Protocol::Tcp
}
fn default_max_connections() -> Option<u32> {
    Some(100)
}

fn parse_unsigned_port(value: &str) -> Option<u16> {
    if value.trim_matches([' ', '\t']) != value
        || value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

impl ListenerConfig {
    pub fn new(name: impl Into<String>, port: u16) -> Self {
        Self {
            name: name.into(),
            port,
            bind_address: "0.0.0.0".to_string(),
            enabled: true,
            emulate_response: true,
            response_delay_ms: 0,
            custom_response: None,
            protocol: if matches!(
                port,
                53 | 67 | 68 | 69 | 123 | 137 | 138 | 161 | 162 | 514 | 1900 | 5353 | 5683 | 5684
            ) {
                tracing::debug!(
                    "Port {} auto-detected as UDP (well-known UDP port). Use with_protocol() to override.",
                    port
                );
                nettrap_core::prelude::Protocol::Udp
            } else {
                nettrap_core::prelude::Protocol::Tcp
            },
            use_ssl: matches!(
                port,
                443 | 465 | 636 | 853 | 990 | 992 | 993 | 994 | 995 | 6697 | 8443 | 8883 | 9443
            ),
            hidden: false,
            process_whitelist: Vec::new(),
            process_blacklist: Vec::new(),
            host_whitelist: Vec::new(),
            host_blacklist: Vec::new(),
            webroot: None,
            ftproot: None,
            tftproot: None,
            banner: None,
            server_name: None,
            execute_cmd: None,
            dump_http_posts: false,
            dump_http_posts_prefix: None,
            port_range: None,
            dns_response_ip: None,
            dns_response_mx: None,
            dns_response_txt: None,
            dns_nxdomains: None,
            dns_ncsi_response_ip: None,
            dns_response_mode: None,
            server_version: None,
            pasv_ports: None,
            timeout_ms: 30000,
            max_connections: Some(100),
            banner_delay_ms: 0,
        }
    }

    /// Parse one comma-split `port_range` segment into the inclusive port range
    /// it represents. Handles single ports ("8080") and ranges ("8000-8010")
    /// with the same validation as the inline form.
    fn parse_port_segment(
        &self,
        part: &str,
    ) -> crate::Result<Option<std::ops::RangeInclusive<u16>>> {
        const MAX_PORT_RANGE: u16 = 1000;

        let part = part.trim_matches([' ', '\t']);
        if part.is_empty() {
            return Err(crate::Error::Config(format!(
                "Listener '{}': empty port_range entry",
                self.name
            )));
        }

        if let Some((start_s, end_s)) = part.split_once('-') {
            let Some(start) = parse_unsigned_port(start_s) else {
                return Err(crate::Error::Config(format!(
                    "Listener '{}': invalid port range start '{}'",
                    self.name,
                    start_s.trim()
                )));
            };
            let Some(end) = parse_unsigned_port(end_s) else {
                return Err(crate::Error::Config(format!(
                    "Listener '{}': invalid port range end '{}'",
                    self.name,
                    end_s.trim()
                )));
            };
            if start > end {
                return Err(crate::Error::Config(format!(
                    "Listener '{}': port range '{}-{}' is inverted",
                    self.name, start, end
                )));
            }
            if start == 0 {
                return Err(crate::Error::Config(format!(
                    "Listener '{}': port_range must not include port 0",
                    self.name
                )));
            }
            if end - start >= MAX_PORT_RANGE {
                return Err(crate::Error::Config(format!(
                    "Listener '{}': port range '{}-{}' exceeds max {}",
                    self.name, start, end, MAX_PORT_RANGE
                )));
            }
            Ok(Some(start..=end))
        } else if let Some(port) = parse_unsigned_port(part) {
            if port == 0 {
                return Err(crate::Error::Config(format!(
                    "Listener '{}': port_range must not include port 0",
                    self.name
                )));
            }
            Ok(Some(port..=port))
        } else {
            Err(crate::Error::Config(format!(
                "Listener '{}': invalid port '{}'",
                self.name, part
            )))
        }
    }

    /// Expand port_range (e.g. "60000-60010") into individual ListenerConfigs
    pub fn expand_port_range(&self) -> crate::Result<Vec<ListenerConfig>> {
        let Some(ref range_str) = self.port_range else {
            return Ok(vec![self.clone()]);
        };

        let mut seen_ports = std::collections::HashSet::new();
        let mut configs = Vec::new();
        let mut push_port = |port: u16| {
            if !seen_ports.insert(port) {
                return Err(crate::Error::Config(format!(
                    "Listener '{}': duplicate port {} in port_range",
                    self.name, port
                )));
            }
            let mut cfg = self.clone();
            cfg.port = port;
            cfg.port_range = None;
            configs.push(cfg);
            Ok(())
        };

        for part in range_str.split(',') {
            if let Some(ports) = self.parse_port_segment(part)? {
                for port in ports {
                    push_port(port)?;
                }
            }
        }

        if configs.len() > 1 {
            for cfg in &mut configs {
                cfg.name = format!("{}_{}", self.name, cfg.port);
            }
        }

        if configs.is_empty() {
            return Err(crate::Error::Config(format!(
                "Listener '{}': no valid ports parsed from port_range '{}'",
                self.name, range_str
            )));
        }

        Ok(configs)
    }

    pub fn dns() -> Self {
        let mut config = Self::new("dns", 53);
        config.protocol = nettrap_core::prelude::Protocol::Udp;
        config
    }

    pub fn http() -> Self {
        let mut config = Self::new("http", 80);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config
    }

    pub fn https() -> Self {
        let mut config = Self::new("https", 443);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config.use_ssl = true;
        config
    }

    pub fn smtp() -> Self {
        let mut config = Self::new("smtp", 25);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config
    }

    pub fn smtps() -> Self {
        let mut config = Self::new("smtps", 465);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config.use_ssl = true;
        config
    }

    pub fn ftp() -> Self {
        let mut config = Self::new("ftp", 21);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config
    }

    pub fn ftps() -> Self {
        let mut config = Self::new("ftps", 990);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config.use_ssl = true;
        config
    }

    pub fn pop3() -> Self {
        let mut config = Self::new("pop3", 110);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config
    }

    pub fn pop3s() -> Self {
        let mut config = Self::new("pop3s", 995);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config.use_ssl = true;
        config
    }

    pub fn irc() -> Self {
        let mut config = Self::new("irc", 6667);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config
    }

    pub fn ircs() -> Self {
        let mut config = Self::new("ircs", 994);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config.use_ssl = true;
        config
    }

    pub fn imap() -> Self {
        let mut config = Self::new("imap", 143);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config
    }

    pub fn imaps() -> Self {
        let mut config = Self::new("imaps", 993);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config.use_ssl = true;
        config
    }

    pub fn ldap() -> Self {
        let mut config = Self::new("ldap", 389);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config
    }

    pub fn ldaps() -> Self {
        let mut config = Self::new("ldaps", 636);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config.use_ssl = true;
        config
    }

    pub fn tftp() -> Self {
        let mut config = Self::new("tftp", 69);
        config.protocol = nettrap_core::prelude::Protocol::Udp;
        config
    }

    pub fn quic() -> Self {
        let mut config = Self::new("quic", 443);
        config.protocol = nettrap_core::prelude::Protocol::Udp;
        config
    }

    pub fn with_bind_address(mut self, addr: impl Into<String>) -> Self {
        self.bind_address = addr.into();
        self
    }

    pub fn with_response_delay(mut self, delay_ms: u64) -> Self {
        self.response_delay_ms = delay_ms;
        self
    }

    pub fn with_custom_response(mut self, response: impl Into<String>) -> Self {
        self.custom_response = Some(response.into());
        self
    }

    pub fn with_protocol(mut self, protocol: nettrap_core::prelude::Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Check if a process name is allowed by this listener's filters.
    /// Matches the process basename (after last path separator) case-insensitively.
    pub fn is_process_allowed(&self, process_name: &str) -> bool {
        let basename = process_name
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(process_name)
            .to_lowercase();

        if !self.process_whitelist.is_empty() {
            return self
                .process_whitelist
                .iter()
                .any(|p| basename == p.to_lowercase());
        }
        if !self.process_blacklist.is_empty() {
            return !self
                .process_blacklist
                .iter()
                .any(|p| basename == p.to_lowercase());
        }
        true
    }

    /// Parse custom_response for DNS-specific domain-to-IP mappings.
    /// Format: "domain1=ip1,ip2;domain2=ip3".
    /// Returns an error when any entry is malformed or contains an invalid IP.
    pub fn parse_dns_custom_responses(&self) -> crate::Result<Vec<(String, Vec<String>)>> {
        fn has_unsafe_whitespace(value: &str) -> bool {
            value
                .chars()
                .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
        }

        let mut result = Vec::new();
        if let Some(ref custom) = self.custom_response {
            for entry in custom.split(';') {
                if entry.is_empty() {
                    return Err(crate::Error::Config(
                        "Invalid DNS custom response entry: domain must not be blank".to_string(),
                    ));
                }
                if entry.trim_matches([' ', '\t']) != entry {
                    return Err(crate::Error::Config(format!(
                        "Invalid DNS custom response entry '{}': invalid whitespace",
                        entry
                    )));
                }
                if result.len() >= MAX_DNS_CUSTOM_RESPONSE_ENTRIES {
                    return Err(crate::Error::Config(format!(
                        "Invalid DNS custom responses: too many entries (>{})",
                        MAX_DNS_CUSTOM_RESPONSE_ENTRIES
                    )));
                }
                if has_unsafe_whitespace(entry) {
                    return Err(crate::Error::Config(format!(
                        "Invalid DNS custom response entry '{}': contains unsupported whitespace",
                        entry
                    )));
                }
                let Some((domain, ips)) = entry.split_once('=') else {
                    return Err(crate::Error::Config(format!(
                        "Invalid DNS custom response entry '{}': expected domain=ip1,ip2",
                        entry
                    )));
                };
                if domain.trim_matches([' ', '\t']) != domain {
                    return Err(crate::Error::Config(format!(
                        "Invalid DNS custom response entry '{}': invalid whitespace in domain",
                        domain
                    )));
                }
                if domain.is_empty() {
                    return Err(crate::Error::Config(
                        "Invalid DNS custom response entry: domain must not be blank".to_string(),
                    ));
                }
                if has_unsafe_whitespace(domain) {
                    return Err(crate::Error::Config(format!(
                        "Invalid DNS custom response entry '{}': contains unsupported whitespace",
                        domain
                    )));
                }
                validate_dns_custom_response_domain(domain)?;

                let mut ip_list = Vec::new();
                for raw_ip in ips.split(',') {
                    if ip_list.len() >= MAX_DNS_CUSTOM_RESPONSE_IPS {
                        return Err(crate::Error::Config(format!(
                            "Invalid DNS custom response for domain '{}': too many IPs (>{})",
                            domain, MAX_DNS_CUSTOM_RESPONSE_IPS
                        )));
                    }
                    if raw_ip.trim_matches([' ', '\t']) != raw_ip || raw_ip.is_empty() {
                        return Err(crate::Error::Config(format!(
                            "Invalid DNS custom response for domain '{}': invalid whitespace in IP '{}'",
                            domain, raw_ip
                        )));
                    }
                    let ip = raw_ip;
                    if has_unsafe_whitespace(ip) {
                        return Err(crate::Error::Config(format!(
                            "Invalid DNS custom response for domain '{}': contains unsupported whitespace in IP '{}'",
                            domain, ip
                        )));
                    }
                    let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() else {
                        return Err(crate::Error::Config(format!(
                            "Invalid DNS custom response for domain '{}': invalid IP '{}'",
                            domain, ip
                        )));
                    };
                    if is_special_dns_custom_response_ip(&ip_addr) {
                        return Err(crate::Error::Config(format!(
                            "Invalid DNS custom response for domain '{}': invalid IP '{}'",
                            domain, ip
                        )));
                    }
                    let normalized_ip = match ip_addr {
                        std::net::IpAddr::V4(ip) => std::net::IpAddr::V4(ip),
                        std::net::IpAddr::V6(ip) => ip
                            .to_ipv4_mapped()
                            .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
                    };
                    ip_list.push(normalized_ip.to_string());
                }

                if ip_list.is_empty() {
                    return Err(crate::Error::Config(format!(
                        "Invalid DNS custom response for domain '{}': at least one IP is required",
                        domain
                    )));
                }
                result.push((domain.to_string(), ip_list));
            }
        }
        Ok(result)
    }
}

fn is_special_dns_custom_response_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()
        }
        std::net::IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.to_ipv4_mapped().is_some_and(|mapped| {
                    mapped.is_unspecified()
                        || mapped.is_loopback()
                        || mapped.is_multicast()
                        || mapped.is_broadcast()
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ListenerConfig, MAX_DNS_CUSTOM_RESPONSE_ENTRIES, MAX_DNS_CUSTOM_RESPONSE_IPS,
        parse_unsigned_port,
    };
    use nettrap_core::prelude::Protocol;

    #[test]
    fn deserializes_listener_with_only_port_range_and_no_port() {
        let toml = r#"
            name = "raw"
            port_range = "18200-18203"
            protocol = "tcp"
        "#;
        let config: ListenerConfig =
            toml::from_str(toml).expect("port_range-only listener should parse");
        assert_eq!(config.port, 0);
        assert_eq!(config.port_range.as_deref(), Some("18200-18203"));

        let expanded = config
            .expand_port_range()
            .expect("valid port_range should expand");
        assert_eq!(expanded.len(), 4);
        assert_eq!(expanded[0].port, 18200);
        assert_eq!(expanded[3].port, 18203);
    }

    #[test]
    fn new_auto_detects_udp_coap_ports() {
        assert_eq!(ListenerConfig::new("coap", 5683).protocol, Protocol::Udp);
        assert_eq!(ListenerConfig::new("coap", 5684).protocol, Protocol::Udp);
    }

    #[test]
    fn quic_constructor_uses_udp_on_port_443() {
        let quic = ListenerConfig::quic();
        assert_eq!(quic.name, "quic");
        assert_eq!(quic.port, 443);
        assert_eq!(quic.protocol, Protocol::Udp);
        assert!(quic.use_ssl);
    }

    #[test]
    fn ldap_constructors_use_expected_defaults() {
        let ldap = ListenerConfig::ldap();
        assert_eq!(ldap.name, "ldap");
        assert_eq!(ldap.port, 389);
        assert_eq!(ldap.protocol, Protocol::Tcp);
        assert!(!ldap.use_ssl);

        let ldaps = ListenerConfig::ldaps();
        assert_eq!(ldaps.name, "ldaps");
        assert_eq!(ldaps.port, 636);
        assert_eq!(ldaps.protocol, Protocol::Tcp);
        assert!(ldaps.use_ssl);
    }

    #[test]
    fn new_defaults_to_ssl_on_implicit_tls_ports() {
        assert!(ListenerConfig::new("https", 443).use_ssl);
        assert!(ListenerConfig::new("smtp", 465).use_ssl);
        assert!(ListenerConfig::new("ldap", 636).use_ssl);
        assert!(ListenerConfig::new("dns", 853).use_ssl);
        assert!(ListenerConfig::new("ftp", 990).use_ssl);
        assert!(ListenerConfig::new("telnet", 992).use_ssl);
        assert!(ListenerConfig::new("imap", 993).use_ssl);
        assert!(ListenerConfig::new("irc", 994).use_ssl);
        assert!(ListenerConfig::new("irc", 6697).use_ssl);
        assert!(ListenerConfig::new("pop3", 995).use_ssl);
        assert!(ListenerConfig::new("http-alt", 8443).use_ssl);
        assert!(ListenerConfig::new("mqtt", 8883).use_ssl);
        assert!(ListenerConfig::new("https-alt", 9443).use_ssl);
    }

    #[test]
    fn imap_constructors_use_expected_defaults() {
        let imap = ListenerConfig::imap();
        assert_eq!(imap.name, "imap");
        assert_eq!(imap.port, 143);
        assert_eq!(imap.protocol, Protocol::Tcp);
        assert!(!imap.use_ssl);

        let imaps = ListenerConfig::imaps();
        assert_eq!(imaps.name, "imaps");
        assert_eq!(imaps.port, 993);
        assert_eq!(imaps.protocol, Protocol::Tcp);
        assert!(imaps.use_ssl);
    }

    #[test]
    fn tls_alias_constructors_use_expected_defaults() {
        let smtps = ListenerConfig::smtps();
        assert_eq!(smtps.name, "smtps");
        assert_eq!(smtps.port, 465);
        assert_eq!(smtps.protocol, Protocol::Tcp);
        assert!(smtps.use_ssl);

        let ftps = ListenerConfig::ftps();
        assert_eq!(ftps.name, "ftps");
        assert_eq!(ftps.port, 990);
        assert_eq!(ftps.protocol, Protocol::Tcp);
        assert!(ftps.use_ssl);

        let pop3s = ListenerConfig::pop3s();
        assert_eq!(pop3s.name, "pop3s");
        assert_eq!(pop3s.port, 995);
        assert_eq!(pop3s.protocol, Protocol::Tcp);
        assert!(pop3s.use_ssl);

        let ircs = ListenerConfig::ircs();
        assert_eq!(ircs.name, "ircs");
        assert_eq!(ircs.port, 994);
        assert_eq!(ircs.protocol, Protocol::Tcp);
        assert!(ircs.use_ssl);
    }

    #[test]
    fn parse_dns_custom_responses_rejects_unicode_whitespace_padding() {
        let config = ListenerConfig::new("dns", 53)
            .with_custom_response("example.com\u{00a0}=1.1.1.1".to_string());

        let err = config
            .parse_dns_custom_responses()
            .expect_err("unicode whitespace should be rejected");

        assert!(err.to_string().contains("unsupported whitespace"));
    }

    #[test]
    fn parse_dns_custom_responses_rejects_ascii_padding() {
        let config = ListenerConfig::new("dns", 53)
            .with_custom_response("example.com =1.1.1.1;example.org= 1.1.1.2".to_string());

        let err = config
            .parse_dns_custom_responses()
            .expect_err("ascii whitespace should be rejected");

        assert!(err.to_string().contains("invalid whitespace"));
    }

    #[test]
    fn parse_dns_custom_responses_rejects_c1_controls() {
        let config = ListenerConfig::new("dns", 53)
            .with_custom_response("example.com\u{009f}=1.1.1.1".to_string());

        let err = config
            .parse_dns_custom_responses()
            .expect_err("C1 control in entry separator should be rejected");

        assert!(err.to_string().contains("unsupported whitespace"));
    }

    #[test]
    fn parse_dns_custom_responses_rejects_empty_entries() {
        let config = ListenerConfig::new("dns", 53)
            .with_custom_response("example.com=1.1.1.1;;other.example=2.2.2.2".to_string());

        let err = config
            .parse_dns_custom_responses()
            .expect_err("empty entry should fail");

        assert!(err.to_string().contains("domain must not be blank"));
    }

    #[test]
    fn parse_dns_custom_responses_rejects_invalid_domain_characters() {
        let config =
            ListenerConfig::new("dns", 53).with_custom_response("bad/domain=1.1.1.1".to_string());

        let err = config
            .parse_dns_custom_responses()
            .expect_err("invalid DNS custom response domain should fail");

        assert!(
            err.to_string()
                .contains("contains invalid label characters"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_unsigned_port_rejects_unicode_whitespace_padding() {
        assert_eq!(parse_unsigned_port("80\u{00a0}"), None);
    }

    #[test]
    fn parse_unsigned_port_rejects_ascii_padding() {
        assert_eq!(parse_unsigned_port(" 80"), None);
        assert_eq!(parse_unsigned_port("80 "), None);
    }

    #[test]
    fn expand_port_range_renames_multiple_single_ports() {
        let mut config = ListenerConfig::new("http", 80);
        config.port_range = Some("80,81".to_string());

        let expanded = config
            .expand_port_range()
            .expect("valid port_range should expand");
        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[0].name, "http_80");
        assert_eq!(expanded[0].port, 80);
        assert_eq!(expanded[1].name, "http_81");
        assert_eq!(expanded[1].port, 81);
    }

    #[test]
    fn expand_port_range_keeps_name_when_only_one_port_is_emitted() {
        let mut config = ListenerConfig::new("http", 80);
        config.port_range = Some("80".to_string());

        let expanded = config
            .expand_port_range()
            .expect("valid port_range should expand");
        assert_eq!(expanded.len(), 1);
        assert_eq!(expanded[0].name, "http");
        assert_eq!(expanded[0].port, 80);
    }

    #[test]
    fn expand_port_range_deduplicates_repeated_ports() {
        let mut config = ListenerConfig::new("http", 80);
        config.port_range = Some("80-81,81,80".to_string());

        let err = config
            .expand_port_range()
            .expect_err("duplicate ports should fail");
        assert!(
            err.to_string().contains("duplicate port"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn expand_port_range_fails_closed_when_all_entries_are_invalid() {
        let mut config = ListenerConfig::new("http", 80);
        config.port_range = Some("abc,100-bad".to_string());

        let err = config
            .expand_port_range()
            .expect_err("invalid port_range should fail");
        assert!(
            err.to_string().contains("invalid port"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn expand_port_range_rejects_signed_ports() {
        let mut config = ListenerConfig::new("http", 80);
        config.port_range = Some("+80,+100-+101,82".to_string());

        let err = config
            .expand_port_range()
            .expect_err("mixed invalid port_range should fail");
        assert!(
            err.to_string().contains("invalid port"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn expand_port_range_rejects_unicode_whitespace_padding() {
        let mut config = ListenerConfig::new("http", 80);
        config.port_range = Some("\u{00a0}80\u{00a0}".to_string());

        let err = config
            .expand_port_range()
            .expect_err("unicode whitespace should be rejected");
        assert!(err.to_string().contains("invalid port"));
    }

    #[test]
    fn expand_port_range_rejects_port_zero() {
        for range in ["0", "0-10"] {
            let mut config = ListenerConfig::new("http", 80);
            config.port_range = Some(range.to_string());

            let err = config
                .expand_port_range()
                .expect_err("port_range must reject port 0");
            assert!(
                err.to_string().contains("must not include port 0"),
                "{range}: {err}"
            );
        }
    }

    #[test]
    fn expand_port_range_keeps_valid_ports_when_mixed_with_invalid_entries() {
        let mut config = ListenerConfig::new("http", 80);
        config.port_range = Some("80,abc".to_string());

        let err = config
            .expand_port_range()
            .expect_err("mixed invalid port_range should fail");
        assert!(
            err.to_string().contains("invalid port"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn expand_port_range_rejects_ranges_that_exceed_limit() {
        let mut config = ListenerConfig::new("http", 80);
        config.port_range = Some("1000-3000".to_string());

        let err = config
            .expand_port_range()
            .expect_err("oversized port_range should fail closed");
        assert!(
            err.to_string().contains("exceeds max 1000"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_dns_custom_responses_rejects_invalid_ips() {
        let config = ListenerConfig::new("dns", 53)
            .with_custom_response("example.com=10.0.0.1,bad-ip;bad.example=also-bad");

        let err = config
            .parse_dns_custom_responses()
            .expect_err("invalid ip should fail");

        assert!(
            err.to_string().contains("invalid IP 'bad-ip'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_dns_custom_responses_rejects_unspecified_ips() {
        let config = ListenerConfig::new("dns", 53)
            .with_custom_response("example.com=0.0.0.0;ipv6=::;mapped=::ffff:0.0.0.0");

        let err = config
            .parse_dns_custom_responses()
            .expect_err("unspecified ip should fail");

        assert!(err.to_string().contains("invalid IP"));
    }

    #[test]
    fn parse_dns_custom_responses_rejects_special_ips() {
        let config = ListenerConfig::new("dns", 53).with_custom_response(
            "loopback=127.0.0.1;multicast=224.0.0.1;v6loop=::1;mapped=::ffff:127.0.0.1",
        );

        let err = config
            .parse_dns_custom_responses()
            .expect_err("special ips should fail");

        assert!(err.to_string().contains("invalid IP"));
    }

    #[test]
    fn parse_dns_custom_responses_canonicalizes_ipv4_mapped_ips() {
        let config = ListenerConfig::new("dns", 53)
            .with_custom_response("mapped=::ffff:192.0.2.10;mapped-port=::ffff:192.0.2.11");

        let responses = config
            .parse_dns_custom_responses()
            .expect("valid DNS custom response should parse");

        assert_eq!(responses[0].1, vec!["192.0.2.10".to_string()]);
        assert_eq!(responses[1].1, vec!["192.0.2.11".to_string()]);
    }

    #[test]
    fn parse_dns_custom_responses_rejects_empty_domains() {
        let config =
            ListenerConfig::new("dns", 53).with_custom_response("=10.0.0.1;example.com=10.0.0.2");

        let err = config
            .parse_dns_custom_responses()
            .expect_err("empty domain should fail");

        assert!(
            err.to_string().contains("domain must not be blank"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_dns_custom_responses_rejects_too_many_entries() {
        let custom_response = (0..=MAX_DNS_CUSTOM_RESPONSE_ENTRIES)
            .map(|idx| format!("host{idx}.example=10.0.0.1"))
            .collect::<Vec<_>>()
            .join(";");
        let config = ListenerConfig::new("dns", 53).with_custom_response(custom_response);

        let err = config
            .parse_dns_custom_responses()
            .expect_err("oversized DNS custom response map should fail");

        assert!(err.to_string().contains("too many entries"));
    }

    #[test]
    fn parse_dns_custom_responses_rejects_too_many_ips_per_entry() {
        let ips = (0..=MAX_DNS_CUSTOM_RESPONSE_IPS)
            .map(|idx| format!("192.0.2.{}", idx + 1))
            .collect::<Vec<_>>()
            .join(",");
        let config =
            ListenerConfig::new("dns", 53).with_custom_response(format!("example.com={ips}"));

        let err = config
            .parse_dns_custom_responses()
            .expect_err("oversized DNS custom response IP list should fail");

        assert!(err.to_string().contains("too many IPs"));
    }
}
