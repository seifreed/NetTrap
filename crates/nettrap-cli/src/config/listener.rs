use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::host_filter::{
    HostRule, compile_host_rules, is_host_allowed_with_rules, is_loopback_host,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub port: u16,
    pub bind_address: String,
    pub enabled: bool,
    pub emulate_response: bool,
    pub response_delay_ms: u64,
    pub custom_response: Option<String>,
    pub protocol: nettrap_core::prelude::Protocol,
    // SSL/TLS support
    #[serde(default)]
    pub use_ssl: bool,
    // Hidden listener (accessible only via proxy)
    #[serde(default)]
    pub hidden: bool,
    // Process filtering
    #[serde(default)]
    pub process_whitelist: Vec<String>,
    #[serde(default)]
    pub process_blacklist: Vec<String>,
    // Host filtering
    #[serde(default)]
    pub host_whitelist: Vec<String>,
    #[serde(default)]
    pub host_blacklist: Vec<String>,
    #[serde(skip)]
    compiled_host_whitelist: Arc<Vec<HostRule>>,
    #[serde(skip)]
    compiled_host_blacklist: Arc<Vec<HostRule>>,
    #[serde(skip)]
    compiled_host_whitelist_source: Arc<Vec<String>>,
    #[serde(skip)]
    compiled_host_blacklist_source: Arc<Vec<String>>,
    // Custom response config
    #[serde(default)]
    pub webroot: Option<String>,
    #[serde(default)]
    pub ftproot: Option<String>,
    #[serde(default)]
    pub tftproot: Option<String>,
    // Banner customization
    #[serde(default)]
    pub banner: Option<String>,
    // Execute command on connection
    #[serde(default)]
    pub execute_cmd: Option<String>,
    // HTTP POST dumping
    #[serde(default)]
    pub dump_http_posts: bool,
    #[serde(default)]
    pub dump_http_posts_prefix: Option<String>,
    // Port range support (alternative to single port)
    #[serde(default)]
    pub port_range: Option<String>,
    // DNS-specific configuration
    #[serde(default)]
    pub dns_response_ip: Option<String>,
    #[serde(default)]
    pub dns_response_mx: Option<String>,
    #[serde(default)]
    pub dns_response_txt: Option<String>,
    #[serde(default)]
    pub dns_nxdomains: Option<u32>,
    // DNS response mode: "static", "auto", or "hostname"
    #[serde(default)]
    pub dns_response_mode: Option<String>,
    // HTTP Server version string
    #[serde(default)]
    pub server_version: Option<String>,
    // FTP PASV port range (e.g. "60000-60100")
    #[serde(default)]
    pub pasv_ports: Option<String>,
    // Timeout
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    // Maximum concurrent connections per listener (throttling)
    // Default: 100 connections to prevent resource exhaustion
    #[serde(default = "default_max_connections")]
    pub max_connections: Option<u32>,
    // Banner delay in milliseconds (for dummy/raw handlers)
    #[serde(default)]
    pub banner_delay_ms: u64,
}

fn default_timeout() -> u64 {
    30000
}
fn default_max_connections() -> Option<u32> {
    Some(100)
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
                53 | 67 | 68 | 69 | 123 | 137 | 138 | 161 | 162 | 514 | 1900 | 5353
            ) {
                tracing::debug!(
                    "Port {} auto-detected as UDP (well-known UDP port). Use with_protocol() to override.",
                    port
                );
                nettrap_core::prelude::Protocol::Udp
            } else {
                nettrap_core::prelude::Protocol::Tcp
            },
            use_ssl: false,
            hidden: false,
            process_whitelist: Vec::new(),
            process_blacklist: Vec::new(),
            host_whitelist: Vec::new(),
            host_blacklist: Vec::new(),
            compiled_host_whitelist: Arc::default(),
            compiled_host_blacklist: Arc::default(),
            compiled_host_whitelist_source: Arc::default(),
            compiled_host_blacklist_source: Arc::default(),
            webroot: None,
            ftproot: None,
            tftproot: None,
            banner: None,
            execute_cmd: None,
            dump_http_posts: false,
            dump_http_posts_prefix: None,
            port_range: None,
            dns_response_ip: None,
            dns_response_mx: None,
            dns_response_txt: None,
            dns_nxdomains: None,
            dns_response_mode: None,
            server_version: None,
            pasv_ports: None,
            timeout_ms: 30000,
            max_connections: Some(100),
            banner_delay_ms: 0,
        }
    }

    /// Expand port_range (e.g. "60000-60010") into individual ListenerConfigs
    pub fn expand_port_range(&self) -> Vec<ListenerConfig> {
        const MAX_PORT_RANGE: u16 = 1000;

        if let Some(ref range_str) = self.port_range {
            let mut seen_ports = std::collections::HashSet::new();
            let mut configs = Vec::new();
            for part in range_str.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    tracing::warn!(
                        "Empty port_range entry for listener {}, skipping",
                        self.name
                    );
                    continue;
                }

                if let Some((start_s, end_s)) = part.split_once('-') {
                    let Ok(start) = start_s.trim().parse::<u16>() else {
                        tracing::warn!(
                            "Invalid port range start '{}' for listener {}, skipping",
                            start_s.trim(),
                            self.name
                        );
                        continue;
                    };
                    let Ok(end) = end_s.trim().parse::<u16>() else {
                        tracing::warn!(
                            "Invalid port range end '{}' for listener {}, skipping",
                            end_s.trim(),
                            self.name
                        );
                        continue;
                    };
                    if start > end {
                        tracing::warn!(
                            "Port range '{}-{}' is inverted for listener {}, skipping",
                            start,
                            end,
                            self.name
                        );
                        continue;
                    }
                    if end - start >= MAX_PORT_RANGE {
                        tracing::warn!(
                            "Port range '{}-{}' exceeds max {} for listener {}, clamping",
                            start,
                            end,
                            MAX_PORT_RANGE,
                            self.name
                        );
                    }
                    let clamped_end = start.saturating_add(MAX_PORT_RANGE - 1).min(end);
                    for port in start..=clamped_end {
                        if !seen_ports.insert(port) {
                            tracing::warn!(
                                "Duplicate port {} in port_range for listener {}, skipping",
                                port,
                                self.name
                            );
                            continue;
                        }
                        let mut cfg = self.clone();
                        cfg.port = port;
                        cfg.port_range = None;
                        configs.push(cfg);
                    }
                } else if let Ok(port) = part.parse::<u16>() {
                    if !seen_ports.insert(port) {
                        tracing::warn!(
                            "Duplicate port {} in port_range for listener {}, skipping",
                            port,
                            self.name
                        );
                        continue;
                    }
                    let mut cfg = self.clone();
                    cfg.port = port;
                    cfg.port_range = None;
                    configs.push(cfg);
                } else {
                    tracing::warn!(
                        "Invalid port '{}' in port_range for listener {}, skipping",
                        part,
                        self.name
                    );
                }
            }

            if configs.len() > 1 {
                for cfg in &mut configs {
                    cfg.name = format!("{}_{}", self.name, cfg.port);
                }
            }

            if configs.is_empty() {
                tracing::warn!(
                    "No valid ports parsed from port_range '{}' for listener {}, skipping listener expansion",
                    range_str,
                    self.name
                );
            }

            return configs;
        }
        vec![self.clone()]
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

    pub fn ftp() -> Self {
        let mut config = Self::new("ftp", 21);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config
    }

    pub fn pop3() -> Self {
        let mut config = Self::new("pop3", 110);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config
    }

    pub fn irc() -> Self {
        let mut config = Self::new("irc", 6667);
        config.protocol = nettrap_core::prelude::Protocol::Tcp;
        config
    }

    pub fn tftp() -> Self {
        let mut config = Self::new("tftp", 69);
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
            .rsplit(|c| c == '/' || c == '\\')
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
    /// Format: "domain1=ip1,ip2;domain2=ip3"
    /// Invalid IPs are logged and skipped.
    pub fn parse_dns_custom_responses(&self) -> Vec<(String, Vec<String>)> {
        let mut result = Vec::new();
        if let Some(ref custom) = self.custom_response {
            for entry in custom.split(';') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                if let Some((domain, ips)) = entry.split_once('=') {
                    let ip_list: Vec<String> = ips
                        .split(',')
                        .filter_map(|s| {
                            let s = s.trim().to_string();
                            if s.parse::<std::net::IpAddr>().is_ok() {
                                Some(s)
                            } else {
                                tracing::warn!(
                                    "Invalid IP '{}' in DNS custom response for domain '{}', skipping",
                                    s,
                                    domain.trim()
                                );
                                None
                            }
                        })
                        .collect();
                    if !ip_list.is_empty() {
                        result.push((domain.trim().to_string(), ip_list));
                    }
                }
            }
        }
        result
    }

    /// Check if a host IP is allowed by this listener's filters
    pub fn is_host_allowed(&self, host: &str) -> bool {
        // Always allow loopback (including IPv4-mapped IPv6 variants)
        if is_loopback_host(host) {
            return true;
        }

        match self.compiled_host_rules() {
            Ok((whitelist, blacklist)) => is_host_allowed_with_rules(host, &whitelist, &blacklist),
            Err(err) => {
                tracing::warn!(
                    "Listener '{}': failed to evaluate host filters: {}",
                    self.name,
                    err
                );
                false
            }
        }
    }

    pub(crate) fn refresh_host_filters(&mut self) -> crate::Result<()> {
        self.compiled_host_whitelist =
            Arc::new(compile_host_rules(&self.host_whitelist).map_err(crate::Error::Config)?);
        self.compiled_host_blacklist =
            Arc::new(compile_host_rules(&self.host_blacklist).map_err(crate::Error::Config)?);
        self.compiled_host_whitelist_source = Arc::new(self.host_whitelist.clone());
        self.compiled_host_blacklist_source = Arc::new(self.host_blacklist.clone());
        Ok(())
    }

    fn compiled_host_rules(&self) -> crate::Result<(Vec<HostRule>, Vec<HostRule>)> {
        let whitelist = if self.host_whitelist.is_empty() {
            Vec::new()
        } else if self.compiled_host_whitelist_source.as_ref() == &self.host_whitelist {
            (*self.compiled_host_whitelist).clone()
        } else {
            compile_host_rules(&self.host_whitelist).map_err(crate::Error::Config)?
        };

        let blacklist = if self.host_blacklist.is_empty() {
            Vec::new()
        } else if self.compiled_host_blacklist_source.as_ref() == &self.host_blacklist {
            (*self.compiled_host_blacklist).clone()
        } else {
            compile_host_rules(&self.host_blacklist).map_err(crate::Error::Config)?
        };

        Ok((whitelist, blacklist))
    }
}

#[cfg(test)]
mod tests {
    use super::ListenerConfig;

    #[test]
    fn expand_port_range_renames_multiple_single_ports() {
        let mut config = ListenerConfig::new("http", 80);
        config.port_range = Some("80,81".to_string());

        let expanded = config.expand_port_range();
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

        let expanded = config.expand_port_range();
        assert_eq!(expanded.len(), 1);
        assert_eq!(expanded[0].name, "http");
        assert_eq!(expanded[0].port, 80);
    }

    #[test]
    fn expand_port_range_deduplicates_repeated_ports() {
        let mut config = ListenerConfig::new("http", 80);
        config.port_range = Some("80-81,81,80".to_string());

        let expanded = config.expand_port_range();
        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[0].name, "http_80");
        assert_eq!(expanded[1].name, "http_81");
    }

    #[test]
    fn expand_port_range_fails_closed_when_all_entries_are_invalid() {
        let mut config = ListenerConfig::new("http", 80);
        config.port_range = Some("abc,100-bad".to_string());

        let expanded = config.expand_port_range();
        assert!(expanded.is_empty());
    }

    #[test]
    fn expand_port_range_keeps_valid_ports_when_mixed_with_invalid_entries() {
        let mut config = ListenerConfig::new("http", 80);
        config.port_range = Some("80,abc".to_string());

        let expanded = config.expand_port_range();
        assert_eq!(expanded.len(), 1);
        assert_eq!(expanded[0].name, "http");
        assert_eq!(expanded[0].port, 80);
    }

    #[test]
    fn host_filters_support_cidr_ranges() {
        let mut config = ListenerConfig::new("http", 80);
        config.host_whitelist = vec!["10.0.0.0/8".to_string()];
        config
            .refresh_host_filters()
            .expect("cidr whitelist should compile");

        assert!(config.is_host_allowed("10.1.2.3"));
        assert!(!config.is_host_allowed("192.168.1.10"));

        config.host_whitelist.clear();
        config.host_blacklist = vec!["192.168.0.0/16".to_string()];
        config
            .refresh_host_filters()
            .expect("cidr blacklist should compile");

        assert!(!config.is_host_allowed("192.168.1.10"));
        assert!(config.is_host_allowed("10.1.2.3"));
    }

    #[test]
    fn host_filters_use_compiled_hostname_snapshot() {
        let mut config = ListenerConfig::new("http", 80);
        config.host_whitelist = vec!["localhost".to_string()];
        config
            .refresh_host_filters()
            .expect("localhost should resolve during refresh");

        assert!(config.is_host_allowed("127.0.0.1"));
    }
}
