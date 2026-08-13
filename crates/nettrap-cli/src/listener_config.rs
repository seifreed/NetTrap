use std::path::PathBuf;

use crate::custom_response::CustomResponseConfig;
use nettrap_core::sanitize::validate_dns_custom_response_domain;

const MAX_DNS_CUSTOM_RESPONSE_ENTRIES: usize = 256;
const MAX_DNS_CUSTOM_RESPONSE_IPS: usize = 32;

/// DNS response mode configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsResponseMode {
    #[default]
    Static,
    Auto,
    Hostname,
}

impl std::fmt::Display for DnsResponseMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static => write!(f, "static"),
            Self::Auto => write!(f, "auto"),
            Self::Hostname => write!(f, "hostname"),
        }
    }
}

impl std::str::FromStr for DnsResponseMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim_matches([' ', '\t']);
        if trimmed != s
            || trimmed.is_empty()
            || trimmed
                .chars()
                .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
        {
            return Err(format!("Invalid DNS response mode: {}", s));
        }

        match trimmed.to_lowercase().as_str() {
            "static" => Ok(Self::Static),
            "auto" => Ok(Self::Auto),
            "hostname" | "gethostname" => Ok(Self::Hostname),
            _ => Err(format!("Invalid DNS response mode: {}", s)),
        }
    }
}

/// Immutable per-listener configuration.
///
/// Contains all configuration that comes from the config file or CLI args.
/// This is created once when the listener starts and never modified.
#[derive(Clone)]
pub struct ListenerConfig {
    pub name: String,
    pub port: u16,
    pub banner: Option<String>,
    /// Server name interpolated into `{servername}` banner tokens.
    /// Already resolved (`!gethostname`/`!random`).
    pub server_name: Option<String>,
    pub webroot: Option<String>,
    pub ftproot: Option<String>,
    pub tftproot: Option<String>,
    pub execute_cmd: Option<String>,
    pub use_ssl: bool,
    pub dump_http_posts: bool,
    pub dump_prefix: Option<String>,
    pub timeout_ms: u64,
    pub response_delay_ms: u64,
    pub custom_response: Option<String>,
    pub custom_response_config: Option<CustomResponseConfig>,
    pub server_version: Option<String>,
    /// Validated at construction time; None means default (Static).
    pub dns_response_mode: Option<String>,
    pub dns_response_ip: Option<String>,
    pub dns_response_mx: Option<String>,
    pub dns_response_txt: Option<String>,
    pub dns_nxdomains: Option<u32>,
    pub dns_ncsi_response_ip: Option<String>,
    pub pasv_ports: Option<String>,
    pub max_connections: Option<u32>,
    pub banner_delay_ms: u64,
    pub smtp_dir: Option<PathBuf>,
    pub log_hexdump: bool,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            port: 0,
            banner: None,
            server_name: None,
            webroot: None,
            ftproot: None,
            tftproot: None,
            execute_cmd: None,
            use_ssl: false,
            dump_http_posts: false,
            dump_prefix: None,
            timeout_ms: 30000,
            response_delay_ms: 0,
            custom_response: None,
            custom_response_config: None,
            server_version: None,
            dns_response_mode: None,
            dns_response_ip: None,
            dns_response_mx: None,
            dns_response_txt: None,
            dns_nxdomains: None,
            dns_ncsi_response_ip: None,
            pasv_ports: None,
            max_connections: Some(100),
            banner_delay_ms: 0,
            smtp_dir: None,
            log_hexdump: false,
        }
    }
}

impl ListenerConfig {
    /// Parse validated DNS custom responses from `custom_response`.
    ///
    /// Format: `domain=ip1,ip2;other.example=ip3`.
    /// Returns an error when any entry is malformed or contains an invalid IP.
    pub fn parse_dns_custom_responses(&self) -> crate::Result<Vec<(String, Vec<String>)>> {
        fn has_unsafe_whitespace(value: &str) -> bool {
            value
                .chars()
                .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
        }

        let Some(custom) = self.custom_response.as_deref() else {
            return Ok(Vec::new());
        };

        let mut result = Vec::new();
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
                if raw_ip.trim_matches([' ', '\t']) != raw_ip {
                    return Err(crate::Error::Config(format!(
                        "Invalid DNS custom response for domain '{}': invalid whitespace in IP '{}'",
                        domain, raw_ip
                    )));
                }
                let ip = raw_ip;
                if ip.is_empty() {
                    return Err(crate::Error::Config(format!(
                        "Invalid DNS custom response for domain '{}': IP must not be blank",
                        domain
                    )));
                }
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
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_dns_response_mode_from_str() {
        assert_eq!(
            DnsResponseMode::from_str("static").unwrap(),
            DnsResponseMode::Static
        );
        assert_eq!(
            DnsResponseMode::from_str("auto").unwrap(),
            DnsResponseMode::Auto
        );
        assert_eq!(
            DnsResponseMode::from_str("hostname").unwrap(),
            DnsResponseMode::Hostname
        );
        assert_eq!(
            DnsResponseMode::from_str("HOSTNAME").unwrap(),
            DnsResponseMode::Hostname
        );
        assert!(DnsResponseMode::from_str("invalid").is_err());
    }

    #[test]
    fn test_dns_response_mode_rejects_whitespace_padding() {
        assert!(DnsResponseMode::from_str(" hostname ").is_err());
        assert!(DnsResponseMode::from_str("\tstatic").is_err());
        assert!(DnsResponseMode::from_str("auto\n").is_err());
    }

    #[test]
    fn test_dns_response_mode_display() {
        assert_eq!(format!("{}", DnsResponseMode::Static), "static");
        assert_eq!(format!("{}", DnsResponseMode::Auto), "auto");
        assert_eq!(format!("{}", DnsResponseMode::Hostname), "hostname");
    }

    #[test]
    fn listener_config_default_limits_connections() {
        assert_eq!(ListenerConfig::default().max_connections, Some(100));
    }

    #[test]
    fn parse_dns_custom_responses_rejects_invalid_ips() {
        let config = ListenerConfig {
            custom_response: Some("example.com=1.2.3.4,bad;invalid=also-bad".to_string()),
            ..Default::default()
        };

        let err = config
            .parse_dns_custom_responses()
            .expect_err("invalid ip should fail");

        assert!(
            err.to_string().contains("invalid IP 'bad'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_dns_custom_responses_rejects_unspecified_ips() {
        let config = ListenerConfig {
            custom_response: Some("example.com=0.0.0.0;ipv6=::;mapped=::ffff:0.0.0.0".to_string()),
            ..Default::default()
        };

        let err = config
            .parse_dns_custom_responses()
            .expect_err("unspecified ip should fail");

        assert!(err.to_string().contains("invalid IP"));
    }

    #[test]
    fn parse_dns_custom_responses_rejects_special_ips() {
        let config = ListenerConfig {
            custom_response: Some(
                "loop=127.0.0.1;multi=224.0.0.1;broadcast=255.255.255.255;\
                 ipv6loop=::1;ipv6multi=ff02::1;mapped=::ffff:127.0.0.1"
                    .to_string(),
            ),
            ..Default::default()
        };

        let err = config
            .parse_dns_custom_responses()
            .expect_err("special IPs should fail");

        assert!(err.to_string().contains("invalid IP"));
    }

    #[test]
    fn parse_dns_custom_responses_canonicalizes_ipv4_mapped_ips() {
        let config = ListenerConfig {
            custom_response: Some(
                "mapped=::ffff:192.0.2.10;mapped-port=::ffff:192.0.2.11".to_string(),
            ),
            ..Default::default()
        };

        let responses = config
            .parse_dns_custom_responses()
            .expect("valid DNS custom response should parse");

        assert_eq!(responses[0].1, vec!["192.0.2.10".to_string()]);
        assert_eq!(responses[1].1, vec!["192.0.2.11".to_string()]);
    }

    #[test]
    fn parse_dns_custom_responses_rejects_empty_domains() {
        let config = ListenerConfig {
            custom_response: Some("=1.2.3.4;example.com=2.2.2.2".to_string()),
            ..Default::default()
        };

        let err = config
            .parse_dns_custom_responses()
            .expect_err("empty domain should fail");

        assert!(
            err.to_string().contains("domain must not be blank"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_dns_custom_responses_rejects_empty_entries() {
        let config = ListenerConfig {
            custom_response: Some("example.com=1.2.3.4;;other.example=2.2.2.2".to_string()),
            ..Default::default()
        };

        let err = config
            .parse_dns_custom_responses()
            .expect_err("empty entry should fail");

        assert!(
            err.to_string().contains("domain must not be blank"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_dns_custom_responses_rejects_invalid_domain_characters() {
        for domain in ["bad/domain", "-bad.example", "bad-.example", "bad_label"] {
            let config = ListenerConfig {
                custom_response: Some(format!("{domain}=1.2.3.4")),
                ..Default::default()
            };

            let err = config
                .parse_dns_custom_responses()
                .expect_err("invalid DNS custom response domain should fail");

            assert!(
                err.to_string()
                    .contains("contains invalid label characters"),
                "{domain}: unexpected error: {err}"
            );
        }
    }

    #[test]
    fn parse_dns_custom_responses_rejects_numeric_and_ip_literal_domains() {
        for custom_response in ["12345=1.2.3.4", "192.0.2.10=1.2.3.4", "127.0.0.1.=1.2.3.4"] {
            let config = ListenerConfig {
                custom_response: Some(custom_response.to_string()),
                ..Default::default()
            };

            let err = config
                .parse_dns_custom_responses()
                .expect_err("numeric or IP literal domain should fail");

            assert!(
                err.to_string().contains("must be a DNS name"),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn parse_dns_custom_responses_accepts_trailing_dot_domains() {
        let config = ListenerConfig {
            custom_response: Some("example.com.=1.2.3.4".to_string()),
            ..Default::default()
        };

        let responses = config
            .parse_dns_custom_responses()
            .expect("valid DNS custom response should parse");

        assert_eq!(responses[0].0, "example.com.");
    }

    #[test]
    fn parse_dns_custom_responses_rejects_multiple_trailing_dots_in_domain() {
        let config = ListenerConfig {
            custom_response: Some("example.com...=1.2.3.4".to_string()),
            ..Default::default()
        };

        let err = config
            .parse_dns_custom_responses()
            .expect_err("domain with multiple trailing dots should fail");

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
        let config = ListenerConfig {
            custom_response: Some(custom_response),
            ..Default::default()
        };

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
        let config = ListenerConfig {
            custom_response: Some(format!("example.com={ips}")),
            ..Default::default()
        };

        let err = config
            .parse_dns_custom_responses()
            .expect_err("oversized DNS custom response IP list should fail");

        assert!(err.to_string().contains("too many IPs"));
    }

    #[test]
    fn parse_dns_custom_responses_rejects_unicode_whitespace_padding() {
        let config = ListenerConfig {
            custom_response: Some("example.com\u{00a0}=1.2.3.4".to_string()),
            ..Default::default()
        };

        let err = config
            .parse_dns_custom_responses()
            .expect_err("unicode whitespace should be rejected");

        assert!(err.to_string().contains("unsupported whitespace"));
    }

    #[test]
    fn parse_dns_custom_responses_rejects_ascii_padding() {
        let config = ListenerConfig {
            custom_response: Some("example.com = 1.2.3.4".to_string()),
            ..Default::default()
        };

        let err = config
            .parse_dns_custom_responses()
            .expect_err("ascii whitespace should be rejected");

        assert!(err.to_string().contains("invalid whitespace"));
    }

    #[test]
    fn parse_dns_custom_responses_rejects_c1_controls_in_domain() {
        let config = ListenerConfig {
            custom_response: Some("example\u{009f}.com=1.2.3.4".to_string()),
            ..Default::default()
        };

        let err = config
            .parse_dns_custom_responses()
            .expect_err("C1 control should be rejected");

        assert!(err.to_string().contains("unsupported whitespace"));
    }
}
