use std::path::PathBuf;

use crate::custom_response::CustomResponseConfig;

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
        match s.to_lowercase().as_str() {
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
            pasv_ports: None,
            max_connections: None,
            banner_delay_ms: 0,
            smtp_dir: None,
            log_hexdump: false,
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
    fn test_dns_response_mode_display() {
        assert_eq!(format!("{}", DnsResponseMode::Static), "static");
        assert_eq!(format!("{}", DnsResponseMode::Auto), "auto");
        assert_eq!(format!("{}", DnsResponseMode::Hostname), "hostname");
    }
}
