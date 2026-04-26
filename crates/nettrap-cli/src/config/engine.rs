use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use super::ListenerConfig;

// ─── FakeTime Configuration ──────────────────────────────────────────────────

/// FakeTime mode configuration — shifts all service timestamps to trigger time-bombs
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FakeTimeConfig {
    /// Enable fake-time mode
    #[serde(default)]
    pub enabled: bool,

    /// Initial time delta in seconds (positive = future, negative = past)
    #[serde(default)]
    pub init_delta: i64,

    /// Seconds between auto-increment ticks (0 = disabled)
    #[serde(default)]
    pub auto_delay_secs: u64,

    /// Seconds to add each tick
    #[serde(default)]
    pub auto_increment_secs: i64,
}

// ─── Distributed Deployment Config (all optional for standalone) ─────────────

/// Distributed deployment configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DistributedConfig {
    /// Enable distributed mode
    #[serde(default)]
    pub enabled: bool,

    /// Node identification
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub node_region: Option<String>,
    #[serde(default)]
    pub node_tags: Vec<String>,

    /// Event sinks (multiple supported simultaneously)
    #[serde(default)]
    pub event_sinks: Vec<EventSinkConfig>,

    /// Control plane API endpoint (for fleet management)
    #[serde(default)]
    pub control_plane_url: Option<String>,
    #[serde(default)]
    pub control_plane_token: Option<String>,

    /// Heartbeat interval in seconds (0 = disabled)
    #[serde(default)]
    pub heartbeat_interval_secs: u64,

    /// Metrics endpoint (Prometheus compatible)
    #[serde(default)]
    pub metrics_bind: Option<String>,

    /// Health check endpoint
    #[serde(default)]
    pub health_bind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSinkConfig {
    /// Sink type: "http", "tcp", "syslog"
    #[serde(rename = "type")]
    pub sink_type: String,
    /// Target address/URL
    pub target: String,
    /// Optional auth (API key, bearer token)
    #[serde(default)]
    pub auth: Option<String>,
    /// Batch size for HTTP sinks (default 100)
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Max time an HTTP event batch may remain buffered before flush (default 1000ms)
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u64,
    /// Max time to wait for a single outbound HTTP request before marking delivery state unknown
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
}

fn default_batch_size() -> usize {
    100
}

fn default_flush_interval_ms() -> u64 {
    1000
}

fn default_request_timeout_ms() -> u64 {
    5000
}

// ─── Database Storage Config ─────────────────────────────────────────────────

/// Database storage configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database backend: "sqlite", "postgres", or "none" (default)
    #[serde(default)]
    pub backend: String,

    /// SQLite file path (for backend = "sqlite")
    #[serde(default)]
    pub sqlite_path: Option<String>,

    /// PostgreSQL connection URL (for backend = "postgres" or "postgresql")
    /// Format: postgres://user:password@host:port/database
    #[serde(default)]
    pub postgres_url: Option<String>,

    /// Connection pool size (default: 5)
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,

    /// Node ID for distributed writes (auto-populated from distributed config)
    #[serde(default)]
    pub node_id: Option<String>,
}

fn default_pool_size() -> u32 {
    5
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    SingleHost,
    MultiHost,
    #[default]
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub listeners: Vec<ListenerConfig>,
    pub attribution_enabled: bool,
    pub attribution_timeout_ms: u64,
    pub default_decision: String,
    pub pcap_enabled: bool,
    pub pcap_path: Option<String>,
    pub output_format: String,
    pub output_path: Option<String>,
    #[serde(default)]
    pub api_bind: Option<String>,
    // Network mode
    #[serde(default)]
    pub network_mode: NetworkMode,
    // SSL/TLS CA configuration
    #[serde(default)]
    pub tls_ca_cert: Option<String>,
    #[serde(default)]
    pub tls_ca_key: Option<String>,
    #[serde(default)]
    pub tls_cert_dir: Option<String>,
    // Global process filtering
    #[serde(default)]
    pub global_process_blacklist: Vec<String>,
    #[serde(default)]
    pub global_process_whitelist: Vec<String>,
    // Global port blacklists
    #[serde(default)]
    pub blacklist_ports_tcp: Vec<u16>,
    #[serde(default)]
    pub blacklist_ports_udp: Vec<u16>,
    // ICMP blacklist (Windows)
    #[serde(default)]
    pub blacklist_ids_icmp: Vec<u16>,
    // Traffic redirection
    #[serde(default)]
    pub redirect_all_traffic: bool,
    #[serde(default)]
    pub default_tcp_listener: Option<String>,
    #[serde(default)]
    pub default_udp_listener: Option<String>,
    // Interface restriction
    #[serde(default)]
    pub restrict_interface: Option<String>,
    // Debug flags
    #[serde(default)]
    pub debug_flags: Vec<String>,
    // DNS settings
    #[serde(default)]
    pub modify_local_dns: bool,
    #[serde(default)]
    pub dns_flush_command: Option<String>,
    // HTTP POST dumping directory
    #[serde(default)]
    pub http_post_dump_dir: Option<String>,
    // SMTP email storage directory
    #[serde(default)]
    pub smtp_dir: Option<String>,
    // Hexdump in logs
    #[serde(default)]
    pub log_hexdump: bool,
    // PCAP filename prefix
    #[serde(default)]
    pub pcap_prefix: Option<String>,
    /// Distributed deployment configuration (optional, all defaults to standalone)
    #[serde(default)]
    pub distributed: DistributedConfig,
    /// Database storage configuration (optional)
    #[serde(default)]
    pub database: DatabaseConfig,
    /// FakeTime mode configuration (optional)
    #[serde(default)]
    pub faketime: FakeTimeConfig,
    /// Language code for NBI report generation (ISO 639-1, e.g. "en", "es", "de")
    #[serde(default = "default_report_language")]
    pub report_language: String,
    #[serde(skip)]
    listener_name_aliases: HashMap<String, Vec<String>>,
}

fn default_report_language() -> String {
    "en".to_string()
}

impl Default for EngineConfig {
    fn default() -> Self {
        use super::{default_dns_config, default_http_config};
        Self {
            listeners: vec![default_dns_config(), default_http_config()],
            attribution_enabled: true,
            attribution_timeout_ms: 5000,
            default_decision: "intercept".to_string(),
            pcap_enabled: false,
            pcap_path: None,
            output_format: "jsonl".to_string(),
            output_path: None,
            api_bind: None,
            network_mode: NetworkMode::Auto,
            tls_ca_cert: None,
            tls_ca_key: None,
            tls_cert_dir: None,
            global_process_blacklist: Vec::new(),
            global_process_whitelist: Vec::new(),
            blacklist_ports_tcp: Vec::new(),
            blacklist_ports_udp: Vec::new(),
            blacklist_ids_icmp: Vec::new(),
            redirect_all_traffic: false,
            default_tcp_listener: None,
            default_udp_listener: None,
            restrict_interface: None,
            debug_flags: Vec::new(),
            modify_local_dns: false,
            dns_flush_command: None,
            http_post_dump_dir: None,
            smtp_dir: None,
            log_hexdump: false,
            pcap_prefix: None,
            distributed: DistributedConfig::default(),
            database: DatabaseConfig::default(),
            faketime: FakeTimeConfig::default(),
            report_language: default_report_language(),
            listener_name_aliases: HashMap::new(),
        }
    }
}

impl EngineConfig {
    pub fn from_file(path: &std::path::Path) -> crate::Result<Self> {
        let mut config = Self::from_file_declarative(path)?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_file_api(path: &std::path::Path) -> crate::Result<Self> {
        let mut config = Self::from_file_declarative(path)?;
        config.validate_global_settings()?;
        Ok(config)
    }

    pub fn from_file_declarative(path: &std::path::Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| crate::Error::Config(e.to_string()))
    }

    fn validate(&mut self) -> crate::Result<()> {
        self.validate_global_settings()?;
        self.prepare_listeners_for_runtime()?;
        self.validate_runtime_global_settings()?;
        Ok(())
    }

    fn validate_global_settings(&mut self) -> crate::Result<()> {
        if self.database.pool_size == 0 {
            tracing::warn!("database.pool_size is 0, correcting to 1");
            self.database.pool_size = 1;
        }
        if self.attribution_timeout_ms == 0 && self.attribution_enabled {
            tracing::warn!(
                "attribution_timeout_ms is 0 with attribution enabled, correcting to 100ms"
            );
            self.attribution_timeout_ms = 100;
        }

        validate_socket_addr_setting("api_bind", self.api_bind.as_deref())?;
        validate_socket_addr_setting(
            "distributed.health_bind",
            self.distributed.health_bind.as_deref(),
        )?;
        validate_socket_addr_setting(
            "distributed.metrics_bind",
            self.distributed.metrics_bind.as_deref(),
        )?;
        validate_output_format_setting(&self.output_format)?;

        Ok(())
    }

    fn validate_runtime_global_settings(&self) -> crate::Result<()> {
        if self.distributed.enabled {
            let _ = crate::distributed::build_event_fanout(&self.distributed)?;
        }

        Ok(())
    }

    fn prepare_listeners_for_runtime(&mut self) -> crate::Result<()> {
        for listener in &mut self.listeners {
            listener.bind_address =
                canonicalize_bind_address(&listener.bind_address).map_err(|err| match err {
                    crate::Error::Config(message) => {
                        crate::Error::Config(format!("Listener '{}': {}", listener.name, message))
                    }
                    other => other,
                })?;

            if listener.port == 0 {
                tracing::warn!(
                    "Listener '{}' has port 0, will bind to random port",
                    listener.name
                );
            }
            // Validate dns_response_mode if set
            if let Some(ref mode) = listener.dns_response_mode {
                let valid = ["static", "auto", "hostname", "gethostname"];
                if !valid.contains(&mode.to_lowercase().as_str()) {
                    tracing::warn!(
                        "Listener '{}': invalid dns_response_mode '{}', resetting to default. Valid: {:?}",
                        listener.name,
                        mode,
                        &valid
                    );
                    listener.dns_response_mode = None;
                }
            }

            listener.refresh_host_filters().map_err(|err| match err {
                crate::Error::Config(message) => {
                    crate::Error::Config(format!("Listener '{}': {}", listener.name, message))
                }
                other => other,
            })?;
        }

        self.expand_listeners();
        if self.listeners.is_empty() {
            return Err(crate::Error::Config(
                "No valid listeners remain after port_range expansion".into(),
            ));
        }
        self.finalize_listener_names()?;
        Ok(())
    }

    pub(crate) fn prepare_runtime_defaults(&mut self) -> crate::Result<()> {
        self.validate()
    }

    pub(crate) fn prepare_api_defaults(&mut self) -> crate::Result<()> {
        self.validate_global_settings()
    }

    pub(crate) fn finalize_after_cli_overrides(&mut self) -> crate::Result<()> {
        self.validate_global_settings()?;
        self.finalize_listener_names()?;
        Ok(())
    }

    pub fn to_file(&self, path: &str) -> crate::Result<()> {
        let content =
            toml::to_string_pretty(self).map_err(|e| crate::Error::Config(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Expand all listeners with port ranges into individual listeners
    pub fn expand_listeners(&mut self) {
        let expanded: Vec<ListenerConfig> = self
            .listeners
            .iter()
            .flat_map(|l| l.expand_port_range())
            .collect();
        self.listeners = expanded;
        self.normalize_listener_names();
    }

    pub(crate) fn finalize_listener_names(&mut self) -> crate::Result<()> {
        self.prepare_listener_names()?;
        self.validate_socket_collisions()?;
        Ok(())
    }

    pub(crate) fn prepare_listener_names(&mut self) -> crate::Result<()> {
        self.normalize_listener_names();
        self.resolve_redirect_defaults()?;
        Ok(())
    }

    pub(crate) fn normalize_listener_names(&mut self) {
        let mut used_names = HashSet::new();
        self.listener_name_aliases.clear();

        for listener in &mut self.listeners {
            let normalized = listener.name.to_ascii_lowercase();
            let original = listener.name.clone();

            if !used_names.insert(normalized) {
                let base = format!("{}_{}", original, listener.port);
                let mut candidate = base.clone();
                let mut suffix = 2u32;

                while !used_names.insert(candidate.to_ascii_lowercase()) {
                    candidate = format!("{}_{}", base, suffix);
                    suffix += 1;
                }

                tracing::warn!(
                    "Duplicate listener name '{}' detected; renaming listener on port {} to '{}'",
                    original,
                    listener.port,
                    candidate
                );
                listener.name = candidate;
            }

            let aliases = self
                .listener_name_aliases
                .entry(original.to_ascii_lowercase())
                .or_default();
            if !aliases
                .iter()
                .any(|name| name.eq_ignore_ascii_case(listener.name.as_str()))
            {
                aliases.push(listener.name.clone());
            }
        }
    }

    fn resolve_redirect_defaults(&mut self) -> crate::Result<()> {
        use nettrap_core::prelude::Protocol;

        if let Some(ref listener) = self.default_tcp_listener.clone() {
            self.default_tcp_listener =
                Some(self.resolve_redirect_default(listener, Protocol::Tcp)?);
        }
        if let Some(ref listener) = self.default_udp_listener.clone() {
            self.default_udp_listener =
                Some(self.resolve_redirect_default(listener, Protocol::Udp)?);
        }
        Ok(())
    }

    fn resolve_redirect_default(
        &self,
        requested_name: &str,
        protocol: nettrap_core::prelude::Protocol,
    ) -> crate::Result<String> {
        let alias_matches: Vec<&ListenerConfig> = self
            .listener_name_aliases
            .get(&requested_name.to_ascii_lowercase())
            .into_iter()
            .flat_map(|aliases| aliases.iter())
            .filter_map(|alias| {
                self.listeners.iter().find(|listener| {
                    listener.protocol == protocol && listener.name.eq_ignore_ascii_case(alias)
                })
            })
            .collect();

        if alias_matches.len() > 1 {
            return Err(crate::Error::Config(format!(
                "redirect_all_traffic {} default listener '{}' became ambiguous after listener name normalization",
                protocol_label(protocol),
                requested_name
            )));
        }

        if let Some(listener) = alias_matches.first() {
            return Ok(listener.name.clone());
        }

        let exact_matches: Vec<&ListenerConfig> = self
            .listeners
            .iter()
            .filter(|listener| {
                listener.protocol == protocol && listener.name.eq_ignore_ascii_case(requested_name)
            })
            .collect();

        if exact_matches.len() == 1 {
            return Ok(exact_matches[0].name.clone());
        }

        if exact_matches.len() > 1 {
            return Err(crate::Error::Config(format!(
                "redirect_all_traffic {} default listener '{}' is ambiguous",
                protocol_label(protocol),
                requested_name
            )));
        }

        Ok(requested_name.to_string())
    }

    fn validate_socket_collisions(&self) -> crate::Result<()> {
        use nettrap_core::prelude::Protocol;

        let mut sockets: Vec<RegisteredSocket> = Vec::new();

        #[derive(Clone)]
        struct RegisteredSocket {
            protocol: Protocol,
            bind_addr: IpAddr,
            port: u16,
            owner: String,
        }

        let mut register_socket = |protocol: Protocol,
                                   bind_addr: IpAddr,
                                   port: u16,
                                   owner: String|
         -> crate::Result<()> {
            if let Some(existing) = sockets.iter().find(|existing| {
                socket_bindings_overlap(
                    existing.protocol,
                    existing.bind_addr,
                    existing.port,
                    protocol,
                    bind_addr,
                    port,
                )
            }) {
                if existing.bind_addr == bind_addr {
                    return Err(crate::Error::Config(format!(
                        "{} and {} both resolve to {} socket {}:{}",
                        existing.owner,
                        owner,
                        protocol_label(protocol),
                        bind_addr,
                        port
                    )));
                }

                return Err(crate::Error::Config(format!(
                    "{} and {} overlap on {} socket port {} ({} vs {})",
                    existing.owner,
                    owner,
                    protocol_label(protocol),
                    port,
                    existing.bind_addr,
                    bind_addr
                )));
            }

            sockets.push(RegisteredSocket {
                protocol,
                bind_addr,
                port,
                owner,
            });
            Ok(())
        };

        for listener in self
            .listeners
            .iter()
            .filter(|l| self.listener_is_spawnable(l))
        {
            let bind_addr = parse_bind_address(&listener.bind_address)?;
            register_socket(
                listener.protocol,
                bind_addr,
                listener.port,
                format!("listener '{}'", listener.name),
            )?;
        }

        if let Some(addr) = parse_optional_socket_addr("api_bind", self.api_bind.as_deref())? {
            register_socket(
                Protocol::Tcp,
                addr.ip(),
                addr.port(),
                "api_bind".to_string(),
            )?;
        }

        if let Some(addr) = parse_optional_socket_addr(
            "distributed.health_bind",
            self.distributed.health_bind.as_deref(),
        )? {
            register_socket(
                Protocol::Tcp,
                addr.ip(),
                addr.port(),
                "distributed.health_bind".to_string(),
            )?;
        }

        if let Some(addr) = parse_optional_socket_addr(
            "distributed.metrics_bind",
            self.distributed.metrics_bind.as_deref(),
        )? {
            register_socket(
                Protocol::Tcp,
                addr.ip(),
                addr.port(),
                "distributed.metrics_bind".to_string(),
            )?;
        }

        Ok(())
    }

    fn listener_is_default_target(&self, listener: &ListenerConfig) -> bool {
        use nettrap_core::prelude::Protocol;

        match listener.protocol {
            Protocol::Tcp => self
                .default_tcp_listener
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case(listener.name.as_str())),
            Protocol::Udp => self
                .default_udp_listener
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case(listener.name.as_str())),
            _ => false,
        }
    }

    fn listener_is_spawnable(&self, listener: &ListenerConfig) -> bool {
        use nettrap_core::prelude::Protocol;

        if !listener.enabled {
            return false;
        }

        if listener.hidden && !self.listener_is_default_target(listener) {
            return false;
        }

        let is_tcp = listener.protocol == Protocol::Tcp;
        !self.is_port_blacklisted(listener.port, is_tcp)
    }

    /// Check if a port is blacklisted
    pub fn is_port_blacklisted(&self, port: u16, is_tcp: bool) -> bool {
        if is_tcp {
            self.blacklist_ports_tcp.contains(&port)
        } else {
            self.blacklist_ports_udp.contains(&port)
        }
    }

    /// Check if a debug flag is enabled
    pub fn has_debug_flag(&self, flag: &str) -> bool {
        self.debug_flags
            .iter()
            .any(|f| f.eq_ignore_ascii_case(flag))
    }

    /// Resolve effective network mode based on OS
    pub fn effective_network_mode(&self) -> NetworkMode {
        match self.network_mode {
            NetworkMode::Auto => {
                if cfg!(target_os = "linux") {
                    NetworkMode::MultiHost
                } else {
                    NetworkMode::SingleHost
                }
            }
            other => other,
        }
    }
}

fn protocol_label(protocol: nettrap_core::prelude::Protocol) -> &'static str {
    match protocol {
        nettrap_core::prelude::Protocol::Tcp => "tcp",
        nettrap_core::prelude::Protocol::Udp => "udp",
        _ => "unsupported",
    }
}

fn parse_bind_address(bind_address: &str) -> crate::Result<IpAddr> {
    let trimmed = bind_address.trim();
    trimmed.parse::<IpAddr>().map_err(|err| {
        crate::Error::Config(format!("invalid bind_address '{}': {}", bind_address, err))
    })
}

fn validate_socket_addr_setting(setting_name: &str, value: Option<&str>) -> crate::Result<()> {
    parse_optional_socket_addr(setting_name, value).map(|_| ())
}

fn validate_output_format_setting(value: &str) -> crate::Result<()> {
    value
        .parse::<crate::output::OutputFormat>()
        .map(|_| ())
        .map_err(|err| crate::Error::Config(err.to_string()))
}

fn parse_optional_socket_addr(
    setting_name: &str,
    value: Option<&str>,
) -> crate::Result<Option<std::net::SocketAddr>> {
    match value {
        None => Ok(None),
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(crate::Error::Config(format!(
                    "{} cannot be empty",
                    setting_name
                )));
            }

            trimmed
                .parse::<std::net::SocketAddr>()
                .map(Some)
                .map_err(|err| {
                    crate::Error::Config(format!("Invalid {} '{}': {}", setting_name, raw, err))
                })
        }
    }
}

fn canonicalize_bind_address(bind_address: &str) -> crate::Result<String> {
    Ok(parse_bind_address(bind_address)?.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NormalizedBindAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl NormalizedBindAddr {
    fn is_ipv6_unspecified(self) -> bool {
        matches!(self, Self::V6(addr) if addr.is_unspecified())
    }
}

fn normalize_bind_addr(addr: IpAddr) -> NormalizedBindAddr {
    match addr {
        IpAddr::V4(addr) => NormalizedBindAddr::V4(addr),
        IpAddr::V6(addr) => match addr.to_ipv4_mapped() {
            Some(mapped) => NormalizedBindAddr::V4(mapped),
            None => NormalizedBindAddr::V6(addr),
        },
    }
}

fn socket_bindings_overlap(
    left_protocol: nettrap_core::prelude::Protocol,
    left_addr: IpAddr,
    left_port: u16,
    right_protocol: nettrap_core::prelude::Protocol,
    right_addr: IpAddr,
    right_port: u16,
) -> bool {
    if left_protocol != right_protocol || left_port != right_port {
        return false;
    }

    let left = normalize_bind_addr(left_addr);
    let right = normalize_bind_addr(right_addr);

    match (left, right) {
        (NormalizedBindAddr::V4(left), NormalizedBindAddr::V4(right)) => {
            left == right || left.is_unspecified() || right.is_unspecified()
        }
        (NormalizedBindAddr::V6(left), NormalizedBindAddr::V6(right)) => {
            left == right || left.is_unspecified() || right.is_unspecified()
        }
        (left, right) => left.is_ipv6_unspecified() || right.is_ipv6_unspecified(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::EngineConfig;
    use crate::config::ListenerConfig;

    #[test]
    fn normalize_listener_names_renames_case_insensitive_duplicates() {
        let mut config = EngineConfig {
            listeners: vec![
                ListenerConfig::new("http", 80),
                ListenerConfig::new("HTTP", 8080),
            ],
            ..EngineConfig::default()
        };

        config.normalize_listener_names();

        assert_eq!(config.listeners[0].name, "http");
        assert_eq!(config.listeners[1].name, "HTTP_8080");
    }

    #[test]
    fn expand_listeners_renames_collisions_after_port_range_expansion() {
        let mut ranged = ListenerConfig::new("http", 80);
        ranged.port_range = Some("80,81".to_string());

        let colliding = ListenerConfig::new("http_80", 9000);

        let mut config = EngineConfig {
            listeners: vec![ranged, colliding],
            ..EngineConfig::default()
        };

        config.expand_listeners();

        let names: Vec<&str> = config
            .listeners
            .iter()
            .map(|listener| listener.name.as_str())
            .collect();
        assert_eq!(names, vec!["http_80", "http_81", "http_80_9000"]);
    }

    #[test]
    fn finalize_listener_names_rejects_ambiguous_redirect_defaults() {
        let mut config = EngineConfig {
            listeners: vec![
                ListenerConfig::new("http", 80),
                ListenerConfig::new("http", 8080),
            ],
            redirect_all_traffic: true,
            default_tcp_listener: Some("http".to_string()),
            ..EngineConfig::default()
        };

        let err = config
            .finalize_listener_names()
            .expect_err("ambiguous defaults should be rejected");

        assert!(
            err.to_string().contains("became ambiguous"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn finalize_listener_names_rewrites_unique_redirect_defaults_to_final_name() {
        let mut config = EngineConfig {
            listeners: vec![
                ListenerConfig::new("http", 80),
                ListenerConfig::new("control", 8080),
            ],
            redirect_all_traffic: true,
            default_tcp_listener: Some("control".to_string()),
            ..EngineConfig::default()
        };

        config
            .finalize_listener_names()
            .expect("unique default listener should remain valid");

        assert_eq!(config.default_tcp_listener.as_deref(), Some("control"));
    }

    #[test]
    fn from_file_rejects_unresolvable_hostname_filters() {
        let path =
            std::env::temp_dir().join(format!("nettrap-host-filter-{}.toml", std::process::id()));
        let mut listener = ListenerConfig::new("http", 80);
        listener.host_whitelist = vec!["definitely-not-a-real-nettrap-host.invalid".to_string()];
        let config = EngineConfig {
            listeners: vec![listener],
            ..EngineConfig::default()
        };
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let err = EngineConfig::from_file(&path).expect_err("invalid hostname should fail");

        let _ = fs::remove_file(&path);

        assert!(err.to_string().contains("failed to resolve host filter"));
    }

    #[test]
    fn finalize_listener_names_rejects_spawnable_socket_collisions() {
        let mut config = EngineConfig {
            listeners: vec![
                ListenerConfig::new("http", 80),
                ListenerConfig::new("http-alt", 80),
            ],
            ..EngineConfig::default()
        };

        let err = config
            .finalize_listener_names()
            .expect_err("colliding sockets should fail validation");

        assert!(
            err.to_string()
                .contains("both resolve to tcp socket 0.0.0.0:80")
        );
    }

    #[test]
    fn finalize_listener_names_ignores_disabled_socket_collisions() {
        let mut disabled = ListenerConfig::new("http-alt", 80);
        disabled.enabled = false;
        let mut config = EngineConfig {
            listeners: vec![ListenerConfig::new("http", 80), disabled],
            ..EngineConfig::default()
        };

        config
            .finalize_listener_names()
            .expect("disabled listeners should not trigger socket collisions");
    }

    #[test]
    fn from_file_rejects_invalid_bind_address() {
        let path =
            std::env::temp_dir().join(format!("nettrap-bind-address-{}.toml", std::process::id()));
        let config = EngineConfig {
            listeners: vec![ListenerConfig::new("http", 80).with_bind_address("not-an-ip")],
            ..EngineConfig::default()
        };
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let err = EngineConfig::from_file(&path).expect_err("invalid bind_address should fail");

        let _ = fs::remove_file(&path);

        assert!(err.to_string().contains("invalid bind_address"));
    }

    #[test]
    fn finalize_listener_names_rejects_canonical_socket_collisions() {
        let mut config = EngineConfig {
            listeners: vec![
                ListenerConfig::new("http-v6-short", 80).with_bind_address("::1"),
                ListenerConfig::new("http-v6-long", 80).with_bind_address("0:0:0:0:0:0:0:1"),
            ],
            ..EngineConfig::default()
        };

        let err = config
            .validate()
            .expect_err("canonicalized IPv6 collisions should fail validation");

        assert!(
            err.to_string()
                .contains("both resolve to tcp socket ::1:80")
        );
    }

    #[test]
    fn from_file_rejects_configs_without_valid_expanded_listeners() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-empty-expansion-{}.toml",
            std::process::id()
        ));
        let mut listener = ListenerConfig::new("http", 80);
        listener.port_range = Some("not-a-port".to_string());
        let config = EngineConfig {
            listeners: vec![listener],
            ..EngineConfig::default()
        };
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let err = EngineConfig::from_file(&path)
            .expect_err("fully invalid port_range should leave no listeners");

        let _ = fs::remove_file(&path);

        assert!(err.to_string().contains("No valid listeners remain"));
    }

    #[test]
    fn from_file_rejects_invalid_distributed_event_sinks_in_runtime_validation() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-invalid-distributed-sink-{}.toml",
            std::process::id()
        ));
        let mut distributed = crate::config::DistributedConfig {
            enabled: true,
            ..crate::config::DistributedConfig::default()
        };
        distributed
            .event_sinks
            .push(crate::config::EventSinkConfig {
                sink_type: "bogus".into(),
                target: "127.0.0.1:1".into(),
                auth: None,
                batch_size: 1,
                flush_interval_ms: 1000,
                request_timeout_ms: 1000,
            });
        let config = EngineConfig {
            distributed,
            ..EngineConfig::default()
        };
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let err = EngineConfig::from_file(&path)
            .expect_err("invalid sink should fail runtime validation");

        let _ = fs::remove_file(&path);

        assert!(
            err.to_string()
                .contains("Unknown distributed event sink type")
        );
    }

    #[test]
    fn from_file_api_applies_global_normalization_without_expanding_listeners() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-api-global-normalization-{}.toml",
            std::process::id()
        ));
        let mut listener = ListenerConfig::new("http", 80).with_bind_address("not-an-ip");
        listener.port_range = Some("80,81".to_string());
        let database = crate::config::DatabaseConfig {
            pool_size: 0,
            ..crate::config::DatabaseConfig::default()
        };
        let config = EngineConfig {
            listeners: vec![listener],
            database,
            attribution_timeout_ms: 0,
            ..EngineConfig::default()
        };
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let loaded = EngineConfig::from_file_api(&path).expect("api config should load");

        let _ = fs::remove_file(&path);

        assert_eq!(loaded.database.pool_size, 1);
        assert_eq!(loaded.attribution_timeout_ms, 100);
        assert_eq!(loaded.listeners.len(), 1);
        assert_eq!(loaded.listeners[0].bind_address, "not-an-ip");
        assert_eq!(loaded.listeners[0].port_range.as_deref(), Some("80,81"));
    }

    #[test]
    fn from_file_api_rejects_invalid_api_bind() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-invalid-api-bind-{}.toml",
            std::process::id()
        ));
        let config = EngineConfig {
            api_bind: Some("not-a-socket".into()),
            ..EngineConfig::default()
        };
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let err = EngineConfig::from_file_api(&path).expect_err("invalid api_bind should fail");

        let _ = fs::remove_file(&path);

        assert!(err.to_string().contains("Invalid api_bind"));
    }

    #[test]
    fn from_file_api_rejects_invalid_distributed_probe_binds() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-invalid-distributed-bind-{}.toml",
            std::process::id()
        ));
        let config = EngineConfig {
            distributed: crate::config::DistributedConfig {
                health_bind: Some("still-not-a-socket".into()),
                ..crate::config::DistributedConfig::default()
            },
            ..EngineConfig::default()
        };
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let err = EngineConfig::from_file_api(&path).expect_err("invalid health_bind should fail");

        let _ = fs::remove_file(&path);

        assert!(err.to_string().contains("distributed.health_bind"));
    }

    #[test]
    fn from_file_api_rejects_empty_global_binds() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-empty-api-bind-{}.toml",
            std::process::id()
        ));
        let config = EngineConfig {
            api_bind: Some("   ".into()),
            ..EngineConfig::default()
        };
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let err = EngineConfig::from_file_api(&path).expect_err("empty api_bind should fail");

        let _ = fs::remove_file(&path);

        assert!(err.to_string().contains("api_bind cannot be empty"));
    }

    #[test]
    fn finalize_listener_names_rejects_listener_and_api_bind_collisions() {
        let mut config = EngineConfig {
            listeners: vec![ListenerConfig::new("http", 8080).with_bind_address("127.0.0.1")],
            api_bind: Some("127.0.0.1:8080".into()),
            ..EngineConfig::default()
        };

        let err = config
            .validate()
            .expect_err("api_bind colliding with listener should fail validation");

        assert!(
            err.to_string()
                .contains("listener 'http' and api_bind both resolve to tcp socket 127.0.0.1:8080")
        );
    }

    #[test]
    fn validate_socket_collision_with_unspecified_listener_and_concrete_api_bind() {
        let mut config = EngineConfig {
            listeners: vec![ListenerConfig::new("http", 8080).with_bind_address("0.0.0.0")],
            api_bind: Some("127.0.0.1:8080".into()),
            ..EngineConfig::default()
        };

        let err = config
            .validate()
            .expect_err("unspecified listener bind should collide with concrete api_bind");

        assert!(
            err.to_string()
                .contains("listener 'http' and api_bind overlap on tcp socket port 8080")
        );
    }

    #[test]
    fn finalize_listener_names_rejects_global_endpoint_collisions() {
        let mut config = EngineConfig {
            listeners: vec![ListenerConfig::new("http", 8080)],
            distributed: crate::config::DistributedConfig {
                health_bind: Some("127.0.0.1:9000".into()),
                metrics_bind: Some("127.0.0.1:9000".into()),
                ..crate::config::DistributedConfig::default()
            },
            ..EngineConfig::default()
        };

        let err = config
            .validate()
            .expect_err("health and metrics bind collision should fail validation");

        assert!(
            err.to_string()
                .contains("distributed.health_bind and distributed.metrics_bind both resolve to tcp socket 127.0.0.1:9000")
        );
    }

    #[test]
    fn from_file_declarative_preserves_port_range_form() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-declarative-roundtrip-{}.toml",
            std::process::id()
        ));
        let mut listener = ListenerConfig::new("http", 80);
        listener.port_range = Some("80,81".to_string());
        let config = EngineConfig {
            listeners: vec![listener],
            ..EngineConfig::default()
        };
        let serialized = toml::to_string(&config).expect("serialize config");
        fs::write(&path, serialized).expect("write temp config");

        let loaded =
            EngineConfig::from_file_declarative(&path).expect("declarative config should load");

        let _ = fs::remove_file(&path);

        assert_eq!(loaded.listeners.len(), 1);
        assert_eq!(loaded.listeners[0].name, "http");
        assert_eq!(loaded.listeners[0].port_range.as_deref(), Some("80,81"));
    }
}
