use serde::{Deserialize, Serialize};

use super::ListenerConfig;

// ─── FakeTime Configuration ──────────────────────────────────────────────────

/// FakeTime mode configuration — shifts all service timestamps to trigger time-bombs
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for FakeTimeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            init_delta: 0,
            auto_delay_secs: 0,
            auto_increment_secs: 0,
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    SingleHost,
    MultiHost,
    Auto,
}

impl Default for NetworkMode {
    fn default() -> Self {
        NetworkMode::Auto
    }
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
        }
    }
}

impl EngineConfig {
    pub fn from_file(path: &std::path::Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut config: Self =
            toml::from_str(&content).map_err(|e| crate::Error::Config(e.to_string()))?;
        config.validate();
        Ok(config)
    }

    /// Validate and fix config values, warning about problematic settings.
    fn validate(&mut self) {
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
        for listener in &mut self.listeners {
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
        }
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
