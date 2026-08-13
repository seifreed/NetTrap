use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum InterceptionMode {
    #[default]
    Userspace,
    KernelEbpf,
    KernelWfp,
    Nfqueue,
    WinDivert,
}

impl std::fmt::Display for InterceptionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterceptionMode::Userspace => write!(f, "userspace"),
            InterceptionMode::KernelEbpf => write!(f, "kernel_ebpf"),
            InterceptionMode::KernelWfp => write!(f, "kernel_wfp"),
            InterceptionMode::Nfqueue => write!(f, "nfqueue"),
            InterceptionMode::WinDivert => write!(f, "windivert"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum OutputFormat {
    #[default]
    Jsonl,
    Json,
    Csv,
    Table,
}

/// Database storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database backend: "sqlite", "postgres", or "none" (default)
    #[serde(default = "default_database_backend")]
    pub backend: String,

    /// SQLite file path (for backend = "sqlite")
    #[serde(default)]
    pub sqlite_path: Option<PathBuf>,

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

fn default_database_backend() -> String {
    "none".to_string()
}

impl Default for DatabaseConfig {
    /// Matches the serde field defaults so `EngineConfig::default()` (used by
    /// `config --defaults`) and a config deserialized with omitted fields agree.
    /// In particular, `pool_size` uses `default_pool_size()` rather than
    /// `u32::default()` (0).
    fn default() -> Self {
        Self {
            backend: "none".to_string(),
            sqlite_path: None,
            postgres_url: None,
            pool_size: default_pool_size(),
            node_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DatabaseConfig;

    #[test]
    fn database_config_default_uses_disabled_backend() {
        let config = DatabaseConfig::default();

        assert_eq!(config.backend, "none");
        assert_eq!(config.pool_size, 5);
    }

    #[test]
    fn database_config_deserializes_missing_backend_as_disabled() {
        let config: DatabaseConfig = toml::from_str("pool_size = 7").expect("deserialize config");

        assert_eq!(config.backend, "none");
        assert_eq!(config.pool_size, 7);
    }
}

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
    /// Target address/URL.
    /// HTTP sinks require an absolute http(s) URL; TCP/syslog sinks require host:port.
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
