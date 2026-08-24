use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use nettrap_core::{DatabaseConfig, DistributedConfig};

use super::ListenerConfig;
use crate::config::{default_dns_config, default_http_config};

pub const CONFIG_VERSION: u32 = 1;

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    SingleHost,
    MultiHost,
    #[default]
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FlowRuleConfig {
    #[serde(default)]
    pub(crate) listener: Option<String>,
    #[serde(default)]
    pub(crate) protocol: Option<String>,
    #[serde(default)]
    pub(crate) source_host: Option<String>,
    #[serde(default)]
    pub(crate) destination_host: Option<String>,
    #[serde(default)]
    pub(crate) destination_port: Option<u16>,
    #[serde(default)]
    pub(crate) process_name: Option<String>,
    pub(crate) decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineConfig {
    #[serde(default = "current_config_version")]
    pub config_version: u32,
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
    #[serde(default = "default_attribution_enabled")]
    pub attribution_enabled: bool,
    #[serde(default = "default_attribution_timeout_ms")]
    pub attribution_timeout_ms: u64,
    #[serde(default = "default_decision")]
    pub default_decision: String,
    #[serde(default)]
    pub pcap_enabled: bool,
    #[serde(default)]
    pub pcap_path: Option<String>,
    #[serde(default = "default_output_format")]
    pub output_format: String,
    #[serde(default)]
    pub output_path: Option<String>,
    #[serde(default)]
    pub api_bind: Option<String>,
    #[serde(default)]
    pub network_mode: NetworkMode,
    #[serde(default)]
    pub tls_ca_cert: Option<String>,
    #[serde(default)]
    pub tls_ca_key: Option<String>,
    #[serde(default)]
    pub tls_cert_dir: Option<String>,
    #[serde(default)]
    pub global_process_blacklist: Vec<String>,
    #[serde(default)]
    pub global_process_whitelist: Vec<String>,
    #[serde(default)]
    pub blacklist_ports_tcp: Vec<u16>,
    #[serde(default)]
    pub blacklist_ports_udp: Vec<u16>,
    #[serde(default)]
    pub blacklist_ids_icmp: Vec<u16>,
    /// Ordered first-match flow policy rules.
    #[serde(default)]
    pub(crate) flow_rules: Vec<FlowRuleConfig>,
    #[serde(default)]
    pub redirect_all_traffic: bool,
    #[serde(default)]
    pub default_tcp_listener: Option<String>,
    #[serde(default)]
    pub default_udp_listener: Option<String>,
    #[serde(default)]
    pub restrict_interface: Option<String>,
    #[serde(default)]
    pub debug_flags: Vec<String>,
    #[serde(default)]
    pub modify_local_dns: bool,
    #[serde(default)]
    pub dns_flush_command: Option<String>,
    #[serde(default)]
    pub http_post_dump_dir: Option<String>,
    // SMTP email storage directory
    #[serde(default)]
    pub smtp_dir: Option<String>,
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
    pub(crate) listener_name_aliases: HashMap<String, Vec<String>>,
}

fn default_attribution_enabled() -> bool {
    true
}
fn current_config_version() -> u32 {
    CONFIG_VERSION
}
fn default_attribution_timeout_ms() -> u64 {
    5000
}
fn default_decision() -> String {
    "emulate".to_string()
}
fn default_output_format() -> String {
    "jsonl".to_string()
}
fn default_report_language() -> String {
    "en".to_string()
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            config_version: CONFIG_VERSION,
            listeners: vec![default_dns_config(), default_http_config()],
            attribution_enabled: true,
            attribution_timeout_ms: 5000,
            default_decision: "emulate".to_string(),
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
            flow_rules: Vec::new(),
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
