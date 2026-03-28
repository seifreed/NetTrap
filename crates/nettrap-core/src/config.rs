use serde::{Deserialize, Serialize};

use crate::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InterceptionMode {
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

impl Default for InterceptionMode {
    fn default() -> Self {
        #[cfg(target_os = "linux")]
        {
            InterceptionMode::Userspace
        }
        #[cfg(target_os = "windows")]
        {
            InterceptionMode::Userspace
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            InterceptionMode::Userspace
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutputFormat {
    Jsonl,
    Json,
    Csv,
    Table,
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Jsonl
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub protocol: Protocol,
    pub port: u16,
    pub bind_address: String,
    pub enabled: bool,
}

impl ListenerConfig {
    pub fn new(name: impl Into<String>, protocol: Protocol, port: u16) -> Self {
        Self {
            name: name.into(),
            protocol,
            port,
            bind_address: "0.0.0.0".to_string(),
            enabled: true,
        }
    }

    pub fn dns() -> Self {
        Self::new("dns", Protocol::Udp, 53)
    }

    pub fn http() -> Self {
        Self::new("http", Protocol::Tcp, 80)
    }

    pub fn https() -> Self {
        Self::new("https", Protocol::Tcp, 443)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub interception_mode: InterceptionMode,
    pub default_decision: PolicyDecision,
    pub log_level: LogLevel,
    pub output_format: OutputFormat,
    pub output_path: Option<String>,
    pub pcap_enabled: bool,
    pub pcap_path: Option<String>,
    pub listeners: Vec<ListenerConfig>,
    pub attribution_enabled: bool,
    pub attribution_timeout_ms: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            interception_mode: InterceptionMode::default(),
            default_decision: PolicyDecision::Intercept,
            log_level: LogLevel::Info,
            output_format: OutputFormat::Jsonl,
            output_path: None,
            pcap_enabled: false,
            pcap_path: None,
            listeners: vec![ListenerConfig::dns(), ListenerConfig::http()],
            attribution_enabled: true,
            attribution_timeout_ms: 5000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub engine: EngineConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            engine: EngineConfig::default(),
        }
    }
}

impl Config {
    pub fn from_file(path: &str) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config =
            toml::from_str(&content).map_err(|e| crate::Error::Config(e.to_string()))?;
        Ok(config)
    }

    pub fn to_file(&self, path: &str) -> crate::Result<()> {
        let content =
            toml::to_string_pretty(self).map_err(|e| crate::Error::Config(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
