use serde::{Deserialize, Serialize};

use super::ListenerConfig;

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
        }
    }
}

impl EngineConfig {
    pub fn from_file(path: &std::path::Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self =
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
