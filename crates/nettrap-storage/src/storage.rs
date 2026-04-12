use async_trait::async_trait;

use crate::prelude::*;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn store_flow(&self, flow: &Flow) -> Result<()>;
    async fn store_packet(&self, packet: &Packet) -> Result<()>;
    async fn store_event(&self, event: &nettrap_events::Event) -> Result<()>;
    async fn flush(&self) -> Result<()>;
    async fn close(&self) -> Result<()>;
}

pub struct StorageConfig {
    pub path: String,
    pub format: StorageFormat,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: "output.jsonl".to_string(),
            format: StorageFormat::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub enum StorageFormat {
    #[default]
    Jsonl,
    Json,
    Csv,
}

impl std::fmt::Display for StorageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageFormat::Jsonl => write!(f, "jsonl"),
            StorageFormat::Json => write!(f, "json"),
            StorageFormat::Csv => write!(f, "csv"),
        }
    }
}

pub fn create_storage(config: StorageConfig) -> Result<Box<dyn Storage>> {
    match config.format {
        StorageFormat::Jsonl => Ok(Box::new(JsonlStorage::new(config.path))),
        StorageFormat::Json => {
            tracing::warn!("JSON storage format not yet implemented, using JSONL");
            Ok(Box::new(JsonlStorage::new(config.path)))
        }
        StorageFormat::Csv => Ok(Box::new(CsvStorage::new(config.path))),
    }
}
