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
    let StorageConfig { path, format } = config;

    match format {
        StorageFormat::Jsonl => {
            let storage = JsonlStorage::new(path);
            storage.open()?;
            Ok(Box::new(storage))
        }
        StorageFormat::Json => {
            tracing::warn!("JSON storage format not yet implemented, using JSONL");
            let storage = JsonlStorage::new(path);
            storage.open()?;
            Ok(Box::new(storage))
        }
        StorageFormat::Csv => {
            let storage = CsvStorage::new(path);
            storage.open()?;
            Ok(Box::new(storage))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{StorageConfig, StorageFormat, create_storage};
    use nettrap_core::Packet;

    fn temp_storage_path(extension: &str) -> String {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("nettrap-storage-{unique}.{extension}"))
            .to_string_lossy()
            .into_owned()
    }

    #[tokio::test]
    async fn create_storage_returns_open_jsonl_backend() {
        let path = temp_storage_path("jsonl");
        let storage = create_storage(StorageConfig {
            path: path.clone(),
            format: StorageFormat::Jsonl,
        })
        .expect("jsonl storage should be created");

        storage
            .store_packet(&Packet::default())
            .await
            .expect("jsonl storage should be ready for writes");
        storage.flush().await.expect("jsonl flush should succeed");

        let contents = std::fs::read_to_string(&path).expect("jsonl output should exist");
        assert!(
            !contents.trim().is_empty(),
            "jsonl output should not be empty"
        );

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn create_storage_returns_open_csv_backend() {
        let path = temp_storage_path("csv");
        let storage = create_storage(StorageConfig {
            path: path.clone(),
            format: StorageFormat::Csv,
        })
        .expect("csv storage should be created");

        storage
            .store_packet(&Packet::default())
            .await
            .expect("csv storage should be ready for writes");
        storage.flush().await.expect("csv flush should succeed");

        let contents = std::fs::read_to_string(&path).expect("csv output should exist");
        assert!(
            contents.starts_with("timestamp,type,src_ip"),
            "csv output should contain the header immediately",
        );

        let _ = std::fs::remove_file(path);
    }
}
