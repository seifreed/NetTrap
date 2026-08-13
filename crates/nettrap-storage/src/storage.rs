use async_trait::async_trait;
use std::path::PathBuf;

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
    pub path: PathBuf,
    pub format: StorageFormat,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("output.jsonl"),
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
            let storage = JsonStorage::new(path);
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
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{StorageConfig, StorageFormat, create_storage};
    #[cfg(unix)]
    use crate::error::Error;
    use nettrap_core::Packet;

    /// Per-process monotonic counter so concurrently-running tests (cargo runs
    /// a crate's tests in parallel) never collide on the same temp path even
    /// when their `SystemTime::now()` reads fall in the same nanosecond.
    static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_storage_path(extension: &str) -> String {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        std::env::temp_dir()
            .join(format!("nettrap-storage-{pid}-{unique}-{seq}.{extension}"))
            .to_string_lossy()
            .into_owned()
    }

    fn simple_storage_path(extension: &str) -> String {
        let unique = uuid::Uuid::new_v4();
        format!("nettrap-storage-{unique}.{extension}")
    }

    #[tokio::test]
    async fn create_storage_returns_open_jsonl_backend() {
        let path = temp_storage_path("jsonl");
        let storage = create_storage(StorageConfig {
            path: PathBuf::from(path.clone()),
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

    #[cfg(unix)]
    #[tokio::test]
    async fn create_storage_rejects_symlinked_parent_directory() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-storage-parent-{}-{}",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let real_parent = root.join("real");
        let linked_parent = root.join("linked");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");

        for format in [
            StorageFormat::Jsonl,
            StorageFormat::Json,
            StorageFormat::Csv,
        ] {
            let path = linked_parent.join(format!("output.{format}"));
            let err = match create_storage(StorageConfig {
                path: path.clone(),
                format,
            }) {
                Ok(_) => panic!("symlinked parent should be rejected"),
                Err(err) => err,
            };

            assert!(
                matches!(err, Error::Io(ref io) if io.kind() == std::io::ErrorKind::InvalidInput)
            );
        }

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn create_storage_returns_open_json_backend() {
        let path = temp_storage_path("json");
        let storage = create_storage(StorageConfig {
            path: PathBuf::from(path.clone()),
            format: StorageFormat::Json,
        })
        .expect("json storage should be created");

        storage
            .store_packet(&Packet::default())
            .await
            .expect("json storage should be ready for writes");
        storage
            .store_packet(&Packet::default())
            .await
            .expect("second json record should be accepted");
        storage
            .close()
            .await
            .expect("json close should finalize the document");

        let contents = std::fs::read_to_string(&path).expect("json output should exist");
        let parsed: serde_json::Value =
            serde_json::from_str(&contents).expect("json output must be a valid JSON document");
        let array = parsed
            .as_array()
            .expect("json output must be a top-level array");
        assert_eq!(array.len(), 2, "both stored packets must be present");

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn json_backend_emits_empty_array_when_no_records() {
        let path = temp_storage_path("json");
        let storage = create_storage(StorageConfig {
            path: PathBuf::from(path.clone()),
            format: StorageFormat::Json,
        })
        .expect("json storage should be created");
        storage.close().await.expect("json close should succeed");
        storage
            .close()
            .await
            .expect("json close should be idempotent");

        let contents = std::fs::read_to_string(&path).expect("json output should exist");
        let parsed: serde_json::Value =
            serde_json::from_str(&contents).expect("empty json output must still be valid");
        assert_eq!(
            parsed.as_array().map(|a| a.len()),
            Some(0),
            "no records must serialize as an empty array"
        );

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn create_storage_returns_open_csv_backend() {
        let path = temp_storage_path("csv");
        let storage = create_storage(StorageConfig {
            path: PathBuf::from(path.clone()),
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

    #[tokio::test]
    async fn create_storage_accepts_simple_relative_paths() {
        for (format, extension) in [
            (StorageFormat::Jsonl, "jsonl"),
            (StorageFormat::Json, "json"),
            (StorageFormat::Csv, "csv"),
        ] {
            let path = simple_storage_path(extension);
            let storage = create_storage(StorageConfig {
                path: PathBuf::from(path.clone()),
                format,
            })
            .expect("simple relative storage path should open");

            storage.close().await.expect("storage should close cleanly");
            assert!(
                std::path::Path::new(&path).is_file(),
                "storage should create {path}"
            );
            let _ = std::fs::remove_file(path);
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[tokio::test]
    async fn create_storage_preserves_non_utf8_paths() {
        use std::os::unix::ffi::OsStringExt;

        let path = PathBuf::from(std::ffi::OsString::from_vec(
            b"/tmp/nettrap-storage-\xff.jsonl".to_vec(),
        ));
        let storage = create_storage(StorageConfig {
            path: path.clone(),
            format: StorageFormat::Jsonl,
        })
        .expect("jsonl storage should accept non-UTF8 paths");

        storage
            .store_packet(&Packet::default())
            .await
            .expect("jsonl storage should be ready for writes");
        storage.flush().await.expect("jsonl flush should succeed");

        assert!(path.exists());
        let _ = std::fs::remove_file(path);
    }
}
