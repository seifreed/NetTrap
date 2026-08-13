use async_trait::async_trait;
use parking_lot::RwLock;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::prelude::*;
use nettrap_fsutil::create_regular_file;

pub struct JsonlStorage {
    writer: RwLock<Option<BufWriter<File>>>,
    path: PathBuf,
}

impl JsonlStorage {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            writer: RwLock::new(None),
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn open(&self) -> Result<()> {
        let file = create_regular_file(self.path.as_path())?;
        *self.writer.write() = Some(BufWriter::new(file));

        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        let mut guard = self.writer.write();
        if let Some(ref mut w) = *guard {
            w.flush().map_err(|e| Error::Storage(e.to_string()))?;
        }
        *guard = None;
        Ok(())
    }

    /// Write a single JSON line, minimizing lock hold time.
    fn write_line(&self, json: &str) -> Result<()> {
        let mut writer = self.writer.write();
        let w = writer
            .as_mut()
            .ok_or_else(|| Error::Storage("Storage not opened — call open() first".to_string()))?;
        writeln!(w, "{}", json).map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl Storage for JsonlStorage {
    async fn store_flow(&self, flow: &Flow) -> Result<()> {
        let json = serde_json::to_string(flow).map_err(|e| Error::Storage(e.to_string()))?;
        self.write_line(&json)
    }

    async fn store_packet(&self, packet: &Packet) -> Result<()> {
        let json = serde_json::to_string(packet).map_err(|e| Error::Storage(e.to_string()))?;
        self.write_line(&json)
    }

    async fn store_event(&self, event: &nettrap_events::Event) -> Result<()> {
        let json = serde_json::to_string(event).map_err(|e| Error::Storage(e.to_string()))?;
        self.write_line(&json)
    }

    async fn flush(&self) -> Result<()> {
        let mut writer = self.writer.write();
        if let Some(ref mut w) = *writer {
            w.flush().map_err(|e| Error::Storage(e.to_string()))?;
        }
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        self.close()
    }
}
