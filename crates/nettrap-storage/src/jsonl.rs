use std::fs::File;
use std::io::{BufWriter, Write};
use parking_lot::RwLock;
use async_trait::async_trait;

use crate::prelude::*;

pub struct JsonlStorage {
    writer: RwLock<Option<BufWriter<File>>>,
    path: String,
}

impl JsonlStorage {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            writer: RwLock::new(None),
            path: path.into(),
        }
    }
    
    pub fn open(&self) -> Result<()> {
        let path = std::path::Path::new(&self.path);
        
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        let file = File::create(path)?;
        *self.writer.write() = Some(BufWriter::new(file));
        
        Ok(())
    }
    
    pub fn close(&self) {
        if let Some(ref mut writer) = *self.writer.write() {
            let _ = writer.flush();
        }
        *self.writer.write() = None;
    }
}

#[async_trait]
impl Storage for JsonlStorage {
    async fn store_flow(&self, flow: &Flow) -> Result<()> {
        let mut writer = self.writer.write();
        let w = writer.as_mut()
            .ok_or_else(|| Error::Storage("Storage not opened — call open() first".to_string()))?;
        let json = serde_json::to_string(flow)
            .map_err(|e| Error::Storage(e.to_string()))?;
        writeln!(w, "{}", json)
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    async fn store_packet(&self, packet: &Packet) -> Result<()> {
        let mut writer = self.writer.write();
        let w = writer.as_mut()
            .ok_or_else(|| Error::Storage("Storage not opened — call open() first".to_string()))?;
        let json = serde_json::to_string(packet)
            .map_err(|e| Error::Storage(e.to_string()))?;
        writeln!(w, "{}", json)
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    async fn store_event(&self, event: &nettrap_events::Event) -> Result<()> {
        let mut writer = self.writer.write();
        let w = writer.as_mut()
            .ok_or_else(|| Error::Storage("Storage not opened — call open() first".to_string()))?;
        let json = serde_json::to_string(event)
            .map_err(|e| Error::Storage(e.to_string()))?;
        writeln!(w, "{}", json)
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }
    
    async fn flush(&self) -> Result<()> {
        let mut writer = self.writer.write();
        if let Some(ref mut w) = *writer {
            w.flush()
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        Ok(())
    }
    
    async fn close(&self) -> Result<()> {
        let mut writer = self.writer.write();
        if let Some(ref mut w) = *writer {
            w.flush()
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        *writer = None;
        Ok(())
    }
}