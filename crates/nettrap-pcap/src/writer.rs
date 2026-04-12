use parking_lot::RwLock;

use crate::prelude::*;

pub struct PacketWriter {
    file: RwLock<Option<std::fs::File>>,
    path: String,
}

impl PacketWriter {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            file: RwLock::new(None),
            path: path.into(),
        }
    }

    pub fn open(&self) -> Result<()> {
        let path = std::path::Path::new(&self.path);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = std::fs::File::create(path)?;
        *self.file.write() = Some(file);

        Ok(())
    }

    pub fn close(&self) {
        *self.file.write() = None;
    }

    pub fn write_packet(&self, packet: &Packet) -> Result<()> {
        let mut file = self.file.write();
        if let Some(ref mut f) = *file {
            let json = serde_json::to_string(packet)
                .map_err(|e| Error::Storage(format!("JSON serialization failed: {}", e)))?;
            use std::io::Write;
            writeln!(f, "{}", json).map_err(|e| Error::Storage(e.to_string()))?;
        }
        Ok(())
    }
}

pub struct FlowWriter {
    file: RwLock<Option<std::fs::File>>,
    path: String,
}

impl FlowWriter {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            file: RwLock::new(None),
            path: path.into(),
        }
    }

    pub fn open(&self) -> Result<()> {
        let path = std::path::Path::new(&self.path);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = std::fs::File::create(path)?;
        *self.file.write() = Some(file);

        Ok(())
    }

    pub fn close(&self) {
        *self.file.write() = None;
    }

    pub fn write_flow(&self, flow: &nettrap_flow::Flow) -> Result<()> {
        let mut file = self.file.write();
        if let Some(ref mut f) = *file {
            let json = serde_json::to_string(flow)
                .map_err(|e| Error::Storage(format!("JSON serialization failed: {}", e)))?;
            use std::io::Write;
            writeln!(f, "{}", json).map_err(|e| Error::Storage(e.to_string()))?;
        }
        Ok(())
    }
}
