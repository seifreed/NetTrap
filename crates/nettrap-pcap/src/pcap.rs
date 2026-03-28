use parking_lot::RwLock;
use std::fs::File;
use std::path::Path;

use crate::prelude::*;

pub struct PcapWriter {
    file: RwLock<Option<File>>,
    path: String,
    enabled: RwLock<bool>,
}

impl PcapWriter {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            file: RwLock::new(None),
            path: path.into(),
            enabled: RwLock::new(false),
        }
    }

    pub fn enable(&self) {
        *self.enabled.write() = true;
    }

    pub fn disable(&self) {
        *self.enabled.write() = false;
    }

    pub fn is_enabled(&self) -> bool {
        *self.enabled.read()
    }

    pub fn open(&self) -> Result<()> {
        let path = Path::new(&self.path);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = File::create(&self.path)?;
        *self.file.write() = Some(file);
        *self.enabled.write() = true;

        Ok(())
    }

    pub fn close(&self) {
        *self.file.write() = None;
        *self.enabled.write() = false;
    }

    pub fn write_packet(&self, packet: &Packet) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        use std::io::Write;
        let mut file = self.file.write();
        if let Some(ref mut f) = *file {
            let ts_sec = packet.timestamp.timestamp() as u32;
            let ts_usec = packet.timestamp.timestamp_subsec_micros();
            let len = packet.payload.len() as u32;

            f.write_all(&ts_sec.to_le_bytes())?;
            f.write_all(&ts_usec.to_le_bytes())?;
            f.write_all(&len.to_le_bytes())?;
            f.write_all(&len.to_le_bytes())?;
            f.write_all(&packet.payload)?;
        }

        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        use std::io::Write;
        let mut file = self.file.write();
        if let Some(ref mut f) = *file {
            f.flush()?;
        }
        Ok(())
    }
}

pub struct PcapReader {
    path: String,
}

impl PcapReader {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }

    pub fn read_file(&self) -> Result<Vec<Packet>> {
        let _file = File::open(&self.path)?;
        Ok(Vec::new())
    }
}
