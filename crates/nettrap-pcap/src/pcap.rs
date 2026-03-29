use parking_lot::RwLock;
use std::fs::File;
use std::path::Path;

use crate::prelude::*;

/// PCAP global header (24 bytes) - libpcap format
const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_THISZONE: i32 = 0;
const PCAP_SIGFIGS: u32 = 0;
const PCAP_SNAPLEN: u32 = 65535;
const PCAP_LINKTYPE_RAW: u32 = 101; // LINKTYPE_RAW (raw IP)

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

        // Write PCAP global header
        self.write_global_header()?;

        Ok(())
    }

    pub fn close(&self) {
        let _ = self.flush();
        *self.file.write() = None;
        *self.enabled.write() = false;
    }

    fn write_global_header(&self) -> Result<()> {
        use std::io::Write;
        let mut file = self.file.write();
        if let Some(ref mut f) = *file {
            f.write_all(&PCAP_MAGIC.to_le_bytes())?;
            f.write_all(&PCAP_VERSION_MAJOR.to_le_bytes())?;
            f.write_all(&PCAP_VERSION_MINOR.to_le_bytes())?;
            f.write_all(&PCAP_THISZONE.to_le_bytes())?;
            f.write_all(&PCAP_SIGFIGS.to_le_bytes())?;
            f.write_all(&PCAP_SNAPLEN.to_le_bytes())?;
            f.write_all(&PCAP_LINKTYPE_RAW.to_le_bytes())?;
        }
        Ok(())
    }

    /// Write a packet record in PCAP format.
    /// Each record: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4) + data
    pub fn write_packet(&self, packet: &Packet) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        use std::io::Write;
        let mut file = self.file.write();
        if let Some(ref mut f) = *file {
            let ts_sec = packet.timestamp.timestamp() as u32;
            let ts_usec = packet.timestamp.timestamp_subsec_micros();
            let data = &packet.payload;
            let incl_len = data.len() as u32;
            let orig_len = packet.length as u32;

            // Packet record header (16 bytes)
            f.write_all(&ts_sec.to_le_bytes())?;
            f.write_all(&ts_usec.to_le_bytes())?;
            f.write_all(&incl_len.to_le_bytes())?;
            f.write_all(&orig_len.to_le_bytes())?;
            // Packet data
            f.write_all(data)?;
        }

        Ok(())
    }

    /// Write raw bytes as a PCAP packet with current timestamp
    pub fn write_raw(&self, data: &[u8]) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        use std::io::Write;
        let mut file = self.file.write();
        if let Some(ref mut f) = *file {
            let now = chrono::Utc::now();
            let ts_sec = now.timestamp() as u32;
            let ts_usec = now.timestamp_subsec_micros();
            let len = data.len() as u32;

            f.write_all(&ts_sec.to_le_bytes())?;
            f.write_all(&ts_usec.to_le_bytes())?;
            f.write_all(&len.to_le_bytes())?;
            f.write_all(&len.to_le_bytes())?;
            f.write_all(data)?;
        }

        Ok(())
    }

    /// Write a pair of packets (original + mangled) for comparison
    pub fn write_packet_pair(&self, original: &Packet, mangled: &Packet) -> Result<()> {
        self.write_packet(original)?;
        self.write_packet(mangled)?;
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
        // TODO: implement PCAP reading
        Ok(Vec::new())
    }
}
