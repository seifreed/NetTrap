use async_trait::async_trait;
use parking_lot::RwLock;
use std::fs::File;
use std::io::{BufWriter, Write};

use crate::prelude::*;

pub struct CsvStorage {
    writer: RwLock<Option<BufWriter<File>>>,
    path: String,
    header_written: RwLock<bool>,
}

impl CsvStorage {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            writer: RwLock::new(None),
            path: path.into(),
            header_written: RwLock::new(false),
        }
    }

    pub fn open(&self) -> Result<()> {
        let path = std::path::Path::new(&self.path);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = File::create(path)?;
        *self.writer.write() = Some(BufWriter::new(file));
        *self.header_written.write() = false;

        Ok(())
    }

    pub fn close(&self) {
        let mut writer = self.writer.write();
        if let Some(ref mut w) = *writer {
            let _ = w.flush();
        }
        *writer = None;
    }

    fn ensure_header(&self, w: &mut BufWriter<File>) -> Result<()> {
        let mut written = self.header_written.write();
        if !*written {
            writeln!(
                w,
                "timestamp,type,src_ip,src_port,dst_ip,dst_port,protocol,direction,length,details"
            )
            .map_err(|e| Error::Storage(e.to_string()))?;
            *written = true;
        }
        Ok(())
    }

    /// Escape a field for CSV (quote if it contains comma, quote, or newline)
    fn csv_escape(s: &str) -> String {
        // Sanitize CSV formula injection (values starting with =, +, -, @)
        let needs_formula_guard =
            s.starts_with('=') || s.starts_with('+') || s.starts_with('-') || s.starts_with('@');
        if needs_formula_guard
            || s.contains(',')
            || s.contains('"')
            || s.contains('\n')
            || s.contains('\r')
        {
            if needs_formula_guard {
                format!("\"'{}\"", s.replace('"', "\"\""))
            } else {
                format!("\"{}\"", s.replace('"', "\"\""))
            }
        } else {
            s.to_string()
        }
    }
}

#[async_trait]
impl Storage for CsvStorage {
    async fn store_flow(&self, flow: &Flow) -> Result<()> {
        let mut writer = self.writer.write();
        let w = writer
            .as_mut()
            .ok_or_else(|| Error::Storage("CSV storage not opened — call open() first".into()))?;
        self.ensure_header(w)?;

        let direction = format!("{:?}", flow.direction);
        let details = format!("state={:?} duration_ms={}", flow.state, flow.duration_ms());
        let line = format!(
            "{},flow,{},{},{},{},{},{},{},{}",
            flow.created_at.to_rfc3339(),
            flow.five_tuple.src_ip,
            flow.five_tuple.src_port,
            flow.five_tuple.dst_ip,
            flow.five_tuple.dst_port,
            flow.five_tuple.protocol,
            direction,
            flow.metadata.bytes_sent + flow.metadata.bytes_received,
            Self::csv_escape(&details),
        );
        writeln!(w, "{}", line).map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    async fn store_packet(&self, packet: &Packet) -> Result<()> {
        let mut writer = self.writer.write();
        let w = writer
            .as_mut()
            .ok_or_else(|| Error::Storage("CSV storage not opened — call open() first".into()))?;
        self.ensure_header(w)?;

        let direction = format!("{:?}", packet.direction);
        let details = format!("type={:?}", packet.packet_type);
        let line = format!(
            "{},packet,{},{},{},{},{},{},{},{}",
            packet.timestamp.to_rfc3339(),
            packet.five_tuple.src_ip,
            packet.five_tuple.src_port,
            packet.five_tuple.dst_ip,
            packet.five_tuple.dst_port,
            packet.five_tuple.protocol,
            direction,
            packet.length,
            Self::csv_escape(&details),
        );
        writeln!(w, "{}", line).map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    async fn store_event(&self, event: &nettrap_events::Event) -> Result<()> {
        let mut writer = self.writer.write();
        let w = writer
            .as_mut()
            .ok_or_else(|| Error::Storage("CSV storage not opened — call open() first".into()))?;
        self.ensure_header(w)?;

        let line = format!(
            "{},event,,,,,,,,{}",
            chrono::Utc::now().to_rfc3339(),
            Self::csv_escape(event.event_type()),
        );
        writeln!(w, "{}", line).map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        let mut writer = self.writer.write();
        if let Some(ref mut w) = *writer {
            w.flush().map_err(|e| Error::Storage(e.to_string()))?;
        }
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        let mut writer = self.writer.write();
        if let Some(ref mut w) = *writer {
            w.flush().map_err(|e| Error::Storage(e.to_string()))?;
        }
        *writer = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::CsvStorage;
    use crate::storage::Storage;
    use nettrap_core::Packet;

    fn temp_csv_path() -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        std::env::temp_dir().join(format!("nettrap-csv-reopen-{unique}.csv"))
    }

    #[tokio::test]
    async fn reopen_rewrites_header_after_truncate() {
        let path = temp_csv_path();
        let storage = CsvStorage::new(path.to_string_lossy().into_owned());

        storage.open().expect("first open should succeed");
        storage
            .store_packet(&Packet::default())
            .await
            .expect("first write should succeed");
        storage.flush().await.expect("first flush should succeed");
        Storage::close(&storage)
            .await
            .expect("first close should succeed");

        storage.open().expect("second open should succeed");
        storage
            .store_packet(&Packet::default())
            .await
            .expect("second write should succeed");
        storage.flush().await.expect("second flush should succeed");
        Storage::close(&storage)
            .await
            .expect("second close should succeed");

        let contents = std::fs::read_to_string(&path).expect("csv file should be readable");
        let lines: Vec<&str> = contents.lines().collect();

        assert_eq!(
            lines.len(),
            2,
            "reopened file should contain header plus one row"
        );
        assert_eq!(
            lines[0],
            "timestamp,type,src_ip,src_port,dst_ip,dst_port,protocol,direction,length,details"
        );

        let _ = std::fs::remove_file(path);
    }
}
