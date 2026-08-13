use async_trait::async_trait;
use parking_lot::RwLock;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::prelude::*;
use nettrap_fsutil::create_regular_file;

pub struct CsvStorage {
    writer: RwLock<Option<BufWriter<File>>>,
    path: PathBuf,
    header_written: RwLock<bool>,
}

impl CsvStorage {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            writer: RwLock::new(None),
            path: path.as_ref().to_path_buf(),
            header_written: RwLock::new(false),
        }
    }

    pub fn open(&self) -> Result<()> {
        let file = create_regular_file(self.path.as_path())?;
        *self.writer.write() = Some(BufWriter::new(file));
        *self.header_written.write() = false;

        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        let mut writer = self.writer.write();
        if let Some(ref mut w) = *writer {
            w.flush().map_err(|e| Error::Storage(e.to_string()))?;
        }
        *writer = None;
        Ok(())
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

    /// Escape a field for CSV (quote if it contains comma, quote, newline, or
    /// other line-breaking control characters).
    fn csv_escape(s: &str) -> String {
        let escaped = Self::csv_field_content(s);
        let needs_formula_guard = Self::needs_formula_guard(s);
        if needs_formula_guard
            || escaped != s
            || escaped.contains(',')
            || escaped.contains('"')
            || escaped.contains('\n')
            || escaped.contains('\r')
        {
            if needs_formula_guard {
                format!("\"'{}\"", escaped.replace('"', "\"\""))
            } else {
                format!("\"{}\"", escaped.replace('"', "\"\""))
            }
        } else {
            escaped
        }
    }

    fn csv_field_content(value: &str) -> String {
        use std::fmt::Write as _;

        let mut escaped = String::new();
        for ch in value.chars() {
            if (ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
                || matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}')
            {
                let _ = write!(escaped, "\\u{:04X}", ch as u32);
            } else {
                escaped.push(ch);
            }
        }
        escaped
    }

    fn needs_formula_guard(s: &str) -> bool {
        let trimmed = s.trim_start_matches(char::is_whitespace);
        matches!(trimmed.as_bytes().first(), Some(b'=' | b'+' | b'-' | b'@'))
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
            flow.metadata.total_bytes(),
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
            event.timestamp().to_rfc3339(),
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
        self.close()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::Duration as ChronoDuration;

    use super::CsvStorage;
    use crate::storage::Storage;
    use nettrap_core::Packet;
    use nettrap_core::prelude::{FiveTuple, Protocol};
    use nettrap_events::{Event, WarningEvent};
    use nettrap_flow::Flow;

    static TEMP_CSV_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_csv_path() -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let seq = TEMP_CSV_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("nettrap-csv-reopen-{pid}-{unique}-{seq}.csv"))
    }

    #[tokio::test]
    async fn reopen_rewrites_header_after_truncate() {
        let path = temp_csv_path();
        let storage = CsvStorage::new(&path);

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

    #[tokio::test]
    async fn store_flow_saturates_total_bytes_on_overflow() {
        let path = temp_csv_path();
        let storage = CsvStorage::new(&path);
        let mut flow = Flow::new(FiveTuple::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            53000,
            443,
            Protocol::Tcp,
        ));
        flow.metadata.bytes_sent = u64::MAX;
        flow.metadata.bytes_received = 1;

        storage.open().expect("csv storage should open");
        storage
            .store_flow(&flow)
            .await
            .expect("flow write should succeed");
        storage.flush().await.expect("csv storage should flush");
        Storage::close(&storage)
            .await
            .expect("csv storage should close");

        let contents = std::fs::read_to_string(&path).expect("csv file should be readable");
        assert!(
            contents
                .lines()
                .any(|line| line.contains(",18446744073709551615,"))
        );

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn store_flow_clamps_negative_duration_to_zero() {
        let path = temp_csv_path();
        let storage = CsvStorage::new(&path);
        let mut flow = Flow::new(FiveTuple::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            53000,
            443,
            Protocol::Tcp,
        ));
        flow.updated_at = flow.created_at - ChronoDuration::seconds(5);

        storage.open().expect("csv storage should open");
        storage
            .store_flow(&flow)
            .await
            .expect("flow write should succeed");
        storage.flush().await.expect("csv storage should flush");
        Storage::close(&storage)
            .await
            .expect("csv storage should close");

        let contents = std::fs::read_to_string(&path).expect("csv file should be readable");
        assert!(contents.contains("duration_ms=0"));
        assert!(!contents.contains("duration_ms=-"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn csv_escape_guards_formulas_after_leading_whitespace() {
        assert_eq!(CsvStorage::csv_escape("=cmd"), "\"'=cmd\"");
        assert_eq!(CsvStorage::csv_escape(" =cmd"), "\"' =cmd\"");
        assert_eq!(CsvStorage::csv_escape("\t@cmd"), "\"'\t@cmd\"");
        assert_eq!(CsvStorage::csv_escape("\u{00a0}=cmd"), "\"'\u{00a0}=cmd\"");
        assert_eq!(CsvStorage::csv_escape("normal"), "normal");
    }

    #[test]
    fn csv_escape_replaces_unicode_separators_and_controls() {
        assert_eq!(CsvStorage::csv_escape("a\u{2028}b"), "\"a\\u2028b\"");
        assert_eq!(CsvStorage::csv_escape("x\u{2029}y"), "\"x\\u2029y\"");
        assert_eq!(CsvStorage::csv_escape("p\u{0085}q"), "\"p\\u0085q\"");
        assert_eq!(CsvStorage::csv_escape("z\u{0001}z"), "\"z\\u0001z\"");
    }

    #[tokio::test]
    async fn store_event_uses_event_timestamp() {
        let path = temp_csv_path();
        let storage = CsvStorage::new(&path);
        let timestamp = chrono::DateTime::from_timestamp(1_704_067_200, 0)
            .expect("fixed timestamp should be valid");
        let event = Event::Warning(WarningEvent {
            timestamp,
            message: "fixture".to_string(),
            flow_id: None,
        });

        storage.open().expect("csv storage should open");
        storage
            .store_event(&event)
            .await
            .expect("event write should succeed");
        storage.flush().await.expect("csv storage should flush");
        Storage::close(&storage)
            .await
            .expect("csv storage should close");

        let contents = std::fs::read_to_string(&path).expect("csv file should be readable");
        assert!(contents.contains("2024-01-01T00:00:00+00:00,event"));

        let _ = std::fs::remove_file(path);
    }
}
