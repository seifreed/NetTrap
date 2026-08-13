use async_trait::async_trait;
use parking_lot::RwLock;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::prelude::*;
use nettrap_fsutil::create_regular_file;

/// Streaming JSON-array storage backend.
///
/// Records are appended one at a time behind a `[ … ]` envelope so memory
/// stays bounded (no in-memory buffering of the whole dataset). The on-disk
/// file is a complete, valid JSON document only after [`Storage::close`] has
/// run; mid-stream (after a bare [`Storage::flush`]) it is a partial document,
/// the same way JSONL is only complete line-by-line.
struct JsonWriterState {
    writer: BufWriter<File>,
    wrote_any: bool,
    closing_written: bool,
}

pub struct JsonStorage {
    state: RwLock<Option<JsonWriterState>>,
    path: PathBuf,
}

impl JsonStorage {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            state: RwLock::new(None),
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn open(&self) -> Result<()> {
        let file = create_regular_file(self.path.as_path())?;
        let mut writer = BufWriter::new(file);
        write!(writer, "[").map_err(|e| Error::Storage(e.to_string()))?;
        *self.state.write() = Some(JsonWriterState {
            writer,
            wrote_any: false,
            closing_written: false,
        });

        Ok(())
    }

    /// Append one serialized record as an array element, minimizing lock hold
    /// time (serialization happens in the caller, outside the lock).
    fn write_record(&self, json: &str) -> Result<()> {
        let mut guard = self.state.write();
        let state = guard
            .as_mut()
            .ok_or_else(|| Error::Storage("Storage not opened — call open() first".to_string()))?;
        if state.closing_written {
            return Err(Error::Storage(
                "Storage close is pending after a previous close failure".to_string(),
            ));
        }
        if state.wrote_any {
            write!(state.writer, ",").map_err(|e| Error::Storage(e.to_string()))?;
        }
        write!(state.writer, "\n  {}", json).map_err(|e| Error::Storage(e.to_string()))?;
        state.wrote_any = true;
        Ok(())
    }
}

#[async_trait]
impl Storage for JsonStorage {
    async fn store_flow(&self, flow: &Flow) -> Result<()> {
        let json = serde_json::to_string(flow).map_err(|e| Error::Storage(e.to_string()))?;
        self.write_record(&json)
    }

    async fn store_packet(&self, packet: &Packet) -> Result<()> {
        let json = serde_json::to_string(packet).map_err(|e| Error::Storage(e.to_string()))?;
        self.write_record(&json)
    }

    async fn store_event(&self, event: &nettrap_events::Event) -> Result<()> {
        let json = serde_json::to_string(event).map_err(|e| Error::Storage(e.to_string()))?;
        self.write_record(&json)
    }

    async fn flush(&self) -> Result<()> {
        let mut guard = self.state.write();
        if let Some(state) = guard.as_mut() {
            state
                .writer
                .flush()
                .map_err(|e| Error::Storage(e.to_string()))?;
        }
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        let mut guard = self.state.write();
        if let Some(state) = guard.as_mut() {
            finish_json_writer(
                &mut state.writer,
                state.wrote_any,
                &mut state.closing_written,
            )?;
            // Idempotent: only remove state after the final bracket has been
            // flushed. A failed close can then be retried without
            // appending a second bracket or losing buffered data.
            guard.take();
        }
        Ok(())
    }
}

fn finish_json_writer<W: Write>(
    writer: &mut W,
    wrote_any: bool,
    closing_written: &mut bool,
) -> Result<()> {
    if !*closing_written {
        if wrote_any {
            write!(writer, "\n]").map_err(|e| Error::Storage(e.to_string()))?;
        } else {
            write!(writer, "]").map_err(|e| Error::Storage(e.to_string()))?;
        }
        *closing_written = true;
    }
    writer.flush().map_err(|e| Error::Storage(e.to_string()))
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use super::finish_json_writer;

    struct FailFlushOnce {
        bytes: Vec<u8>,
        fail_next_flush: bool,
    }

    impl FailFlushOnce {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                fail_next_flush: true,
            }
        }
    }

    impl Write for FailFlushOnce {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail_next_flush {
                self.fail_next_flush = false;
                Err(io::Error::other("synthetic flush failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn close_retry_does_not_duplicate_json_array_terminator_after_flush_failure() {
        let mut writer = FailFlushOnce::new();
        writer.bytes.extend_from_slice(b"[\n  {}");
        let mut closing_written = false;

        let err = finish_json_writer(&mut writer, true, &mut closing_written)
            .expect_err("first close should surface flush failure");

        assert!(err.to_string().contains("synthetic flush failure"));
        assert!(closing_written);
        assert_eq!(writer.bytes, b"[\n  {}\n]");

        finish_json_writer(&mut writer, true, &mut closing_written)
            .expect("retry should only flush the existing terminator");

        assert_eq!(writer.bytes, b"[\n  {}\n]");
    }
}
