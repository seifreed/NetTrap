use parking_lot::RwLock;
use std::path::{Path, PathBuf};

use crate::prelude::*;
use nettrap_fsutil::create_regular_file;

pub struct PacketWriter {
    file: RwLock<Option<std::fs::File>>,
    path: PathBuf,
}

impl PacketWriter {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(Error::Storage(
                "packet writer path must not be empty".to_string(),
            ));
        }

        Ok(Self {
            file: RwLock::new(None),
            path,
        })
    }

    pub fn open(&self) -> Result<()> {
        let file = create_regular_output_file(Path::new(&self.path))?;
        *self.file.write() = Some(file);

        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        let Some(mut file) = self.file.write().take() else {
            return Ok(());
        };

        use std::io::Write;
        file.flush().map_err(|e| Error::Storage(e.to_string()))
    }

    pub fn write_packet(&self, packet: &Packet) -> Result<()> {
        let mut file = self.file.write();
        let Some(ref mut f) = *file else {
            return Err(Error::Storage("packet writer is not open".to_string()));
        };

        let json = serde_json::to_string(packet)
            .map_err(|e| Error::Storage(format!("JSON serialization failed: {}", e)))?;
        use std::io::Write;
        writeln!(f, "{}", json).map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }
}

pub struct FlowWriter {
    file: RwLock<Option<std::fs::File>>,
    path: PathBuf,
}

impl FlowWriter {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(Error::Storage(
                "flow writer path must not be empty".to_string(),
            ));
        }

        Ok(Self {
            file: RwLock::new(None),
            path,
        })
    }

    pub fn open(&self) -> Result<()> {
        let file = create_regular_output_file(Path::new(&self.path))?;
        *self.file.write() = Some(file);

        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        let Some(mut file) = self.file.write().take() else {
            return Ok(());
        };

        use std::io::Write;
        file.flush().map_err(|e| Error::Storage(e.to_string()))
    }

    pub fn write_flow(&self, flow: &nettrap_flow::Flow) -> Result<()> {
        let mut file = self.file.write();
        let Some(ref mut f) = *file else {
            return Err(Error::Storage("flow writer is not open".to_string()));
        };

        let json = serde_json::to_string(flow)
            .map_err(|e| Error::Storage(format!("JSON serialization failed: {}", e)))?;
        use std::io::Write;
        writeln!(f, "{}", json).map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }
}

pub(crate) fn create_regular_output_file(path: &Path) -> Result<std::fs::File> {
    create_regular_file(path).map_err(|err| Error::Storage(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{FlowWriter, PacketWriter, create_regular_output_file};
    use nettrap_core::prelude::{FiveTuple, Packet, PacketDirection, Protocol};
    use std::net::{IpAddr, Ipv4Addr};

    fn simple_writer_path(kind: &str) -> String {
        format!(
            "nettrap-{kind}-writer-{}-{}.jsonl",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        )
    }

    #[test]
    fn packet_writer_accepts_simple_relative_path() {
        let _cwd_lock = crate::test_util::lock_current_dir();
        let path = simple_writer_path("packet");
        let writer = PacketWriter::new(path.clone()).expect("valid packet path");

        writer.open().expect("packet writer should open");
        writer.close().expect("packet writer should close");

        assert!(
            std::path::Path::new(&path).is_file(),
            "packet writer should create {path}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn packet_writer_rejects_symlinked_parent_directory() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-packet-writer-parent-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let real_parent = root.join("real");
        let linked_parent = root.join("linked");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");

        let writer =
            PacketWriter::new(linked_parent.join("packet.jsonl")).expect("valid packet path");
        let err = writer
            .open()
            .expect_err("symlinked parent should be rejected");

        assert!(err.to_string().contains("symlink"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn packet_writer_rejects_writes_before_open() {
        let writer =
            PacketWriter::new(simple_writer_path("packet-closed")).expect("valid packet path");
        let packet = Packet::new(
            FiveTuple::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                12345,
                53,
                Protocol::Udp,
            ),
            PacketDirection::Outbound,
            bytes::Bytes::from_static(b"test"),
        );

        let err = match writer.write_packet(&packet) {
            Ok(_) => panic!("closed packet writer should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("not open"));
    }

    #[test]
    fn flow_writer_accepts_simple_relative_path() {
        let _cwd_lock = crate::test_util::lock_current_dir();
        let path = simple_writer_path("flow");
        let writer = FlowWriter::new(path.clone()).expect("valid flow path");

        writer.open().expect("flow writer should open");
        writer.close().expect("flow writer should close");

        assert!(
            std::path::Path::new(&path).is_file(),
            "flow writer should create {path}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn create_regular_output_file_accepts_trailing_current_dir_component() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-pcap-output-curdir-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("capture.pcap");

        let file = create_regular_output_file(&path.join("."))
            .expect("trailing current-dir component should be accepted");

        assert!(file.metadata().expect("metadata").is_file());
        assert!(path.is_file());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn packet_writer_rejects_empty_path() {
        let err = match PacketWriter::new(std::path::PathBuf::new()) {
            Ok(_) => panic!("empty packet writer path should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn flow_writer_rejects_empty_path() {
        let err = match FlowWriter::new(std::path::PathBuf::new()) {
            Ok(_) => panic!("empty flow writer path should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("must not be empty"));
    }

    #[cfg(unix)]
    #[test]
    fn flow_writer_rejects_symlinked_parent_directory() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-flow-writer-parent-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let real_parent = root.join("real");
        let linked_parent = root.join("linked");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");

        let writer = FlowWriter::new(linked_parent.join("flow.jsonl")).expect("valid flow path");
        let err = writer
            .open()
            .expect_err("symlinked parent should be rejected");

        assert!(err.to_string().contains("symlink"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn packet_writer_accepts_non_utf8_output_path() {
        use std::os::unix::ffi::OsStringExt;

        let root = std::env::temp_dir().join(format!(
            "nettrap-packet-writer-nonutf8-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join(std::ffi::OsString::from_vec(b"packet-\xff.jsonl".to_vec()));

        let writer = PacketWriter::new(&path).expect("valid packet path");
        writer.open().expect("packet writer should open");
        writer.close().expect("packet writer should close");

        assert!(path.is_file());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn flow_writer_accepts_non_utf8_output_path() {
        use std::os::unix::ffi::OsStringExt;

        let root = std::env::temp_dir().join(format!(
            "nettrap-flow-writer-nonutf8-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join(std::ffi::OsString::from_vec(b"flow-\xff.jsonl".to_vec()));

        let writer = FlowWriter::new(&path).expect("valid flow path");
        writer.open().expect("flow writer should open");
        writer.close().expect("flow writer should close");

        assert!(path.is_file());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn packet_writer_close_is_idempotent_after_flush() {
        let path = simple_writer_path("packet-idempotent-close");
        let writer = PacketWriter::new(path.clone()).expect("valid packet path");

        writer.open().expect("packet writer should open");
        writer.close().expect("first close should flush");
        writer.close().expect("second close should be a no-op");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn flow_writer_close_is_idempotent_after_flush() {
        let path = simple_writer_path("flow-idempotent-close");
        let writer = FlowWriter::new(path.clone()).expect("valid flow path");

        writer.open().expect("flow writer should open");
        writer.close().expect("first close should flush");
        writer.close().expect("second close should be a no-op");

        let _ = std::fs::remove_file(path);
    }
}
