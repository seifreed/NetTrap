use crate::prelude::*;
use async_trait::async_trait;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use nettrap_fsutil::ensure_no_symlink_ancestors;
use nettrap_fsutil::ensure_regular_file;
use nettrap_fsutil::open_regular_file_beneath_root;

const MAX_TFTP_SERVE_BYTES: u64 = 8 * 1024 * 1024;
const REDACTED_TFTP_FIELD: &str = "***REDACTED***";

#[derive(Debug)]
pub struct TftpHandler {
    root_dir: Option<PathBuf>,
    upload_prefix: String,
    default_content: Vec<u8>,
}

impl TftpHandler {
    pub fn new() -> Self {
        Self {
            root_dir: None,
            upload_prefix: "tftp_upload".to_string(),
            default_content: b"NetTrap TFTP default file content\n".to_vec(),
        }
    }

    pub fn with_root_dir(mut self, dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        if dir.as_os_str().is_empty() {
            return Err(Error::Config(
                "TFTP root directory must not be empty".to_string(),
            ));
        }
        self.root_dir = Some(dir);
        Ok(self)
    }

    pub fn with_upload_prefix(mut self, prefix: impl Into<String>) -> Result<Self> {
        let prefix = prefix.into();
        if prefix.trim_matches([' ', '\t']).is_empty() {
            return Err(Error::Config(
                "TFTP upload prefix must not be blank".to_string(),
            ));
        }
        if !prefix.is_ascii()
            || prefix.chars().any(|ch| ch.is_control())
            || !crate::tftp::tftp_filename_is_safe(&prefix)
        {
            return Err(Error::Config(
                "TFTP upload prefix must be a safe relative path".to_string(),
            ));
        }
        self.upload_prefix = prefix;
        Ok(self)
    }

    pub fn with_default_content(mut self, content: Vec<u8>) -> Result<Self> {
        if content.len() as u64 > MAX_TFTP_SERVE_BYTES {
            return Err(Error::Config(format!(
                "TFTP default content exceeds serve limit ({} > {} bytes)",
                content.len(),
                MAX_TFTP_SERVE_BYTES
            )));
        }
        self.default_content = content;
        Ok(self)
    }

    pub fn upload_prefix(&self) -> &str {
        &self.upload_prefix
    }

    /// Handle a RRQ - returns only the first DATA packet.
    ///
    /// TFTP is lock-step: additional blocks must only be sent after ACKs.
    pub fn handle_read_request(&self, filename: &str) -> Vec<TftpPacket> {
        tracing::debug!(
            "TFTP RRQ for file: {}",
            nettrap_core::sanitize::single_line(filename)
        );
        vec![self.handle_read_request_block(filename, 1)]
    }

    pub fn handle_read_request_block(&self, filename: &str, block: u16) -> TftpPacket {
        tracing::debug!(
            "TFTP RRQ block {} for file: {}",
            block,
            nettrap_core::sanitize::single_line(filename)
        );

        if block == 0 {
            return TftpPacket::Error {
                code: 4,
                message: "Invalid block".to_string(),
            };
        }

        if let Some(ref root) = self.root_dir {
            self.read_file_block(root, filename, block)
        } else {
            TftpPacket::Data {
                block,
                data: self.default_content_block(block),
            }
        }
    }

    fn read_file_block(&self, root: &Path, filename: &str, block: u16) -> TftpPacket {
        let mut file = match open_regular_file_beneath_root(root, Path::new(filename)) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return TftpPacket::Data {
                    block,
                    data: self.default_content_block(block),
                };
            }
            Err(err) => {
                tracing::debug!(
                    "TFTP read blocked for {}: {}",
                    nettrap_core::sanitize::single_line(filename),
                    err
                );
                tracing::warn!("TFTP read blocked for {}: {}", REDACTED_TFTP_FIELD, err);
                return TftpPacket::Error {
                    code: 2,
                    message: "Access violation".to_string(),
                };
            }
        };

        let metadata = match file.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                return TftpPacket::Error {
                    code: 2,
                    message: "Access violation".to_string(),
                };
            }
        };
        if !metadata.is_file() || metadata.len() > MAX_TFTP_SERVE_BYTES {
            return TftpPacket::Error {
                code: 2,
                message: "Access violation".to_string(),
            };
        }

        let offset = (u64::from(block) - 1) * TFTP_BLOCK_SIZE as u64;
        if offset > metadata.len() {
            return TftpPacket::Data {
                block,
                data: Vec::new(),
            };
        }

        read_open_file_block(&mut file, filename, block, offset)
    }

    fn default_content_block(&self, block: u16) -> Vec<u8> {
        let offset = (usize::from(block) - 1) * TFTP_BLOCK_SIZE;
        if offset >= self.default_content.len() {
            return Vec::new();
        }
        let end = offset
            .saturating_add(TFTP_BLOCK_SIZE)
            .min(self.default_content.len());
        self.default_content
            .get(offset..end)
            .unwrap_or_default()
            .to_vec()
    }

    /// Handle WRQ - returns initial ACK (block 0)
    pub fn handle_write_request(&self, filename: &str) -> TftpPacket {
        tracing::debug!(
            "TFTP WRQ for file: {} (upload prefix: {})",
            nettrap_core::sanitize::single_line(filename),
            nettrap_core::sanitize::single_line(&self.upload_prefix)
        );
        TftpPacket::Ack { block: 0 }
    }

    pub fn open_upload_file(&self, filename: &str) -> Result<Option<std::fs::File>> {
        let Some(root) = &self.root_dir else {
            return Ok(None);
        };

        if !crate::tftp::tftp_filename_is_safe(filename) {
            return Err(Error::Protocol(
                "TFTP packet contains unsafe text".to_string(),
            ));
        }

        let path = root.join(&self.upload_prefix).join(filename);
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            ensure_no_symlink_ancestors(parent)?;
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(ensure_regular_file)
            .map_err(|err| {
                Error::Io(std::io::Error::new(
                    err.kind(),
                    format!("failed to open TFTP upload path {:?}: {}", path, err),
                ))
            })?;
        Ok(Some(file))
    }

    /// Handle incoming DATA block during a write transfer
    pub fn handle_data_block(&self, block: u16, data: &[u8]) -> TftpPacket {
        tracing::debug!("TFTP DATA block {} ({} bytes)", block, data.len());
        TftpPacket::Ack { block }
    }
}

impl Default for TftpHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait TftpHandlerTrait: Send + Sync {
    async fn handle_packet(&self, packet: &TftpPacket) -> Result<Vec<TftpPacket>>;
    fn name(&self) -> &'static str;
}

#[async_trait]
impl TftpHandlerTrait for TftpHandler {
    async fn handle_packet(&self, packet: &TftpPacket) -> Result<Vec<TftpPacket>> {
        match packet {
            TftpPacket::ReadRequest {
                options, filename, ..
            } if !options.is_empty() => Ok(vec![option_negotiation_failed(filename)]),
            TftpPacket::ReadRequest { filename, .. } => Ok(self.handle_read_request(filename)),
            TftpPacket::WriteRequest {
                options, filename, ..
            } if !options.is_empty() => Ok(vec![option_negotiation_failed(filename)]),
            TftpPacket::WriteRequest { filename, .. } => {
                Ok(vec![self.handle_write_request(filename)])
            }
            TftpPacket::Data { .. } => Ok(Vec::new()),
            TftpPacket::Ack { .. } => {
                Ok(Vec::new()) // ACKs don't need responses in server mode
            }
            TftpPacket::Error { code, message } => {
                tracing::debug!(
                    "TFTP error from client: {} - {}",
                    code,
                    nettrap_core::sanitize::single_line(message)
                );
                tracing::warn!("TFTP error from client: {} - {}", code, REDACTED_TFTP_FIELD);
                Ok(Vec::new())
            }
        }
    }

    fn name(&self) -> &'static str {
        "tftp"
    }
}

pub fn option_negotiation_failed(filename: &str) -> TftpPacket {
    tracing::debug!(
        "TFTP request for {} included unsupported options",
        nettrap_core::sanitize::single_line(filename)
    );
    TftpPacket::Error {
        code: 8,
        message: "Option negotiation failed".to_string(),
    }
}

fn read_open_file_block<R: Read + Seek>(
    file: &mut R,
    filename: &str,
    block: u16,
    offset: u64,
) -> TftpPacket {
    if let Err(err) = file.seek(SeekFrom::Start(offset)) {
        return read_failed_packet(filename, err);
    }

    let mut data = vec![0u8; TFTP_BLOCK_SIZE];
    let n = match file.read(&mut data) {
        Ok(n) => n,
        Err(err) => return read_failed_packet(filename, err),
    };
    data.truncate(n);
    TftpPacket::Data { block, data }
}

fn read_failed_packet(filename: &str, err: io::Error) -> TftpPacket {
    tracing::debug!(
        "TFTP read failed for {}: {}",
        nettrap_core::sanitize::single_line(filename),
        err
    );
    tracing::warn!("TFTP read failed for {}: {}", REDACTED_TFTP_FIELD, err);
    TftpPacket::Error {
        code: 0,
        message: "Read failed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG_FIELD_PREVIEW_CHARS: usize = 240;
    use std::io::Write;

    #[test]
    fn rrq_returns_only_first_block() {
        let handler = TftpHandler::new()
            .with_default_content(vec![b'a'; TFTP_BLOCK_SIZE * 3])
            .expect("bounded default content should be accepted");

        let packets = handler.handle_read_request("large.bin");

        assert_eq!(packets.len(), 1);
        match packets.first() {
            Some(TftpPacket::Data { block, data })
                if *block == 1 && data.len() == TFTP_BLOCK_SIZE => {}
            _ => panic!("expected first packet to be data block 1"),
        }
    }

    #[test]
    fn rejects_default_content_over_serve_limit() {
        let err =
            match TftpHandler::new()
                .with_default_content(vec![0; MAX_TFTP_SERVE_BYTES as usize + 1])
            {
                Ok(_) => panic!("oversized default content should fail"),
                Err(err) => err,
            };

        assert!(
            err.to_string()
                .contains("default content exceeds serve limit")
        );
    }

    #[test]
    fn reads_requested_file_block_without_loading_all_blocks() {
        let root = unique_temp_dir("nettrap-tftp-block");
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("firmware.bin");
        let mut file = std::fs::File::create(&path).expect("create fixture");
        file.write_all(&vec![b'a'; TFTP_BLOCK_SIZE])
            .expect("write first block");
        file.write_all(b"tail").expect("write tail");

        let handler = TftpHandler::new()
            .with_root_dir(&root)
            .expect("valid TFTP root");
        let first = handler.handle_read_request("firmware.bin");
        let second = handler.handle_read_request_block("firmware.bin", 2);

        match first.first() {
            Some(TftpPacket::Data { block, data })
                if *block == 1 && data.len() == TFTP_BLOCK_SIZE => {}
            _ => panic!("expected first packet to be data block 1"),
        }
        assert!(matches!(
            second,
            TftpPacket::Data { block: 2, data } if data == b"tail"
        ));

        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn rejects_files_over_serve_limit() {
        let root = unique_temp_dir("nettrap-tftp-limit");
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("huge.bin");
        let file = std::fs::File::create(&path).expect("create sparse file");
        file.set_len(MAX_TFTP_SERVE_BYTES + 1)
            .expect("extend sparse file");

        let handler = TftpHandler::new()
            .with_root_dir(&root)
            .expect("valid TFTP root");
        let packet = handler.handle_read_request_block("huge.bin", 1);

        assert!(matches!(packet, TftpPacket::Error { code: 2, .. }));

        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn read_failures_return_error_packet_instead_of_empty_data() {
        struct FailingRead;

        impl Read for FailingRead {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "synthetic read failure",
                ))
            }
        }

        impl Seek for FailingRead {
            fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
                Ok(0)
            }
        }

        let mut file = FailingRead;
        let packet = read_open_file_block(&mut file, "firmware.bin", 1, 0);

        assert!(matches!(
            packet,
            TftpPacket::Error { code: 0, message } if message == "Read failed"
        ));
    }

    #[test]
    fn seek_failures_return_error_packet_instead_of_empty_data() {
        struct FailingSeek;

        impl Read for FailingSeek {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Ok(0)
            }
        }

        impl Seek for FailingSeek {
            fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "synthetic seek failure",
                ))
            }
        }

        let mut file = FailingSeek;
        let packet = read_open_file_block(&mut file, "firmware.bin", 1, 0);

        assert!(matches!(
            packet,
            TftpPacket::Error { code: 0, message } if message == "Read failed"
        ));
    }

    #[test]
    fn requests_with_options_fail_without_silent_downgrade() {
        assert!(matches!(
            option_negotiation_failed("firmware.bin"),
            TftpPacket::Error { code: 8, message } if message == "Option negotiation failed"
        ));
    }

    #[test]
    fn upload_prefix_setter_updates_handler_configuration() {
        let handler = TftpHandler::new()
            .with_upload_prefix("incoming")
            .expect("valid upload prefix");

        assert_eq!(handler.upload_prefix(), "incoming");
    }

    #[test]
    fn upload_prefix_rejects_blank_or_control_prefixes() {
        assert!(TftpHandler::new().with_upload_prefix("   ").is_err());
        assert!(
            TftpHandler::new()
                .with_upload_prefix("bad\nprefix")
                .is_err()
        );
        assert!(
            TftpHandler::new()
                .with_upload_prefix("incoming\u{00a0}")
                .is_err()
        );
    }

    #[test]
    fn upload_prefix_rejects_path_traversal_components() {
        assert!(
            TftpHandler::new()
                .with_upload_prefix("../incoming")
                .is_err()
        );
        assert!(TftpHandler::new().with_upload_prefix("/incoming").is_err());
        assert!(TftpHandler::new().with_upload_prefix("./incoming").is_err());
    }

    #[test]
    fn upload_rejects_current_dir_filename_before_opening_prefix_path() {
        let root = unique_temp_dir("nettrap-tftp-upload-dot");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        let handler = TftpHandler::new()
            .with_root_dir(&root)
            .expect("valid TFTP root");

        assert!(handler.open_upload_file(".").is_err());
        assert!(!root.join(handler.upload_prefix()).exists());

        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn upload_rejects_non_ascii_filename_before_opening_prefix_path() {
        let root = unique_temp_dir("nettrap-tftp-upload-nonascii");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        let handler = TftpHandler::new()
            .with_root_dir(&root)
            .expect("valid TFTP root");

        assert!(handler.open_upload_file("firmware\u{00a0}.bin").is_err());
        assert!(!root.join(handler.upload_prefix()).exists());

        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn upload_rejects_existing_file_without_truncating_it() {
        let root = unique_temp_dir("nettrap-tftp-upload-existing");
        let _ = std::fs::remove_dir_all(&root);
        let upload_dir = root.join("incoming");
        std::fs::create_dir_all(&upload_dir).expect("create upload dir");
        let path = upload_dir.join("firmware.bin");
        std::fs::write(&path, b"existing").expect("write existing upload");
        let handler = TftpHandler::new()
            .with_root_dir(&root)
            .expect("valid TFTP root")
            .with_upload_prefix("incoming")
            .expect("valid upload prefix");

        assert!(handler.open_upload_file("firmware.bin").is_err());
        assert_eq!(
            std::fs::read(&path).expect("read existing upload"),
            b"existing"
        );

        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[test]
    fn with_root_dir_rejects_empty_path() {
        let err = TftpHandler::new()
            .with_root_dir(PathBuf::new())
            .expect_err("empty root directory should be rejected");

        assert!(matches!(err, Error::Config(message) if message.contains("must not be empty")));
    }

    #[test]
    fn logged_tftp_fields_are_single_line() {
        let filename = nettrap_core::sanitize::single_line("firmware\n.bin\x1b");
        let message = nettrap_core::sanitize::single_line("client\r\nerror\x1b");

        assert_eq!(filename, "firmware .bin ");
        assert_eq!(message, "client  error ");
        assert!(!filename.chars().any(char::is_control));
        assert!(!message.chars().any(char::is_control));

        let long = "a".repeat(LOG_FIELD_PREVIEW_CHARS + 1);
        assert_eq!(
            nettrap_core::sanitize::single_line(&long).len(),
            LOG_FIELD_PREVIEW_CHARS
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_final_symlink_inside_root() {
        use std::os::unix::fs::symlink;

        let root = unique_temp_dir("nettrap-tftp-symlink");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(root.join("real.bin"), b"secret").expect("write fixture");
        symlink("real.bin", root.join("link.bin")).expect("create symlink");

        let handler = TftpHandler::new()
            .with_root_dir(&root)
            .expect("valid TFTP root");
        let packet = handler.handle_read_request_block("link.bin", 1);

        assert!(matches!(packet, TftpPacket::Error { code: 2, .. }));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_intermediate_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = unique_temp_dir("nettrap-tftp-intermediate-symlink");
        let outside = unique_temp_dir("nettrap-tftp-intermediate-outside");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::create_dir_all(&outside).expect("create outside dir");
        std::fs::write(outside.join("secret.bin"), b"secret").expect("write outside fixture");
        symlink(&outside, root.join("dir")).expect("create intermediate symlink");

        let handler = TftpHandler::new()
            .with_root_dir(&root)
            .expect("valid TFTP root");
        let packet = handler.handle_read_request_block("dir/secret.bin", 1);

        assert!(matches!(packet, TftpPacket::Error { code: 2, .. }));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
        std::fs::remove_dir_all(outside).expect("cleanup outside dir");
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!("{}-{}", prefix, std::process::id()))
    }
}
