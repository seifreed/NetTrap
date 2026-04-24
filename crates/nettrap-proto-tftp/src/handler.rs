use crate::prelude::*;
use async_trait::async_trait;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const MAX_TFTP_SERVE_BYTES: u64 = 8 * 1024 * 1024;

#[cfg(unix)]
fn open_regular_file_no_final_symlink(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure_regular_file(file)
}

#[cfg(windows)]
fn open_regular_file_no_final_symlink(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    ensure_regular_file(file)
}

#[cfg(not(any(unix, windows)))]
fn open_regular_file_no_final_symlink(path: &Path) -> io::Result<File> {
    ensure_regular_file(File::open(path)?)
}

fn ensure_regular_file(file: File) -> io::Result<File> {
    if file.metadata()?.is_file() {
        Ok(file)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ))
    }
}

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

    pub fn with_root_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.root_dir = Some(dir.into());
        self
    }

    pub fn with_upload_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.upload_prefix = prefix.into();
        self
    }

    pub fn with_default_content(mut self, content: Vec<u8>) -> Self {
        self.default_content = content;
        self
    }

    /// Handle a RRQ - returns only the first DATA packet.
    ///
    /// TFTP is lock-step: additional blocks must only be sent after ACKs.
    pub fn handle_read_request(&self, filename: &str) -> Vec<TftpPacket> {
        tracing::debug!("TFTP RRQ for file: {}", filename);
        vec![self.handle_read_request_block(filename, 1)]
    }

    pub fn handle_read_request_block(&self, filename: &str, block: u16) -> TftpPacket {
        tracing::debug!("TFTP RRQ block {} for file: {}", block, filename);

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
        let canonical_root = match root.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("TFTP root dir canonicalize failed: {}", e);
                return TftpPacket::Error {
                    code: 2,
                    message: "Access violation".to_string(),
                };
            }
        };
        let path = canonical_root.join(filename);
        match path.canonicalize() {
            Ok(p) if p.starts_with(&canonical_root) => {}
            Ok(_) => {
                tracing::warn!("TFTP path traversal attempt: {}", filename);
                return TftpPacket::Error {
                    code: 2,
                    message: "Access violation".to_string(),
                };
            }
            Err(_) => {
                return TftpPacket::Data {
                    block,
                    data: self.default_content_block(block),
                };
            }
        }

        let mut file = match open_regular_file_no_final_symlink(&path) {
            Ok(file) => file,
            Err(_) => {
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

        if file.seek(SeekFrom::Start(offset)).is_err() {
            return TftpPacket::Data {
                block,
                data: Vec::new(),
            };
        }

        let mut data = vec![0u8; TFTP_BLOCK_SIZE];
        let n = file.read(&mut data).unwrap_or(0);
        data.truncate(n);
        TftpPacket::Data { block, data }
    }

    fn default_content_block(&self, block: u16) -> Vec<u8> {
        let offset = (usize::from(block) - 1) * TFTP_BLOCK_SIZE;
        if offset >= self.default_content.len() {
            return Vec::new();
        }
        let end = offset
            .saturating_add(TFTP_BLOCK_SIZE)
            .min(self.default_content.len());
        self.default_content[offset..end].to_vec()
    }

    /// Handle WRQ - returns initial ACK (block 0)
    pub fn handle_write_request(&self, filename: &str) -> TftpPacket {
        tracing::debug!("TFTP WRQ for file: {}", filename);
        TftpPacket::Ack { block: 0 }
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
            TftpPacket::ReadRequest { filename, .. } => Ok(self.handle_read_request(filename)),
            TftpPacket::WriteRequest { filename, .. } => {
                Ok(vec![self.handle_write_request(filename)])
            }
            TftpPacket::Data { .. } => Ok(Vec::new()),
            TftpPacket::Ack { .. } => {
                Ok(Vec::new()) // ACKs don't need responses in server mode
            }
            TftpPacket::Error { code, message } => {
                tracing::warn!("TFTP error from client: {} - {}", code, message);
                Ok(Vec::new())
            }
        }
    }

    fn name(&self) -> &'static str {
        "tftp"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn rrq_returns_only_first_block() {
        let handler = TftpHandler::new().with_default_content(vec![b'a'; TFTP_BLOCK_SIZE * 3]);

        let packets = handler.handle_read_request("large.bin");

        assert_eq!(packets.len(), 1);
        assert!(matches!(
            &packets[0],
            TftpPacket::Data { block: 1, data } if data.len() == TFTP_BLOCK_SIZE
        ));
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

        let handler = TftpHandler::new().with_root_dir(&root);
        let first = handler.handle_read_request("firmware.bin");
        let second = handler.handle_read_request_block("firmware.bin", 2);

        assert!(matches!(
            &first[0],
            TftpPacket::Data { block: 1, data } if data.len() == TFTP_BLOCK_SIZE
        ));
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

        let handler = TftpHandler::new().with_root_dir(&root);
        let packet = handler.handle_read_request_block("huge.bin", 1);

        assert!(matches!(packet, TftpPacket::Error { code: 2, .. }));

        std::fs::remove_dir_all(root).expect("cleanup temp root");
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

        let handler = TftpHandler::new().with_root_dir(&root);
        let packet = handler.handle_read_request_block("link.bin", 1);

        assert!(matches!(packet, TftpPacket::Error { code: 2, .. }));
        std::fs::remove_dir_all(root).expect("cleanup temp root");
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!("{}-{}", prefix, std::process::id()))
    }
}
