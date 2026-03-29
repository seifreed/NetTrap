use async_trait::async_trait;
use std::path::PathBuf;
use crate::prelude::*;

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

    /// Handle a RRQ - returns list of DATA packets (block-segmented)
    pub fn handle_read_request(&self, filename: &str) -> Vec<TftpPacket> {
        tracing::debug!("TFTP RRQ for file: {}", filename);

        let content = if let Some(ref root) = self.root_dir {
            let path = root.join(filename);
            // Prevent path traversal
            if path.starts_with(root) {
                std::fs::read(&path).unwrap_or_else(|_| self.default_content.clone())
            } else {
                tracing::warn!("TFTP path traversal attempt: {}", filename);
                return vec![TftpPacket::Error {
                    code: 2,
                    message: "Access violation".to_string(),
                }];
            }
        } else {
            self.default_content.clone()
        };

        let mut packets = Vec::new();
        let chunks = content.chunks(TFTP_BLOCK_SIZE);
        let mut block: u16 = 1;

        for chunk in chunks {
            packets.push(TftpPacket::Data {
                block,
                data: chunk.to_vec(),
            });
            block = block.wrapping_add(1);
        }

        // If content is exactly a multiple of block size, send empty final block
        if content.len() % TFTP_BLOCK_SIZE == 0 {
            packets.push(TftpPacket::Data {
                block,
                data: Vec::new(),
            });
        }

        // If no content at all, send single empty data block
        if packets.is_empty() {
            packets.push(TftpPacket::Data {
                block: 1,
                data: Vec::new(),
            });
        }

        packets
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
    fn default() -> Self { Self::new() }
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
            TftpPacket::ReadRequest { filename, .. } => {
                Ok(self.handle_read_request(filename))
            }
            TftpPacket::WriteRequest { filename, .. } => {
                Ok(vec![self.handle_write_request(filename)])
            }
            TftpPacket::Data { block, data } => {
                Ok(vec![self.handle_data_block(*block, data)])
            }
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
