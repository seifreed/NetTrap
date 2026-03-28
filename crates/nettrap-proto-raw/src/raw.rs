use async_trait::async_trait;

use crate::prelude::*;

pub struct RawHandler {
    buffer_size: usize,
}

impl RawHandler {
    pub fn new() -> Self {
        Self {
            buffer_size: 65535,
        }
    }
    
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size;
        self
    }
}

impl Default for RawHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait RawHandlerTrait: Send + Sync {
    async fn handle(&self, data: &[u8], src: std::net::SocketAddr, dst: std::net::SocketAddr) -> Result<()>;
    fn name(&self) -> &'static str;
}

#[async_trait]
impl RawHandlerTrait for RawHandler {
    async fn handle(&self, data: &[u8], _src: std::net::SocketAddr, _dst: std::net::SocketAddr) -> Result<()> {
        tracing::debug!("Raw handler received {} bytes", data.len());
        
        let hex: String = data.iter()
            .take(64)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        
        tracing::debug!("Data: {}", hex);
        
        Ok(())
    }
    
    fn name(&self) -> &'static str {
        "raw"
    }
}