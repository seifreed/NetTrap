use async_trait::async_trait;

use crate::prelude::*;

#[async_trait]
pub trait Interceptor: Send + Sync {
    async fn init(&mut self) -> Result<()>;
    async fn recv_packet(&self) -> Result<Packet>;
    async fn send_packet(&self, packet: Packet) -> Result<()>;
    async fn shutdown(&mut self) -> Result<()>;
    fn name(&self) -> &'static str;
    fn is_running(&self) -> bool;
}

#[async_trait]
pub trait PacketSource: Send + Sync {
    async fn next(&self) -> Result<Option<Packet>>;
    fn is_exhausted(&self) -> bool;
}

#[async_trait]
pub trait PacketSink: Send + Sync {
    async fn send(&self, packet: Packet) -> Result<()>;
    async fn flush(&self) -> Result<()>;
}

#[derive(Debug, Default, Clone)]
pub struct InterceptStats {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub packets_dropped: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
}

#[derive(Debug, Clone)]
pub struct InterceptorConfig {
    pub mode: nettrap_core::config::InterceptionMode,
    pub interface: Option<String>,
    pub buffer_size: usize,
    pub promiscuous: bool,
}

impl Default for InterceptorConfig {
    fn default() -> Self {
        Self {
            mode: nettrap_core::config::InterceptionMode::default(),
            interface: None,
            buffer_size: 65536,
            promiscuous: true,
        }
    }
}