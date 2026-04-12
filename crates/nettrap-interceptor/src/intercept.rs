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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intercept_stats_default() {
        let stats = InterceptStats::default();
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.bytes_received, 0);
    }

    #[test]
    fn test_interceptor_config_default() {
        let config = InterceptorConfig::default();
        assert!(config.interface.is_none());
        assert_eq!(config.buffer_size, 65536);
        assert!(config.promiscuous);
    }

    #[test]
    fn test_intercept_stats_clone() {
        let stats = InterceptStats {
            packets_received: 100,
            packets_sent: 50,
            packets_dropped: 5,
            bytes_received: 1024,
            bytes_sent: 512,
        };
        let cloned = stats.clone();
        assert_eq!(cloned.packets_received, 100);
        assert_eq!(cloned.bytes_received, 1024);
    }
}
