use async_trait::async_trait;

use crate::intercept::{Interceptor, InterceptorConfig};
use crate::prelude::*;

/// Linux NFQUEUE-based interceptor using iptables NFQUEUE target.
///
/// Requires the `nfqueue` iptables target and appropriate privileges (CAP_NET_ADMIN).
/// Packets are diverted from the kernel networking stack via netfilter,
/// allowing inspection and verdict (accept/drop/modify) before forwarding.
pub struct NfqueueInterceptor {
    config: InterceptorConfig,
    queue_num: u16,
    running: bool,
}

impl NfqueueInterceptor {
    pub fn new(config: InterceptorConfig) -> Result<Self> {
        Ok(Self {
            config,
            queue_num: 0,
            running: false,
        })
    }

    pub fn with_queue_num(mut self, num: u16) -> Self {
        self.queue_num = num;
        self
    }

    pub fn queue_num(&self) -> u16 {
        self.queue_num
    }

    pub fn config(&self) -> &InterceptorConfig {
        &self.config
    }
}

#[async_trait]
impl Interceptor for NfqueueInterceptor {
    async fn init(&mut self) -> Result<()> {
        Err(Error::NotImplemented(
            "NFQUEUE interceptor not yet implemented — use pcap mode on Linux".into(),
        ))
    }

    async fn recv_packet(&self) -> Result<Packet> {
        Err(Error::NotImplemented("NFQUEUE recv not implemented".into()))
    }

    async fn send_packet(&self, _packet: Packet) -> Result<()> {
        Err(Error::NotImplemented("NFQUEUE send not implemented".into()))
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.running = false;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "nfqueue"
    }

    fn is_running(&self) -> bool {
        self.running
    }
}
