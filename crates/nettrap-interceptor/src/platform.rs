use crate::prelude::*;

#[cfg(not(target_os = "windows"))]
pub type DefaultInterceptor = crate::pcap::PcapInterceptor;

#[cfg(target_os = "windows")]
pub type DefaultInterceptor = WindowsInterceptor;

#[cfg(target_os = "windows")]
pub struct WindowsInterceptor {
    config: InterceptorConfig,
    running: parking_lot::RwLock<bool>,
    stats: crate::intercept::InterceptStats,
}

#[cfg(target_os = "windows")]
impl WindowsInterceptor {
    pub fn new(config: InterceptorConfig) -> Result<Self> {
        Ok(Self {
            config,
            running: parking_lot::RwLock::new(false),
            stats: crate::intercept::InterceptStats::default(),
        })
    }

    pub fn config(&self) -> &InterceptorConfig {
        &self.config
    }
}

#[cfg(target_os = "windows")]
#[async_trait]
impl Interceptor for WindowsInterceptor {
    async fn init(&mut self) -> Result<()> {
        tracing::info!("Initializing Windows WFP interceptor");
        *self.running.write() = true;
        
        Err(Error::NotSupported(
            "Windows WFP interception requires elevated privileges and a kernel driver. \
             Use pcap mode for userspace packet capture on Windows.".into()
        ))
    }

    async fn recv_packet(&self) -> Result<Packet> {
        Err(Error::NotSupported("Windows WFP not initialized".into()))
    }

    async fn send_packet(&self, _packet: Packet) -> Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        *self.running.write() = false;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "windows_wfp"
    }

    fn is_running(&self) -> bool {
        *self.running.read()
    }
}

pub struct InterceptorBuilder {
    config: InterceptorConfig,
}

impl InterceptorBuilder {
    pub fn new() -> Self {
        Self {
            config: InterceptorConfig::default(),
        }
    }

    pub fn mode(mut self, mode: nettrap_core::config::InterceptionMode) -> Self {
        self.config.mode = mode;
        self
    }

    pub fn interface(mut self, iface: impl Into<String>) -> Self {
        self.config.interface = Some(iface.into());
        self
    }

    pub fn buffer_size(mut self, size: usize) -> Self {
        self.config.buffer_size = size;
        self
    }

    pub fn promiscuous(mut self, promisc: bool) -> Self {
        self.config.promiscuous = promisc;
        self
    }

    pub fn build(self) -> Result<DefaultInterceptor> {
        DefaultInterceptor::new(self.config)
    }
}

impl Default for InterceptorBuilder {
    fn default() -> Self {
        Self::new()
    }
}