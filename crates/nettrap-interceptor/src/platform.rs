use crate::prelude::*;

#[cfg(not(target_os = "windows"))]
pub type DefaultInterceptor = crate::pcap::PcapInterceptor;

#[cfg(target_os = "windows")]
pub type DefaultInterceptor = crate::windivert::WinDivertInterceptor;

#[cfg(target_os = "windows")]
pub mod windivert {
    use crate::prelude::*;
    use parking_lot::RwLock;
    use std::sync::Arc;
    
    pub struct WinDivertInterceptor {
        config: InterceptorConfig,
        running: RwLock<bool>,
        stats: crate::intercept::InterceptStats,
        handle: Arc<RwLock<Option<isize>>>,
        windivert: Arc<RwLock<Option<()>>>,
        filter: String,
    }
    
    impl WinDivertInterceptor {
        pub fn new(config: InterceptorConfig) -> Result<Self> {
            Ok(Self {
                config,
                running: RwLock::new(false),
                stats: crate::intercept::InterceptStats::default(),
                handle: Arc::new(RwLock::new(None)),
                windivert: Arc::new(RwLock::new(None)),
                filter: "outbound and ip".to_string(),
            })
        }
        
        pub fn with_filter(mut self, filter: impl Into<String>) -> Self {
            self.filter = filter.into();
            self
        }
    }
    
    #[async_trait]
    impl Interceptor for WinDivertInterceptor {
        async fn init(&mut self) -> Result<()> {
            tracing::info!("Initializing WinDivert interceptor with filter: {}", self.filter);
            
            #[cfg(windows)]
            {
                let windivert = nettrap_windivert::WinDivert::new();
                let handle = windivert.open(&self.filter, 0, 0, 0)
                    .map_err(|e| Error::Interception(format!("Failed to open WinDivert: {}", e)))?;
                
                *self.handle.write() = Some(handle as isize);
                *self.running.write() = true;
                
                tracing::info!("WinDivert interceptor initialized successfully");
                Ok(())
            }
            
            #[cfg(not(windows))]
            {
                Err(Error::NotSupported("WinDivert only available on Windows".into()))
            }
        }
        
        async fn recv_packet(&self) -> Result<Packet> {
            #[cfg(windows)]
            {
                use tokio::task::spawn_blocking;
                
                let handle = self.handle.read()
                    .ok_or_else(|| Error::InvalidState("WinDivert not initialized".into()))?;
                
                spawn_blocking(move || {
                    Err(Error::NotImplemented("Packet receiving not yet implemented".into()))
                }).await
                    .map_err(|e| Error::Interception(format!("Join error: {}", e)))?
            }
            
            #[cfg(not(windows))]
            {
                Err(Error::NotSupported("WinDivert only available on Windows".into()))
            }
        }
        
        async fn send_packet(&self, _packet: Packet) -> Result<()> {
            Ok(())
        }
        
        async fn shutdown(&mut self) -> Result<()> {
            tracing::info!("Shutting down WinDivert interceptor");
            *self.running.write() = false;
            *self.handle.write() = None;
            tracing::info!("WinDivert interceptor shut down");
            Ok(())
        }
        
        fn name(&self) -> &'static str {
            "windivert"
        }
        
        fn is_running(&self) -> bool {
            *self.running.read()
        }
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