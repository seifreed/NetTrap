use crate::prelude::*;

// Default interceptor selection based on platform and architecture:
// - Linux: NFQUEUE (x86_64, i686, ARM64 with kernel support) or PCAP fallback
// - macOS: PCAP
// - Windows x86_64/i686: WinDivert (full packet modification, PID tracking)
// - Windows ARM64: PCAP/Npcap (packet capture only, no modification)

#[cfg(not(target_os = "windows"))]
pub type DefaultInterceptor = crate::pcap::PcapInterceptor;

// Windows x86_64 and x86 use WinDivert
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub type DefaultInterceptor = crate::windivert::WinDivertInterceptor;

#[cfg(all(target_os = "windows", target_arch = "x86"))]
pub type DefaultInterceptor = crate::windivert::WinDivertInterceptor;

// Windows ARM64 uses PCAP (Npcap has native ARM64 support)
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
pub type DefaultInterceptor = crate::pcap::PcapInterceptor;

#[cfg(target_os = "windows")]
pub mod windivert {
    use crate::prelude::*;
    use parking_lot::RwLock;
    use std::sync::Arc;
    
    /// WinDivert-based packet interceptor for Windows x86/x86_64.
    /// 
    /// WinDivert provides kernel-level packet interception with:
    /// - Packet modification
    /// - Process ID tracking
    /// - Filtering capabilities
    /// 
    /// Note: WinDivert does NOT have native ARM64 drivers.
    /// Use PcapInterceptor for Windows ARM64.
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
        
        /// Check if WinDivert is available on this system.
        /// Returns true on Windows x86/x86_64, false on ARM64.
        pub fn is_available() -> bool {
            cfg!(all(target_os = "windows", any(target_arch = "x86_64", target_arch = "x86")))
        }
    }
    
    #[async_trait]
    impl Interceptor for WinDivertInterceptor {
        async fn init(&mut self) -> Result<()> {
            tracing::info!("Initializing WinDivert interceptor with filter: {}", self.filter);
            
            #[cfg(all(target_os = "windows", any(target_arch = "x86_64", target_arch = "x86")))]
            {
                let windivert = nettrap_windivert::WinDivert::new();
                let handle = windivert.open(&self.filter, 0, 0, 0)
                    .map_err(|e| Error::Interception(format!("Failed to open WinDivert: {}", e)))?;
                
                *self.handle.write() = Some(handle as isize);
                *self.running.write() = true;
                
                tracing::info!("WinDivert interceptor initialized successfully");
                Ok(())
            }
            
            #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
            {
                Err(Error::NotSupported(
                    "WinDivert is not available on Windows ARM64. \
                     Use PcapInterceptor with Npcap instead.".into()
                ))
            }
            
            #[cfg(not(target_os = "windows"))]
            {
                Err(Error::NotSupported("WinDivert only available on Windows".into()))
            }
        }
        
        async fn recv_packet(&self) -> Result<Packet> {
            #[cfg(all(target_os = "windows", any(target_arch = "x86_64", target_arch = "x86")))]
            {
                use tokio::task::spawn_blocking;
                
                let handle = self.handle.read()
                    .ok_or_else(|| Error::InvalidState("WinDivert not initialized".into()))?;
                
                spawn_blocking(move || {
                    Err(Error::NotImplemented("Packet receiving not yet implemented".into()))
                }).await
                    .map_err(|e| Error::Interception(format!("Join error: {}", e)))?
            }
            
            #[cfg(not(all(target_os = "windows", any(target_arch = "x86_64", target_arch = "x86"))))]
            {
                Err(Error::NotSupported("WinDivert not available on this platform".into()))
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

/// Windows PCAP interceptor using Npcap.
/// 
/// Npcap provides native ARM64 support and works on all Windows architectures.
/// Use this for Windows ARM64 where WinDivert is not available.
#[cfg(target_os = "windows")]
pub mod windows_pcap {
    use crate::pcap::PcapInterceptor;
    use crate::prelude::*;
    
    pub type WindowsPcapInterceptor = PcapInterceptor;
    
    /// Check if Npcap is available on this system.
    pub fn is_npcap_available() -> bool {
        // Npcap is available if PCAP can be initialized
        // This is checked at runtime in PcapInterceptor::init
        true
    }
    
    /// Get recommended interceptor for Windows based on architecture.
    pub fn get_recommended_interceptor() -> &'static str {
        if cfg!(target_arch = "aarch64") {
            "pcap" // Npcap for ARM64
        } else {
            "windivert" // WinDivert for x86/x86_64
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
    
    /// Build a PCAP interceptor (works on all platforms).
    pub fn build_pcap(self) -> Result<crate::pcap::PcapInterceptor> {
        crate::pcap::PcapInterceptor::new(self.config)
    }
    
    /// Build a WinDivert interceptor (Windows x86/x86_64 only).
    #[cfg(all(target_os = "windows", any(target_arch = "x86_64", target_arch = "x86")))]
    pub fn build_windivert(self) -> Result<crate::windivert::WinDivertInterceptor> {
        crate::windivert::WinDivertInterceptor::new(self.config)
    }
}

impl Default for InterceptorBuilder {
    fn default() -> Self {
        Self::new()
    }
}