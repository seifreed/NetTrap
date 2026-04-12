//! WinDivert Interceptor implementation.
//!
//! Implements the Interceptor trait using WinDivert for Windows packet capture.

use crate::prelude::*;
use crate::bindings::{WinDivert, WindivertAddress, WINDIVERT_LAYER_NETWORK, WINDIVERT_DIRECTION_OUT};
use parking_lot::RwLock;
use std::sync::Arc;

#[cfg(windows)]
pub struct WinDivertInterceptor {
    config: crate::intercept::InterceptorConfig,
    windivert: Arc<RwLock<Option<WinDivert>>>,
    handle: Arc<RwLock<Option<crate::bindings::HANDLE>>>,
    running: RwLock<bool>,
    filter: String,
    stats: crate::intercept::InterceptStats,
}

#[cfg(windows)]
impl WinDivertInterceptor {
    pub fn new(config: crate::intercept::InterceptorConfig) -> Result<Self> {
        Ok(Self {
            config,
            windivert: Arc::new(RwLock::new(None)),
            handle: Arc::new(RwLock::new(None)),
            running: RwLock::new(false),
            filter: "outbound and ip".to_string(),
            stats: crate::intercept::InterceptStats::default(),
        })
    }
    
    pub fn with_filter(mut self, filter: impl Into<String>) -> Self {
        self.filter = filter.into();
        self
    }
    
    fn parse_ipv4_packet(data: &[u8], len: usize) -> Result<Option<Packet>> {
        use crate::bindings::{WindivertIpHdr, WindivertTcpHdr, WindivertUdpHdr};
        
        if len < std::mem::size_of::<WindivertIpHdr>() {
            return Ok(None);
        }
        
        let ip_header = unsafe { &*(data.as_ptr() as *const WindivertIpHdr) };
        let ihl = (ip_header.ver_hdrlen & 0x0F) as usize * 4;
        
        let src_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(ip_header.src_addr)));
        let dst_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(ip_header.dst_addr)));
        
        match ip_header.protocol {
            crate::bindings::IPPROTO_TCP => {
                if len < ihl + std::mem::size_of::<WindivertTcpHdr>() {
                    return Ok(None);
                }
                
                let tcp_header = unsafe {
                    &*(data.as_ptr().add(ihl) as *const WindivertTcpHdr)
                };
                
                let src_port = u16::from_be(tcp_header.src_port);
                let dst_port = u16::from_be(tcp_header.dst_port);
                let tcp_header_len = ((tcp_header.flags0 >> 4) as usize) * 4;
                let payload_start = ihl + tcp_header_len;
                
                if len < payload_start {
                    return Ok(None);
                }
                
                Ok(Some(Packet::new(
                    FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Tcp),
                    PacketDirection::Outbound,
                    bytes::Bytes::copy_from_slice(&data[payload_start..len]),
                )))
            }
            crate::bindings::IPPROTO_UDP => {
                if len < ihl + std::mem::size_of::<WindivertUdpHdr>() {
                    return Ok(None);
                }
                
                let udp_header = unsafe {
                    &*(data.as_ptr().add(ihl) as *const WindivertUdpHdr)
                };
                
                let src_port = u16::from_be(udp_header.src_port);
                let dst_port = u16::from_be(udp_header.dst_port);
                let payload_start = ihl + std::mem::size_of::<WindivertUdpHdr>();
                
                if len < payload_start {
                    return Ok(None);
                }
                
                Ok(Some(Packet::new(
                    FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Udp),
                    PacketDirection::Outbound,
                    bytes::Bytes::copy_from_slice(&data[payload_start..len]),
                )))
            }
            _ => Ok(None),
        }
    }
    
    fn parse_ipv6_packet(data: &[u8], len: usize) -> Result<Option<Packet>> {
        use crate::bindings::{WindivertIpv6Hdr, WindivertTcpHdr, WindivertUdpHdr};
        
        if len < std::mem::size_of::<WindivertIpv6Hdr>() {
            return Ok(None);
        }
        
        let ip_header = unsafe { &*(data.as_ptr() as *const WindivertIpv6Hdr) };
        
        let src_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_header.src_addr));
        let dst_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_header.dst_addr));
        
        match ip_header.nxt {
            crate::bindings::IPPROTO_TCP => {
                if len < 40 + std::mem::size_of::<WindivertTcpHdr>() {
                    return Ok(None);
                }
                
                let tcp_header = unsafe {
                    &*(data.as_ptr().add(40) as *const WindivertTcpHdr)
                };
                
                let src_port = u16::from_be(tcp_header.src_port);
                let dst_port = u16::from_be(tcp_header.dst_port);
                let tcp_header_len = ((tcp_header.flags0 >> 4) as usize) * 4;
                let payload_start = 40 + tcp_header_len;
                
                if len < payload_start {
                    return Ok(None);
                }
                
                Ok(Some(Packet::new(
                    FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Tcp),
                    PacketDirection::Outbound,
                    bytes::Bytes::copy_from_slice(&data[payload_start..len]),
                )))
            }
            crate::bindings::IPPROTO_UDP => {
                if len < 40 + std::mem::size_of::<WindivertUdpHdr>() {
                    return Ok(None);
                }
                
                let udp_header = unsafe {
                    &*(data.as_ptr().add(40) as *const WindivertUdpHdr)
                };
                
                let src_port = u16::from_be(udp_header.src_port);
                let dst_port = u16::from_be(udp_header.dst_port);
                let payload_start = 40 + std::mem::size_of::<WindivertUdpHdr>();
                
                if len < payload_start {
                    return Ok(None);
                }
                
                Ok(Some(Packet::new(
                    FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Udp),
                    PacketDirection::Outbound,
                    bytes::Bytes::copy_from_slice(&data[payload_start..len]),
                )))
            }
            _ => Ok(None),
        }
    }
    
    fn parse_packet(data: &[u8], len: usize) -> Result<Option<Packet>> {
        if len < 1 {
            return Ok(None);
        }
        
        let version = (data[0] & 0xF0) >> 4;
        
        match version {
            4 => Self::parse_ipv4_packet(data, len),
            6 => Self::parse_ipv6_packet(data, len),
            _ => Ok(None),
        }
    }
}

#[cfg(windows)]
#[async_trait]
impl Interceptor for WinDivertInterceptor {
    async fn init(&mut self) -> Result<()> {
        tracing::info!("Initializing WinDivert interceptor with filter: {}", self.filter);
        
        let mut windivert = WinDivert::new();
        let handle = windivert.open(
            &self.filter,
            0,
            WINDIVERT_LAYER_NETWORK,
            0
        ).map_err(|e| Error::Interception(format!("Failed to open WinDivert: {}", e)))?;
        
        *self.windivert.write() = Some(windivert);
        *self.handle.write() = Some(handle);
        *self.running.write() = true;
        
        tracing::info!("WinDivert interceptor initialized successfully");
        Ok(())
    }
    
    async fn recv_packet(&self) -> Result<Packet> {
        let handle = self.handle.read();
        let handle = handle.ok_or_else(|| Error::InvalidState("WinDivert not initialized".into()))?;
        
        let windivert = self.windivert.read();
        let windivert = windivert.as_ref()
            .ok_or_else(|| Error::InvalidState("WinDivert not initialized".into()))?;
        
        let mut packet_buf = vec![0u8; 65535];
        let mut addr = WindivertAddress::default();
        
        tokio::task::spawn_blocking(move || {
            let len = windivert.recv(handle, &mut packet_buf, &mut addr)
                .map_err(|e| Error::Interception(format!("WinDivertRecv failed: {}", e)))?;
            
            Self::parse_packet(&packet_buf, len as usize)
                .and_then(|opt| opt.ok_or_else(|| Error::Interception("Failed to parse packet".into())))
        }).await
            .map_err(|e| Error::Interception(format!("Join error: {}", e)))?
    }
    
    async fn send_packet(&self, _packet: Packet) -> Result<()> {
        // WinDivert requires a complete IP packet (headers + payload) but the Packet
        // struct only contains the application-layer payload after header stripping.
        // Sending raw payload would inject malformed packets into the network stack.
        Err(Error::NotSupported(
            "WinDivert packet re-injection requires full IP packet reconstruction (not implemented)".into(),
        ))
    }
    
    async fn shutdown(&mut self) -> Result<()> {
        tracing::info!("Shutting down WinDivert interceptor");
        *self.running.write() = false;
        
        if let Some(handle) = self.handle.write().take() {
            if let Some(windivert) = self.windivert.write().take() {
                let _ = windivert.close(handle);
            }
        }
        
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

#[cfg(not(windows))]
pub struct WinDivertInterceptor;

#[cfg(not(windows))]
impl WinDivertInterceptor {
    pub fn new(_config: crate::intercept::InterceptorConfig) -> Result<Self> {
        Err(Error::NotSupported("WinDivert only available on Windows".into()))
    }
}

#[cfg(not(windows))]
#[async_trait]
impl Interceptor for WinDivertInterceptor {
    async fn init(&mut self) -> Result<()> {
        Err(Error::NotSupported("WinDivert only available on Windows".into()))
    }
    
    async fn recv_packet(&self) -> Result<Packet> {
        Err(Error::NotSupported("WinDivert only available on Windows".into()))
    }
    
    async fn send_packet(&self, _packet: Packet) -> Result<()> {
        Err(Error::NotSupported("WinDivert only available on Windows".into()))
    }
    
    async fn shutdown(&mut self) -> Result<()> {
        Err(Error::NotSupported("WinDivert only available on Windows".into()))
    }
    
    fn name(&self) -> &'static str {
        "windivert"
    }
    
    fn is_running(&self) -> bool {
        false
    }
}
