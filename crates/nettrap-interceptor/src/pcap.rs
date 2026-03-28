use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::prelude::*;

pub struct PcapInterceptor {
    config: crate::intercept::InterceptorConfig,
    capture: Arc<Mutex<Option<pcap::Capture<pcap::Active>>>>,
    running: parking_lot::RwLock<bool>,
    interface: String,
}

impl PcapInterceptor {
    pub fn new(config: crate::intercept::InterceptorConfig) -> Result<Self> {
        let interface = config.interface.clone().unwrap_or_else(|| {
            pcap::Device::list()
                .ok()
                .and_then(|devices| devices.into_iter().next())
                .map(|d| d.name)
                .unwrap_or_else(|| "any".to_string())
        });
        
        Ok(Self {
            config,
            capture: Arc::new(Mutex::new(None)),
            running: parking_lot::RwLock::new(false),
            interface,
        })
    }
    
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = interface.into();
        self
    }
    
    fn parse_packet(data: &[u8], len: usize) -> Result<Option<Packet>> {
        if len < 14 {
            return Ok(None);
        }
        
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        
        match ethertype {
            0x0800 => Self::parse_ipv4(data, len),
            0x86DD => Self::parse_ipv6(data, len),
            _ => Ok(None),
        }
    }
    
    fn parse_ipv4(data: &[u8], len: usize) -> Result<Option<Packet>> {
        if len < 34 {
            return Ok(None);
        }
        
        let ihl = (data[14] & 0x0F) as usize * 4;
        if len < 14 + ihl + 20 {
            return Ok(None);
        }
        
        let src_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            data[14 + 12],
            data[14 + 13],
            data[14 + 14],
            data[14 + 15],
        ));
        let dst_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            data[14 + 16],
            data[14 + 17],
            data[14 + 18],
            data[14 + 19],
        ));
        let protocol_num = data[14 + 9];
        
        Self::parse_transport(data, len, ihl, protocol_num, src_ip, dst_ip, 14)
    }
    
    #[allow(clippy::too_many_arguments)]
    fn parse_transport(
        data: &[u8],
        len: usize,
        ip_header_len: usize,
        protocol: u8,
        src_ip: std::net::IpAddr,
        dst_ip: std::net::IpAddr,
        eth_offset: usize,
    ) -> Result<Option<Packet>> {
        let (proto, payload_start) = match protocol {
            6 => {
                if len < eth_offset + ip_header_len + 20 {
                    return Ok(None);
                }
                let tcp_offset = eth_offset + ip_header_len;
                let tcp_header_len = ((data[tcp_offset + 12] >> 4) as usize) * 4;
                (Protocol::Tcp, tcp_offset + tcp_header_len)
            }
            17 => {
                if len < eth_offset + ip_header_len + 8 {
                    return Ok(None);
                }
                (Protocol::Udp, eth_offset + ip_header_len + 8)
            }
            _ => return Ok(None),
        };
        
        let transport_offset = eth_offset + ip_header_len;
        let src_port = u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
        let dst_port = u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);
        
        if len < payload_start {
            return Ok(None);
        }
        
        Ok(Some(Packet::new(
            FiveTuple::new(src_ip, dst_ip, src_port, dst_port, proto),
            PacketDirection::Outbound,
            bytes::Bytes::copy_from_slice(&data[payload_start..len]),
        )))
    }
    
    fn parse_ipv6(data: &[u8], len: usize) -> Result<Option<Packet>> {
        if len < 54 {
            return Ok(None);
        }
        
        let src_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from([
            data[14 + 8], data[14 + 9], data[14 + 10], data[14 + 11],
            data[14 + 12], data[14 + 13], data[14 + 14], data[14 + 15],
            data[14 + 16], data[14 + 17], data[14 + 18], data[14 + 19],
            data[14 + 20], data[14 + 21], data[14 + 22], data[14 + 23],
        ]));
        let dst_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from([
            data[14 + 24], data[14 + 25], data[14 + 26], data[14 + 27],
            data[14 + 28], data[14 + 29], data[14 + 30], data[14 + 31],
            data[14 + 32], data[14 + 33], data[14 + 34], data[14 + 35],
            data[14 + 36], data[14 + 37], data[14 + 38], data[14 + 39],
        ]));
        let protocol_num = data[14 + 6];
        
        Self::parse_transport(data, len, 40, protocol_num, src_ip, dst_ip, 14)
    }
}

#[async_trait]
impl Interceptor for PcapInterceptor {
    async fn init(&mut self) -> Result<()> {
        tracing::info!("Initializing pcap interceptor on interface {}", self.interface);
        
        let device = pcap::Device::list()
            .map_err(|e| Error::Interception(format!("Failed to list devices: {}", e)))?
            .into_iter()
            .find(|d| d.name == self.interface)
            .ok_or_else(|| Error::Interception(format!("Interface {} not found", self.interface)))?;
        
        let mut cap = pcap::Capture::from_device(device)
            .map_err(|e| Error::Interception(format!("Failed to open device: {}", e)))?
            .promisc(self.config.promiscuous)
            .snaplen(self.config.buffer_size as i32)
            .open()
            .map_err(|e| Error::Interception(format!("Failed to activate capture: {}", e)))?;
        
        cap.filter("tcp or udp", true)
            .map_err(|e| Error::Interception(format!("Failed to set filter: {}", e)))?;
        
        *self.capture.lock() = Some(cap);
        *self.running.write() = true;
        
        tracing::info!("Pcap interceptor initialized successfully");
        Ok(())
    }
    
    async fn recv_packet(&self) -> Result<Packet> {
        let capture = self.capture.clone();
        
        tokio::task::spawn_blocking(move || {
            let mut cap_guard = capture.lock();
            let cap = cap_guard.as_mut()
                .ok_or_else(|| Error::InvalidState("Capture not initialized".into()))?;
            
            loop {
                let packet = cap.next_packet()
                    .map_err(|e| Error::Interception(format!("Failed to receive packet: {}", e)))?;
                
                if let Some(pkt) = Self::parse_packet(packet.data, packet.header.len as usize)? {
                    return Ok(pkt);
                }
            }
        }).await
            .map_err(|e| Error::Interception(format!("Join error: {}", e)))?
    }
    
    async fn send_packet(&self, _packet: Packet) -> Result<()> {
        Err(Error::NotSupported("Pcap capture cannot send packets".into()))
    }
    
    async fn shutdown(&mut self) -> Result<()> {
        tracing::info!("Shutting down pcap interceptor");
        *self.running.write() = false;
        *self.capture.lock() = None;
        Ok(())
    }
    
    fn name(&self) -> &'static str {
        "pcap"
    }
    
    fn is_running(&self) -> bool {
        *self.running.read()
    }
}