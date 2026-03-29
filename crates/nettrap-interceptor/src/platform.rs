use crate::prelude::*;

// Default interceptor selection based on platform and architecture:
// - Linux/macOS: PCAP
// - Windows x86_64/i686: WinDivert
// - Windows ARM64: PCAP/Npcap

#[cfg(not(target_os = "windows"))]
pub type DefaultInterceptor = crate::pcap::PcapInterceptor;

#[cfg(all(target_os = "windows", any(target_arch = "x86_64", target_arch = "x86")))]
pub type DefaultInterceptor = crate::windivert::WinDivertInterceptor;

#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
pub type DefaultInterceptor = crate::pcap::PcapInterceptor;

#[cfg(target_os = "windows")]
pub mod windivert {
    use crate::prelude::*;
    use nettrap_windivert::{
        WinDivert, HANDLE, WindivertAddress, WindivertIpHdr, WindivertIpv6Hdr, WindivertTcpHdr,
        WindivertUdpHdr, IPPROTO_TCP, IPPROTO_UDP, WINDIVERT_DIRECTION_IN,
        WINDIVERT_DIRECTION_OUT, WINDIVERT_LAYER_NETWORK,
    };
    use parking_lot::{Mutex, RwLock};
    use std::sync::Arc;

    pub struct WinDivertInterceptor {
        config: InterceptorConfig,
        running: Arc<RwLock<bool>>,
        stats: Arc<RwLock<InterceptStats>>,
        handle: Arc<RwLock<Option<usize>>>,
        windivert: Arc<Mutex<Option<WinDivert>>>,
        filter: String,
    }

    impl WinDivertInterceptor {
        pub fn new(config: InterceptorConfig) -> Result<Self> {
            Ok(Self {
                filter: build_filter(&config),
                config,
                running: Arc::new(RwLock::new(false)),
                stats: Arc::new(RwLock::new(InterceptStats::default())),
                handle: Arc::new(RwLock::new(None)),
                windivert: Arc::new(Mutex::new(None)),
            })
        }

        pub fn with_filter(mut self, filter: impl Into<String>) -> Self {
            self.filter = filter.into();
            self
        }

        pub fn filter(&self) -> &str {
            &self.filter
        }

        pub fn stats(&self) -> InterceptStats {
            self.stats.read().clone()
        }

        pub fn is_available() -> bool {
            cfg!(all(target_os = "windows", any(target_arch = "x86_64", target_arch = "x86")))
        }

        fn parse_ipv4_packet(
            data: &[u8],
            len: usize,
            direction: PacketDirection,
        ) -> Result<Option<Packet>> {
            if len < std::mem::size_of::<WindivertIpHdr>() {
                return Ok(None);
            }

            let ip_header = unsafe { &*(data.as_ptr() as *const WindivertIpHdr) };
            let ihl = (ip_header.ver_hdrlen & 0x0F) as usize * 4;
            if len < ihl {
                return Ok(None);
            }

            let src_ip =
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(ip_header.src_addr)));
            let dst_ip =
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(ip_header.dst_addr)));

            match ip_header.protocol {
                IPPROTO_TCP => {
                    if len < ihl + std::mem::size_of::<WindivertTcpHdr>() {
                        return Ok(None);
                    }

                    let tcp_header = unsafe { &*(data.as_ptr().add(ihl) as *const WindivertTcpHdr) };
                    let src_port = u16::from_be(tcp_header.src_port);
                    let dst_port = u16::from_be(tcp_header.dst_port);
                    let tcp_header_len = ((tcp_header.flags0 >> 4) as usize) * 4;
                    // Validate TCP header length (RFC 793: min 20, max 60 bytes)
                    if tcp_header_len < 20 || tcp_header_len > 60 {
                        return Ok(None);
                    }
                    let payload_start = ihl + tcp_header_len;
                    if len < payload_start {
                        return Ok(None);
                    }

                    let tcp_flags = TcpFlags::from_bits_truncate_value(tcp_header.flags1);

                    Ok(Some(
                        Packet::new(
                            FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Tcp),
                            direction,
                            bytes::Bytes::copy_from_slice(&data[payload_start..len]),
                        )
                        .with_tcp_flags(tcp_flags),
                    ))
                }
                IPPROTO_UDP => {
                    if len < ihl + std::mem::size_of::<WindivertUdpHdr>() {
                        return Ok(None);
                    }

                    let udp_header = unsafe { &*(data.as_ptr().add(ihl) as *const WindivertUdpHdr) };
                    let src_port = u16::from_be(udp_header.src_port);
                    let dst_port = u16::from_be(udp_header.dst_port);
                    let payload_start = ihl + std::mem::size_of::<WindivertUdpHdr>();
                    if len < payload_start {
                        return Ok(None);
                    }

                    Ok(Some(Packet::new(
                        FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Udp),
                        direction,
                        bytes::Bytes::copy_from_slice(&data[payload_start..len]),
                    )))
                }
                other => Ok(Some(Packet::new(
                    FiveTuple::new(src_ip, dst_ip, 0, 0, Protocol::Unknown(other)),
                    direction,
                    bytes::Bytes::copy_from_slice(&data[ihl..len]),
                ))),
            }
        }

        fn parse_ipv6_packet(
            data: &[u8],
            len: usize,
            direction: PacketDirection,
        ) -> Result<Option<Packet>> {
            const IPV6_HEADER_LEN: usize = 40;

            if len < std::mem::size_of::<WindivertIpv6Hdr>() {
                return Ok(None);
            }

            let ip_header = unsafe { &*(data.as_ptr() as *const WindivertIpv6Hdr) };
            let src_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_header.src_addr));
            let dst_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_header.dst_addr));

            match ip_header.nxt {
                IPPROTO_TCP => {
                    if len < IPV6_HEADER_LEN + std::mem::size_of::<WindivertTcpHdr>() {
                        return Ok(None);
                    }

                    let tcp_header =
                        unsafe { &*(data.as_ptr().add(IPV6_HEADER_LEN) as *const WindivertTcpHdr) };
                    let src_port = u16::from_be(tcp_header.src_port);
                    let dst_port = u16::from_be(tcp_header.dst_port);
                    let tcp_header_len = ((tcp_header.flags0 >> 4) as usize) * 4;
                    // Validate TCP header length (RFC 793: min 20, max 60 bytes)
                    if tcp_header_len < 20 || tcp_header_len > 60 {
                        return Ok(None);
                    }
                    let payload_start = IPV6_HEADER_LEN + tcp_header_len;
                    if len < payload_start {
                        return Ok(None);
                    }

                    let tcp_flags = TcpFlags::from_bits_truncate_value(tcp_header.flags1);

                    Ok(Some(
                        Packet::new(
                            FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Tcp),
                            direction,
                            bytes::Bytes::copy_from_slice(&data[payload_start..len]),
                        )
                        .with_tcp_flags(tcp_flags),
                    ))
                }
                IPPROTO_UDP => {
                    if len < IPV6_HEADER_LEN + std::mem::size_of::<WindivertUdpHdr>() {
                        return Ok(None);
                    }

                    let udp_header =
                        unsafe { &*(data.as_ptr().add(IPV6_HEADER_LEN) as *const WindivertUdpHdr) };
                    let src_port = u16::from_be(udp_header.src_port);
                    let dst_port = u16::from_be(udp_header.dst_port);
                    let payload_start = IPV6_HEADER_LEN + std::mem::size_of::<WindivertUdpHdr>();
                    if len < payload_start {
                        return Ok(None);
                    }

                    Ok(Some(Packet::new(
                        FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Udp),
                        direction,
                        bytes::Bytes::copy_from_slice(&data[payload_start..len]),
                    )))
                }
                other => Ok(Some(Packet::new(
                    FiveTuple::new(src_ip, dst_ip, 0, 0, Protocol::Unknown(other)),
                    direction,
                    bytes::Bytes::copy_from_slice(&data[IPV6_HEADER_LEN..len]),
                ))),
            }
        }

        fn parse_packet(data: &[u8], len: usize, addr: &WindivertAddress) -> Result<Option<Packet>> {
            if len < 1 {
                return Ok(None);
            }

            let direction = match addr.direction() {
                WINDIVERT_DIRECTION_OUT => PacketDirection::Outbound,
                WINDIVERT_DIRECTION_IN => PacketDirection::Inbound,
                _ => PacketDirection::Unknown,
            };

            match (data[0] & 0xF0) >> 4 {
                4 => Self::parse_ipv4_packet(data, len, direction),
                6 => Self::parse_ipv6_packet(data, len, direction),
                _ => Ok(None),
            }
        }
    }

    #[async_trait]
    impl Interceptor for WinDivertInterceptor {
        async fn init(&mut self) -> Result<()> {
            tracing::info!("Initializing WinDivert interceptor with filter: {}", self.filter);

            let mut windivert = WinDivert::new();
            let handle = windivert
                .open(&self.filter, 0, WINDIVERT_LAYER_NETWORK, 0)
                .map_err(|e| Error::Interception(format!("Failed to open WinDivert: {}", e)))?;

            *self.handle.write() = Some(handle as usize);
            *self.windivert.lock() = Some(windivert);
            *self.running.write() = true;

            tracing::info!("WinDivert interceptor initialized successfully");
            Ok(())
        }

        async fn recv_packet(&self) -> Result<Packet> {
            let handle = (*self.handle.read())
                .ok_or_else(|| Error::InvalidState("WinDivert not initialized".into()))?;
            let windivert = Arc::clone(&self.windivert);
            let stats = Arc::clone(&self.stats);

            tokio::task::spawn_blocking(move || {
                let handle = handle as HANDLE;
                let mut packet_buf = vec![0u8; 65535];
                let mut addr = WindivertAddress::default();

                let len = {
                    let guard = windivert.lock();
                    let api = guard
                        .as_ref()
                        .ok_or_else(|| Error::InvalidState("WinDivert not initialized".into()))?;
                    api.recv(handle, &mut packet_buf, &mut addr).map_err(|e| {
                        Error::Interception(format!("WinDivertRecv failed: {}", e))
                    })?
                };

                let packet = Self::parse_packet(&packet_buf, len as usize, &addr)?
                    .ok_or_else(|| Error::Packet("Failed to parse WinDivert packet".into()))?;

                {
                    let mut guard = stats.write();
                    guard.packets_received += 1;
                    guard.bytes_received += packet.length as u64;
                }

                Ok(packet)
            })
            .await
            .map_err(|e| Error::Interception(format!("Join error: {}", e)))?
        }

        async fn send_packet(&self, packet: Packet) -> Result<()> {
            let handle = (*self.handle.read())
                .ok_or_else(|| Error::InvalidState("WinDivert not initialized".into()))?;
            let windivert = Arc::clone(&self.windivert);
            let stats = Arc::clone(&self.stats);
            let payload = packet.payload.clone();
            let direction = match packet.direction {
                PacketDirection::Inbound => WINDIVERT_DIRECTION_IN,
                _ => WINDIVERT_DIRECTION_OUT,
            };

            tokio::task::spawn_blocking(move || {
                let handle = handle as HANDLE;
                let mut addr = WindivertAddress::default();
                addr.set_direction(direction);

                let guard = windivert.lock();
                let api = guard
                    .as_ref()
                    .ok_or_else(|| Error::InvalidState("WinDivert not initialized".into()))?;
                api.send(handle, payload.as_ref(), &addr)
                    .map_err(|e| Error::Interception(format!("WinDivertSend failed: {}", e)))?;

                let mut guard = stats.write();
                guard.packets_sent += 1;
                guard.bytes_sent += payload.len() as u64;
                Ok(())
            })
            .await
            .map_err(|e| Error::Interception(format!("Join error: {}", e)))?
        }

        async fn shutdown(&mut self) -> Result<()> {
            tracing::info!("Shutting down WinDivert interceptor");
            *self.running.write() = false;

            let handle = self.handle.write().take();
            if let Some(handle) = handle {
                if let Some(mut api) = self.windivert.lock().take() {
                    let _ = api.close(handle as HANDLE);
                }
            }

            Ok(())
        }

        fn name(&self) -> &'static str {
            "windivert"
        }

        fn is_running(&self) -> bool {
            *self.running.read()
        }
    }

    fn build_filter(config: &InterceptorConfig) -> String {
        let mut clauses = vec!["ip".to_string()];

        if let Some(iface) = &config.interface {
            let trimmed = iface.trim();
            if !trimmed.is_empty() {
                clauses.push(format!("ifIdx == {}", trimmed));
            }
        }

        match config.mode {
            nettrap_core::config::InterceptionMode::WinDivert => clauses.push("true".to_string()),
            _ => clauses.push("true".to_string()),
        }

        clauses.join(" and ")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_ipv4_tcp_packet() {
            let data: [u8; 40] = [
                0x45, 0x00, 0x00, 0x28, 0, 0, 0, 0, 64, 6, 0, 0, 192, 168, 1, 10, 93, 184, 216,
                34, 0x1f, 0x90, 0x00, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0x00, 0, 0,
                0, 0,
            ];
            let addr = WindivertAddress {
                direction: WINDIVERT_DIRECTION_OUT,
                ..Default::default()
            };

            let packet = WinDivertInterceptor::parse_packet(&data, data.len(), &addr)
                .unwrap()
                .unwrap();

            assert_eq!(packet.five_tuple.src_port, 8080);
            assert_eq!(packet.five_tuple.dst_port, 80);
            assert!(packet.is_tcp());
            assert!(packet.direction.is_outbound());
        }

        #[test]
        fn parses_ipv4_udp_packet() {
            let data: [u8; 32] = [
                0x45, 0x00, 0x00, 0x20, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 8, 8, 8, 8, 0x30,
                0x39, 0x00, 0x35, 0x00, 0x0c, 0, 0, b't', b'e', b's', b't',
            ];
            let addr = WindivertAddress {
                direction: WINDIVERT_DIRECTION_IN,
                ..Default::default()
            };

            let packet = WinDivertInterceptor::parse_packet(&data, data.len(), &addr)
                .unwrap()
                .unwrap();

            assert_eq!(packet.five_tuple.src_port, 12345);
            assert_eq!(packet.five_tuple.dst_port, 53);
            assert!(packet.is_udp());
            assert!(packet.direction.is_inbound());
            assert_eq!(packet.payload.as_ref(), b"test");
        }
    }
}

#[cfg(target_os = "windows")]
pub mod windows_pcap {
    pub use crate::pcap::PcapInterceptor as WindowsPcapInterceptor;

    pub fn is_npcap_available() -> bool {
        true
    }

    pub fn get_recommended_interceptor() -> &'static str {
        if cfg!(target_arch = "aarch64") {
            "pcap"
        } else {
            "windivert"
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

    pub fn build_pcap(self) -> Result<crate::pcap::PcapInterceptor> {
        crate::pcap::PcapInterceptor::new(self.config)
    }

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
