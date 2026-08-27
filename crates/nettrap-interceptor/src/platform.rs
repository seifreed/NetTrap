use crate::prelude::*;

// Default interceptor selection based on platform and architecture:
// - Linux/macOS: PCAP
// - Windows x86_64/i686: WinDivert
// - Windows ARM64: PCAP/Npcap

#[cfg(not(target_os = "windows"))]
pub type DefaultInterceptor = crate::pcap::PcapInterceptor;

#[cfg(all(
    target_os = "windows",
    any(target_arch = "x86_64", target_arch = "x86")
))]
pub type DefaultInterceptor = crate::windivert::WinDivertInterceptor;

#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
pub type DefaultInterceptor = crate::pcap::PcapInterceptor;

#[cfg(target_os = "windows")]
pub mod windivert {
    use super::parse_windivert_interface_index;
    use crate::prelude::*;
    use nettrap_windivert::{
        HANDLE, IPPROTO_TCP, IPPROTO_UDP, WINDIVERT_DIRECTION_IN, WINDIVERT_DIRECTION_OUT,
        WINDIVERT_LAYER_NETWORK, WinDivert, WindivertAddress, WindivertFlags, WindivertIpHdr,
        WindivertIpv6Hdr, WindivertTcpHdr, WindivertUdpHdr, close_handle,
    };
    use parking_lot::{Mutex, RwLock};
    use std::collections::{HashMap, VecDeque};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const MAX_REDIRECT_FLOWS: usize = 8192;
    const MAX_REDIRECT_EXPIRY_ENTRIES: usize = MAX_REDIRECT_FLOWS * 2;
    const REDIRECT_FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

    /// TCP or UDP destination-port mapping applied by the WinDivert NAT path.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PortRedirect {
        pub source_port: Option<u16>,
        pub target_port: u16,
        pub is_tcp: bool,
    }

    impl PortRedirect {
        /// Redirect one destination port to a local listener port.
        pub fn new(source_port: u16, is_tcp: bool, target_port: u16) -> Self {
            Self {
                source_port: Some(source_port),
                target_port,
                is_tcp,
            }
        }

        /// Redirect all destinations for one transport protocol to a listener.
        pub fn catch_all(is_tcp: bool, target_port: u16) -> Self {
            Self {
                source_port: None,
                target_port,
                is_tcp,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct FlowKey {
        protocol: u8,
        client: SocketAddr,
        original_destination: SocketAddr,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct ReverseFlowKey {
        protocol: u8,
        client: SocketAddr,
        listener_port: u16,
    }

    #[derive(Debug, Clone)]
    struct RedirectFlow {
        original_destination: SocketAddr,
        listener_port: u16,
        last_seen: Instant,
    }

    #[derive(Debug, Default)]
    struct RedirectFlowTable {
        entries: HashMap<FlowKey, RedirectFlow>,
        reverse: HashMap<ReverseFlowKey, FlowKey>,
        expiry: VecDeque<(Instant, FlowKey)>,
    }

    impl RedirectFlowTable {
        fn compact_expiry(&mut self) {
            self.expiry.clear();
            let mut entries: Vec<_> = self
                .entries
                .iter()
                .map(|(key, flow)| (flow.last_seen, key.clone()))
                .collect();
            entries.sort_by_key(|(seen, _)| *seen);
            self.expiry.extend(entries);
        }

        fn prune(&mut self, now: Instant) {
            while let Some((seen, key)) = self.expiry.front().cloned() {
                if now.duration_since(seen) < REDIRECT_FLOW_IDLE_TIMEOUT {
                    break;
                }
                self.expiry.pop_front();
                let should_remove = self
                    .entries
                    .get(&key)
                    .is_some_and(|flow| flow.last_seen <= seen);
                if should_remove {
                    self.remove(&key);
                }
            }
        }

        fn remove(&mut self, key: &FlowKey) {
            if let Some(flow) = self.entries.remove(key) {
                let reverse = ReverseFlowKey {
                    protocol: key.protocol,
                    client: key.client,
                    listener_port: flow.listener_port,
                };
                if self.reverse.get(&reverse) == Some(key) {
                    self.reverse.remove(&reverse);
                }
            }
        }

        fn insert(&mut self, key: FlowKey, listener_port: u16, now: Instant) {
            self.prune(now);
            self.remove(&key);
            while self.entries.len() >= MAX_REDIRECT_FLOWS {
                let Some((_, oldest)) = self.expiry.pop_front() else {
                    break;
                };
                self.remove(&oldest);
            }

            let reverse = ReverseFlowKey {
                protocol: key.protocol,
                client: key.original_destination,
                listener_port,
            };
            if let Some(previous) = self.reverse.insert(reverse, key.clone()) {
                self.remove(&previous);
            }
            self.entries.insert(
                key.clone(),
                RedirectFlow {
                    original_destination: key.original_destination,
                    listener_port,
                    last_seen: now,
                },
            );
            self.expiry.push_back((now, key));
        }

        fn touch(&mut self, key: &FlowKey, now: Instant) {
            if !self.entries.contains_key(key) {
                return;
            }
            if let Some(flow) = self.entries.get_mut(key) {
                flow.last_seen = now;
            }
            if self.expiry.len() >= MAX_REDIRECT_EXPIRY_ENTRIES {
                self.compact_expiry();
            }
            self.expiry.push_back((now, key.clone()));
        }

        fn outbound_listener(&mut self, key: &FlowKey, now: Instant) -> Option<u16> {
            self.prune(now);
            let listener = self.entries.get(key).map(|flow| flow.listener_port);
            if listener.is_some() {
                self.touch(key, now);
            }
            listener
        }

        fn inbound_endpoints(
            &mut self,
            key: &ReverseFlowKey,
            now: Instant,
        ) -> Option<(SocketAddr, SocketAddr)> {
            self.prune(now);
            let flow_key = if let Some(flow_key) = self.reverse.get(key).cloned() {
                flow_key
            } else {
                let flow_key = self.entries.iter().find_map(|(flow_key, flow)| {
                    (flow_key.protocol == key.protocol
                        && flow_key.client == key.client
                        && flow.listener_port == key.listener_port)
                        .then(|| flow_key.clone())
                })?;
                self.reverse.insert(key.clone(), flow_key.clone());
                flow_key
            };
            let endpoints = self
                .entries
                .get(&flow_key)
                .map(|flow| (flow.original_destination, flow_key.client));
            if endpoints.is_some() {
                self.touch(&flow_key, now);
            }
            endpoints
        }
    }

    pub struct WinDivertInterceptor {
        running: Arc<RwLock<bool>>,
        stats: Arc<RwLock<InterceptStats>>,
        handle: Arc<RwLock<Option<usize>>>,
        windivert: Arc<Mutex<Option<WinDivert>>>,
        filter: String,
        redirects: Vec<PortRedirect>,
        flows: Arc<Mutex<RedirectFlowTable>>,
    }

    impl WinDivertInterceptor {
        pub fn new(config: InterceptorConfig) -> Result<Self> {
            validate_mode(&config)?;
            let filter = build_filter(&config)?;
            Ok(Self {
                filter,
                running: Arc::new(RwLock::new(false)),
                stats: Arc::new(RwLock::new(InterceptStats::default())),
                handle: Arc::new(RwLock::new(None)),
                windivert: Arc::new(Mutex::new(None)),
                redirects: Vec::new(),
                flows: Arc::new(Mutex::new(RedirectFlowTable::default())),
            })
        }

        /// Configure bounded TCP/UDP NAT mappings before startup.
        pub fn with_port_redirects(mut self, redirects: Vec<PortRedirect>) -> Self {
            self.redirects = redirects;
            self
        }

        pub fn filter(&self) -> &str {
            &self.filter
        }

        pub fn stats(&self) -> InterceptStats {
            self.stats.read().clone()
        }

        pub fn is_available() -> bool {
            cfg!(all(
                target_os = "windows",
                any(target_arch = "x86_64", target_arch = "x86")
            ))
        }

        fn parse_ipv4_packet(
            data: &[u8],
            len: usize,
            direction: PacketDirection,
        ) -> Result<Option<Packet>> {
            const IP_MIN_HEADER: usize = std::mem::size_of::<WindivertIpHdr>();
            let captured_len = len.min(data.len());

            if captured_len < IP_MIN_HEADER {
                return Ok(None);
            }

            let ip_header =
                unsafe { std::ptr::read_unaligned(data.as_ptr() as *const WindivertIpHdr) };
            let ihl = ((ip_header.ver_hdrlen & 0x0F) as usize) * 4;
            // Validate IHL: RFC 791 specifies minimum 5 (20 bytes), maximum 15 (60 bytes)
            if !(20..=60).contains(&ihl) {
                return Ok(None);
            }
            if captured_len < ihl {
                return Ok(None);
            }
            let total_len = u16::from_be(ip_header.len) as usize;
            if total_len < ihl || total_len > captured_len {
                return Ok(None);
            }
            let fragment = u16::from_be(ip_header.frag_off);
            if fragment & 0x3fff != 0 {
                return Ok(None);
            }
            let packet_data = &data[..total_len];

            let src_ip =
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(ip_header.src_addr)));
            let dst_ip =
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(ip_header.dst_addr)));

            match ip_header.protocol {
                IPPROTO_TCP => {
                    if total_len < ihl + std::mem::size_of::<WindivertTcpHdr>() {
                        return Ok(None);
                    }

                    let tcp_header = unsafe {
                        std::ptr::read_unaligned(
                            packet_data.as_ptr().add(ihl) as *const WindivertTcpHdr
                        )
                    };
                    let src_port = u16::from_be(tcp_header.src_port);
                    let dst_port = u16::from_be(tcp_header.dst_port);
                    let tcp_header_len = ((tcp_header.flags0 >> 4) as usize) * 4;
                    // Validate TCP header length (RFC 793: min 20, max 60 bytes)
                    if !(20..=60).contains(&tcp_header_len) {
                        return Ok(None);
                    }
                    let payload_start = ihl + tcp_header_len;
                    if total_len < payload_start {
                        return Ok(None);
                    }

                    let tcp_flags = TcpFlags::from_bits_truncate_value(tcp_header.flags1);

                    Ok(Some(
                        Packet::new(
                            FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Tcp),
                            direction,
                            bytes::Bytes::copy_from_slice(&packet_data[payload_start..total_len]),
                        )
                        .with_tcp_flags(tcp_flags),
                    ))
                }
                IPPROTO_UDP => {
                    if total_len < ihl + std::mem::size_of::<WindivertUdpHdr>() {
                        return Ok(None);
                    }

                    let udp_header = unsafe {
                        std::ptr::read_unaligned(
                            packet_data.as_ptr().add(ihl) as *const WindivertUdpHdr
                        )
                    };
                    let src_port = u16::from_be(udp_header.src_port);
                    let dst_port = u16::from_be(udp_header.dst_port);
                    let udp_len = u16::from_be(udp_header.len) as usize;
                    if udp_len < std::mem::size_of::<WindivertUdpHdr>() {
                        return Ok(None);
                    }
                    let payload_start = ihl + std::mem::size_of::<WindivertUdpHdr>();
                    let payload_end = ihl + udp_len;
                    if payload_end > total_len || payload_start > payload_end {
                        return Ok(None);
                    }

                    Ok(Some(Packet::new(
                        FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Udp),
                        direction,
                        bytes::Bytes::copy_from_slice(&packet_data[payload_start..payload_end]),
                    )))
                }
                other => Ok(Some(Packet::new(
                    FiveTuple::new(src_ip, dst_ip, 0, 0, Protocol::Unknown(other)),
                    direction,
                    bytes::Bytes::copy_from_slice(&packet_data[ihl..total_len]),
                ))),
            }
        }

        fn parse_ipv6_packet(
            data: &[u8],
            len: usize,
            direction: PacketDirection,
        ) -> Result<Option<Packet>> {
            const IPV6_HEADER_LEN: usize = 40;
            let captured_len = len.min(data.len());

            if captured_len < IPV6_HEADER_LEN {
                return Ok(None);
            }

            let ip_header =
                unsafe { std::ptr::read_unaligned(data.as_ptr() as *const WindivertIpv6Hdr) };
            let payload_len = u16::from_be(ip_header.plen) as usize;
            let total_len = IPV6_HEADER_LEN + payload_len;
            if total_len > captured_len {
                return Ok(None);
            }
            let packet_data = &data[..total_len];
            let src_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_header.src_addr));
            let dst_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_header.dst_addr));
            let Some((protocol, transport_offset)) =
                Self::ipv6_transport_start(packet_data, IPV6_HEADER_LEN)
            else {
                return Ok(None);
            };

            match protocol {
                IPPROTO_TCP => {
                    if total_len < transport_offset + std::mem::size_of::<WindivertTcpHdr>() {
                        return Ok(None);
                    }

                    let tcp_header = unsafe {
                        std::ptr::read_unaligned(
                            packet_data.as_ptr().add(transport_offset) as *const WindivertTcpHdr
                        )
                    };
                    let src_port = u16::from_be(tcp_header.src_port);
                    let dst_port = u16::from_be(tcp_header.dst_port);
                    let tcp_header_len = ((tcp_header.flags0 >> 4) as usize) * 4;
                    // Validate TCP header length (RFC 793: min 20, max 60 bytes)
                    if !(20..=60).contains(&tcp_header_len) {
                        return Ok(None);
                    }
                    let payload_start = transport_offset + tcp_header_len;
                    if total_len < payload_start {
                        return Ok(None);
                    }

                    let tcp_flags = TcpFlags::from_bits_truncate_value(tcp_header.flags1);

                    Ok(Some(
                        Packet::new(
                            FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Tcp),
                            direction,
                            bytes::Bytes::copy_from_slice(&packet_data[payload_start..total_len]),
                        )
                        .with_tcp_flags(tcp_flags),
                    ))
                }
                IPPROTO_UDP => {
                    if total_len < transport_offset + std::mem::size_of::<WindivertUdpHdr>() {
                        return Ok(None);
                    }

                    let udp_header = unsafe {
                        std::ptr::read_unaligned(
                            packet_data.as_ptr().add(transport_offset) as *const WindivertUdpHdr
                        )
                    };
                    let src_port = u16::from_be(udp_header.src_port);
                    let dst_port = u16::from_be(udp_header.dst_port);
                    let udp_len = u16::from_be(udp_header.len) as usize;
                    if udp_len < std::mem::size_of::<WindivertUdpHdr>() {
                        return Ok(None);
                    }
                    let payload_start = transport_offset + std::mem::size_of::<WindivertUdpHdr>();
                    let payload_end = transport_offset + udp_len;
                    if payload_end > total_len || payload_start > payload_end {
                        return Ok(None);
                    }

                    Ok(Some(Packet::new(
                        FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Udp),
                        direction,
                        bytes::Bytes::copy_from_slice(&packet_data[payload_start..payload_end]),
                    )))
                }
                other => Ok(Some(Packet::new(
                    FiveTuple::new(src_ip, dst_ip, 0, 0, Protocol::Unknown(other)),
                    direction,
                    bytes::Bytes::copy_from_slice(&packet_data[transport_offset..total_len]),
                ))),
            }
        }

        fn ipv6_transport_start(data: &[u8], offset: usize) -> Option<(u8, usize)> {
            let mut protocol = data[6];
            let mut offset = offset;

            for _ in 0..8 {
                match protocol {
                    0 | 43 | 60 => {
                        let next = *data.get(offset)?;
                        let len = usize::from(*data.get(offset + 1)?);
                        let header_len = 8usize.checked_mul(len.checked_add(1)?)?;
                        let next_offset = offset.checked_add(header_len)?;
                        if next_offset > data.len() {
                            return None;
                        }
                        protocol = next;
                        offset = next_offset;
                    }
                    44 => {
                        let header = data.get(offset..offset.checked_add(8)?)?;
                        let fragment = u16::from_be_bytes([header[2], header[3]]);
                        if fragment != 0 {
                            return None;
                        }
                        protocol = header[0];
                        offset = offset.checked_add(8)?;
                    }
                    59 => return None,
                    _ => return Some((protocol, offset)),
                }
            }

            None
        }

        fn parse_packet(
            data: &[u8],
            len: usize,
            addr: &WindivertAddress,
        ) -> Result<Option<Packet>> {
            let captured_len = len.min(data.len());
            if captured_len < 1 {
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

        fn packet_metadata(
            data: &[u8],
            len: usize,
        ) -> Option<(bool, u8, usize, IpAddr, IpAddr, usize)> {
            let captured_len = len.min(data.len());
            let version = data.first().map(|byte| byte >> 4)?;
            match version {
                4 => {
                    if captured_len < 20 {
                        return None;
                    }
                    let ihl = usize::from(data[0] & 0x0f).checked_mul(4)?;
                    if !(20..=60).contains(&ihl) || captured_len < ihl {
                        return None;
                    }
                    let total_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
                    if total_len < ihl || total_len > captured_len {
                        return None;
                    }
                    let fragment = u16::from_be_bytes([data[6], data[7]]);
                    if fragment & 0x3fff != 0 {
                        return None;
                    }
                    let src = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
                    let dst = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
                    let protocol = data[9];
                    let transport_len = match protocol {
                        IPPROTO_TCP => {
                            if total_len < ihl + 20 {
                                return None;
                            }
                            usize::from(data[ihl + 12] >> 4).checked_mul(4)?
                        }
                        IPPROTO_UDP => 8,
                        _ => 0,
                    };
                    if protocol == IPPROTO_TCP && !(20..=60).contains(&transport_len) {
                        return None;
                    }
                    if protocol == IPPROTO_TCP && total_len < ihl + transport_len {
                        return None;
                    }
                    if protocol == IPPROTO_UDP && total_len < ihl + 8 {
                        return None;
                    }
                    Some((false, protocol, ihl, src, dst, total_len))
                }
                6 => {
                    if captured_len < 40 {
                        return None;
                    }
                    let payload_len = usize::from(u16::from_be_bytes([data[4], data[5]]));
                    let total_len = 40usize.checked_add(payload_len)?;
                    if total_len > captured_len {
                        return None;
                    }
                    let src_bytes: [u8; 16] = data[8..24].try_into().ok()?;
                    let dst_bytes: [u8; 16] = data[24..40].try_into().ok()?;
                    let src = IpAddr::V6(Ipv6Addr::from(src_bytes));
                    let dst = IpAddr::V6(Ipv6Addr::from(dst_bytes));
                    let (protocol, transport_offset) =
                        Self::ipv6_transport_start(&data[..total_len], 40)?;
                    let transport_len = match protocol {
                        IPPROTO_TCP => {
                            if total_len < transport_offset + 20 {
                                return None;
                            }
                            usize::from(data[transport_offset + 12] >> 4).checked_mul(4)?
                        }
                        IPPROTO_UDP => 8,
                        _ => 0,
                    };
                    if protocol == IPPROTO_TCP && !(20..=60).contains(&transport_len) {
                        return None;
                    }
                    if protocol == IPPROTO_TCP && total_len < transport_offset + transport_len {
                        return None;
                    }
                    if protocol == IPPROTO_UDP && total_len < transport_offset + 8 {
                        return None;
                    }
                    Some((true, protocol, transport_offset, src, dst, total_len))
                }
                _ => None,
            }
        }

        fn redirect_target(
            redirects: &[PortRedirect],
            protocol: u8,
            destination_port: u16,
        ) -> Option<u16> {
            let is_tcp = protocol == IPPROTO_TCP;
            redirects
                .iter()
                .find(|redirect| {
                    redirect.is_tcp == is_tcp && redirect.source_port == Some(destination_port)
                })
                .or_else(|| {
                    redirects.iter().find(|redirect| {
                        redirect.is_tcp == is_tcp && redirect.source_port.is_none()
                    })
                })
                .map(|redirect| redirect.target_port)
        }

        fn rewrite_endpoint(
            data: &mut [u8],
            is_ipv6: bool,
            transport_offset: usize,
            source: bool,
            address: IpAddr,
            port: u16,
        ) -> bool {
            let (address_start, port_start) = if is_ipv6 {
                (
                    if source { 8 } else { 24 },
                    transport_offset + if source { 0 } else { 2 },
                )
            } else {
                (
                    if source { 12 } else { 16 },
                    transport_offset + if source { 0 } else { 2 },
                )
            };
            let address_bytes = match (is_ipv6, address) {
                (true, IpAddr::V6(address)) => address.octets().to_vec(),
                (false, IpAddr::V4(address)) => address.octets().to_vec(),
                _ => return false,
            };
            let Some(address_slot) =
                data.get_mut(address_start..address_start + address_bytes.len())
            else {
                return false;
            };
            address_slot.copy_from_slice(&address_bytes);
            let Some(port_slot) = data.get_mut(port_start..port_start + 2) else {
                return false;
            };
            port_slot.copy_from_slice(&port.to_be_bytes());
            true
        }

        fn redirect_packet(
            data: &mut [u8],
            len: usize,
            addr: &mut WindivertAddress,
            redirects: &[PortRedirect],
            flow_table: &Arc<Mutex<RedirectFlowTable>>,
        ) -> Result<()> {
            let Some((is_ipv6, protocol, transport_offset, src, dst, total_len)) =
                Self::packet_metadata(data, len)
            else {
                return Ok(());
            };
            if !matches!(protocol, IPPROTO_TCP | IPPROTO_UDP) {
                return Ok(());
            }

            let src_port = u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
            let dst_port =
                u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);
            let now = Instant::now();
            let mut flows = flow_table.lock();

            // Match replies before applying the outbound request rewrite. WinDivert
            // may classify replies as outbound and the local source can vary by
            // listener binding, so the flow key is the authoritative discriminator.
            let reverse = ReverseFlowKey {
                protocol,
                client: SocketAddr::new(dst, dst_port),
                listener_port: src_port,
            };
            if let Some((original_destination, original_client)) =
                flows.inbound_endpoints(&reverse, now)
            {
                if !Self::rewrite_endpoint(
                    data,
                    is_ipv6,
                    transport_offset,
                    true,
                    original_destination.ip(),
                    original_destination.port(),
                ) {
                    return Err(Error::Packet(
                        "Failed to rewrite loopback reply endpoint".into(),
                    ));
                }
                if !Self::rewrite_endpoint(
                    data,
                    is_ipv6,
                    transport_offset,
                    false,
                    original_client.ip(),
                    original_client.port(),
                ) {
                    return Err(Error::Packet(
                        "Failed to rewrite redirected reply destination".into(),
                    ));
                }
                return Ok(());
            }

            if addr.direction() == WINDIVERT_DIRECTION_OUT {
                if dst.is_loopback() {
                    return Ok(());
                }
                let original_destination = SocketAddr::new(dst, dst_port);
                let key = FlowKey {
                    protocol,
                    client: SocketAddr::new(src, src_port),
                    original_destination,
                };
                let listener_port = flows
                    .outbound_listener(&key, now)
                    .or_else(|| Self::redirect_target(redirects, protocol, dst_port));
                let Some(listener_port) = listener_port else {
                    return Ok(());
                };
                let new_flow = !flows.entries.contains_key(&key);
                if !Self::rewrite_endpoint(
                    data,
                    is_ipv6,
                    transport_offset,
                    true,
                    original_destination.ip(),
                    original_destination.port(),
                ) || !Self::rewrite_endpoint(
                    data,
                    is_ipv6,
                    transport_offset,
                    false,
                    key.client.ip(),
                    listener_port,
                ) {
                    return Err(Error::Packet(
                        "Failed to rewrite redirected endpoints".into(),
                    ));
                }
                // Reflect the packet into the inbound stack using the captured interface.
                addr.set_direction(WINDIVERT_DIRECTION_IN);
                if new_flow {
                    flows.insert(key, listener_port, now);
                }
            }

            if total_len > data.len() {
                return Err(Error::Packet(
                    "WinDivert packet length exceeds buffer".into(),
                ));
            }
            Ok(())
        }

        fn restore_original_packet(data: &mut [u8], original: &[u8], len: usize) -> bool {
            let (Some(destination), Some(source)) = (data.get_mut(..len), original.get(..len))
            else {
                return false;
            };
            destination.copy_from_slice(source);
            true
        }
    }

    #[async_trait]
    impl Interceptor for WinDivertInterceptor {
        async fn init(&mut self) -> Result<()> {
            if self.redirects.is_empty() {
                return Err(Error::Config(
                    "WinDivert interception requires at least one listener redirect rule".into(),
                ));
            }

            tracing::info!(
                "Initializing WinDivert interceptor with filter: {}",
                self.filter
            );

            let mut windivert = WinDivert::new();
            let handle = windivert
                .open(
                    &self.filter,
                    0,
                    WINDIVERT_LAYER_NETWORK,
                    WindivertFlags::DEFAULT.bits(),
                )
                .map_err(|e| Error::Interception(format!("Failed to open WinDivert: {}", e)))?;

            *self.handle.write() = Some(handle as usize);
            *self.windivert.lock() = Some(windivert);
            *self.running.write() = true;

            tracing::info!(
                "WinDivert interceptor initialized with {} redirect rule(s)",
                self.redirects.len()
            );
            Ok(())
        }

        async fn recv_packet(&self) -> Result<Packet> {
            let handle = (*self.handle.read())
                .ok_or_else(|| Error::InvalidState("WinDivert not initialized".into()))?;
            let windivert = Arc::clone(&self.windivert);
            let stats = Arc::clone(&self.stats);
            let flows = Arc::clone(&self.flows);
            let redirects = self.redirects.clone();

            tokio::task::spawn_blocking(move || {
                let handle = handle as HANDLE;
                loop {
                    let mut packet_buf = vec![0u8; 65535];
                    let mut addr = WindivertAddress::default();
                    let len = {
                        let guard = windivert.lock();
                        let api = guard.as_ref().ok_or_else(|| {
                            Error::InvalidState("WinDivert not initialized".into())
                        })?;
                        api.recv(handle, &mut packet_buf, &mut addr).map_err(|e| {
                            Error::Interception(format!("WinDivertRecv failed: {}", e))
                        })?
                    } as usize;

                    let original = packet_buf[..len].to_vec();
                    let original_addr = addr;
                    let mut restore_original = false;
                    let packet = match Self::parse_packet(&original, len, &addr) {
                        Ok(packet) => packet,
                        Err(err) => {
                            tracing::warn!(
                                "WinDivert packet parse failed; reinjecting original packet: {}",
                                err
                            );
                            restore_original = true;
                            None
                        }
                    };

                    if !restore_original
                        && let Err(err) = Self::redirect_packet(
                            &mut packet_buf,
                            len,
                            &mut addr,
                            &redirects,
                            &flows,
                        )
                    {
                        tracing::warn!(
                            "WinDivert packet rewrite failed; reinjecting original packet: {}",
                            err
                        );
                        restore_original = true;
                    }
                    if restore_original
                        && !Self::restore_original_packet(&mut packet_buf, &original, len)
                    {
                        return Err(Error::Packet(
                            "Failed to restore original WinDivert packet after rewrite error"
                                .into(),
                        ));
                    }

                    let guard = windivert.lock();
                    let api = guard
                        .as_ref()
                        .ok_or_else(|| Error::InvalidState("WinDivert not initialized".into()))?;
                    let mut send_addr = addr;
                    let send_result = api
                        .calc_checksums(&mut packet_buf[..len], &mut send_addr)
                        .and_then(|()| api.send(handle, &packet_buf[..len], &send_addr));
                    if let Err(error) = send_result {
                        // A failed rewrite or checksum/send must not strand the packet in the
                        // divert queue. Reinject the untouched frame before surfacing the error.
                        tracing::warn!(
                            "WinDivert modified-packet reinjection failed; retrying original packet: {}",
                            error
                        );
                        if !Self::restore_original_packet(&mut packet_buf, &original, len) {
                            return Err(Error::Packet(
                                "Failed to restore original WinDivert packet after reinjection error"
                                    .into(),
                            ));
                        }
                        api.send(handle, &packet_buf[..len], &original_addr).map_err(|fallback| {
                            Error::Interception(format!(
                                "WinDivertSend failed for modified packet ({}), and original packet fallback failed: {}",
                                error, fallback
                            ))
                        })?;
                    }

                    {
                        let mut guard = stats.write();
                        guard.packets_sent += 1;
                        guard.bytes_sent += len as u64;
                    }

                    let Some(packet) = packet else {
                        continue;
                    };
                    {
                        let mut guard = stats.write();
                        guard.packets_received += 1;
                        guard.bytes_received += packet.length as u64;
                    }
                    return Ok(packet);
                }
            })
            .await
            .map_err(|e| Error::Interception(format!("Join error: {}", e)))?
        }

        async fn send_packet(&self, packet: Packet) -> Result<()> {
            let _ = packet;
            Err(Error::NotSupported(
                "WinDivert reinjection requires the original network packet; use recv_packet"
                    .into(),
            ))
        }

        async fn shutdown(&mut self) -> Result<()> {
            tracing::info!("Shutting down WinDivert interceptor");
            *self.running.write() = false;

            let handle = self.handle.write().take();
            if let Some(handle) = handle {
                close_handle(handle as HANDLE)
                    .map_err(|e| Error::Interception(format!("WinDivertClose failed: {}", e)))?;
            }

            // Once the raw handle is closed, any blocked recv should unwind and
            // release the shared WinDivert state.
            self.windivert.lock().take();

            Ok(())
        }

        fn name(&self) -> &'static str {
            "windivert"
        }

        fn is_running(&self) -> bool {
            *self.running.read()
        }
    }

    fn validate_mode(config: &InterceptorConfig) -> Result<()> {
        match config.mode {
            nettrap_core::config::InterceptionMode::WinDivert => Ok(()),
            other => Err(Error::Interception(format!(
                "WinDivert interceptor requires interception mode 'windivert', got '{}'",
                other
            ))),
        }
    }

    fn build_filter(config: &InterceptorConfig) -> Result<String> {
        let mut clauses = vec!["(ip or ipv6) and (tcp or udp) and !impostor".to_string()];

        if let Some(iface) = &config.interface
            && let Some(ifidx) = parse_windivert_interface_index(Some(iface.as_str()))?
        {
            clauses.push(format!("ifIdx == {}", ifidx));
        }

        Ok(clauses.join(" and "))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn init_fails_closed_before_opening_windivert() {
            let config = InterceptorConfig {
                mode: nettrap_core::config::InterceptionMode::WinDivert,
                ..Default::default()
            };
            let mut interceptor = WinDivertInterceptor::new(config).expect("valid config");

            let error = interceptor
                .init()
                .await
                .expect_err("WinDivert must reject startup without redirect rules");
            assert!(matches!(error, Error::Config(message) if message.contains("redirect rule")));
        }

        #[test]
        fn parses_ipv4_tcp_packet() {
            let data: [u8; 40] = [
                0x45, 0x00, 0x00, 0x28, 0, 0, 0, 0, 64, 6, 0, 0, 192, 168, 1, 10, 93, 184, 216, 34,
                0x1f, 0x90, 0x00, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0x20, 0x00, 0, 0, 0, 0,
            ];
            let mut addr = WindivertAddress::default();
            addr.set_direction(WINDIVERT_DIRECTION_OUT);

            let packet = WinDivertInterceptor::parse_packet(&data, data.len(), &addr)
                .unwrap()
                .unwrap();

            assert_eq!(packet.five_tuple.src_port, 8080);
            assert_eq!(packet.five_tuple.dst_port, 80);
            assert_eq!(packet.five_tuple.protocol, Protocol::Tcp);
            assert_eq!(packet.direction, PacketDirection::Outbound);
        }

        #[test]
        fn parses_ipv4_udp_packet() {
            let data: [u8; 32] = [
                0x45, 0x00, 0x00, 0x20, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 8, 8, 8, 8, 0x30,
                0x39, 0x00, 0x35, 0x00, 0x0c, 0, 0, b't', b'e', b's', b't',
            ];
            let mut addr = WindivertAddress::default();
            addr.set_direction(WINDIVERT_DIRECTION_IN);

            let packet = WinDivertInterceptor::parse_packet(&data, data.len(), &addr)
                .unwrap()
                .unwrap();

            assert_eq!(packet.five_tuple.src_port, 12345);
            assert_eq!(packet.five_tuple.dst_port, 53);
            assert_eq!(packet.five_tuple.protocol, Protocol::Udp);
            assert!(packet.direction.is_inbound());
            assert_eq!(packet.payload.as_ref(), b"test");
        }

        #[test]
        fn ipv4_udp_payload_ignores_padding_after_declared_lengths() {
            let mut data = vec![
                0x45, 0x00, 0x00, 0x20, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 8, 8, 8, 8, 0x30,
                0x39, 0x00, 0x35, 0x00, 0x0c, 0, 0, b't', b'e', b's', b't',
            ];
            data.extend_from_slice(b"padding");
            let addr = WindivertAddress::default();

            let packet = WinDivertInterceptor::parse_packet(&data, data.len(), &addr)
                .unwrap()
                .unwrap();

            assert_eq!(packet.payload.as_ref(), b"test");
        }

        #[test]
        fn ipv4_udp_rejects_length_beyond_ip_payload() {
            let data: [u8; 32] = [
                0x45, 0x00, 0x00, 0x20, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 8, 8, 8, 8, 0x30,
                0x39, 0x00, 0x35, 0x00, 0x10, 0, 0, b't', b'e', b's', b't',
            ];
            let addr = WindivertAddress::default();

            let packet = WinDivertInterceptor::parse_packet(&data, data.len(), &addr).unwrap();

            assert!(packet.is_none());
        }

        #[test]
        fn ipv4_rejects_fragments_before_transport_parsing() {
            let mut data: [u8; 32] = [
                0x45, 0x00, 0x00, 0x20, 0, 0, 0x20, 0, 64, 17, 0, 0, 127, 0, 0, 1, 8, 8, 8, 8,
                0x30, 0x39, 0x00, 0x35, 0x00, 0x0c, 0, 0, b't', b'e', b's', b't',
            ];
            let addr = WindivertAddress::default();

            let first_fragment = WinDivertInterceptor::parse_packet(&data, data.len(), &addr)
                .expect("parse should not fail");
            assert!(first_fragment.is_none());

            data[6] = 0;
            data[7] = 1;
            let later_fragment = WinDivertInterceptor::parse_packet(&data, data.len(), &addr)
                .expect("parse should not fail");
            assert!(later_fragment.is_none());
        }

        #[test]
        fn parse_packet_rejects_empty_buffer_with_reported_length() {
            let addr = WindivertAddress::default();

            let packet = WinDivertInterceptor::parse_packet(&[], 1, &addr).unwrap();

            assert!(packet.is_none());
        }

        #[test]
        fn ipv6_udp_payload_ignores_padding_after_declared_lengths() {
            let mut data = vec![0x60, 0, 0, 0, 0x00, 0x0c, IPPROTO_UDP, 64];
            data.extend_from_slice(&[0u8; 16]);
            data.extend_from_slice(&[0u8; 15]);
            data.push(1);
            data.extend_from_slice(&[
                0x30, 0x39, 0x00, 0x35, 0x00, 0x0c, 0, 0, b't', b'e', b's', b't',
            ]);
            data.extend_from_slice(b"padding");
            let addr = WindivertAddress::default();

            let packet = WinDivertInterceptor::parse_packet(&data, data.len(), &addr)
                .unwrap()
                .unwrap();

            assert_eq!(packet.payload.as_ref(), b"test");
        }

        #[test]
        fn ipv6_udp_after_hop_by_hop_extension_parses() {
            let mut data = vec![0x60, 0, 0, 0, 0x00, 0x14, 0, 64];
            data.extend_from_slice(&[0u8; 16]);
            data.extend_from_slice(&[0u8; 15]);
            data.push(1);
            data.extend_from_slice(&[IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0]);
            data.extend_from_slice(&[
                0x30, 0x39, 0x00, 0x35, 0x00, 0x0c, 0, 0, b't', b'e', b's', b't',
            ]);
            let addr = WindivertAddress::default();

            let packet = WinDivertInterceptor::parse_packet(&data, data.len(), &addr)
                .unwrap()
                .unwrap();

            assert_eq!(packet.five_tuple.protocol, Protocol::Udp);
            assert_eq!(packet.payload.as_ref(), b"test");
        }

        #[test]
        fn ipv6_fragmented_udp_is_not_parsed_without_reassembly() {
            let mut data = vec![0x60, 0, 0, 0, 0x00, 0x14, 44, 64];
            data.extend_from_slice(&[0u8; 16]);
            data.extend_from_slice(&[0u8; 15]);
            data.push(1);
            data.extend_from_slice(&[IPPROTO_UDP, 0, 0, 1, 0, 0, 0, 1]);
            data.extend_from_slice(&[0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0, 0]);
            let addr = WindivertAddress::default();

            let packet = WinDivertInterceptor::parse_packet(&data, data.len(), &addr).unwrap();

            assert!(packet.is_none());
        }

        #[test]
        fn restoring_original_packet_discards_partial_rewrite() {
            let original = [0x45, 0x00, 0x00, 0x14];
            let mut rewritten = [0x45, 0x00, 0x00, 0x14];
            rewritten[1] = 0xff;

            assert!(WinDivertInterceptor::restore_original_packet(
                &mut rewritten,
                &original,
                original.len()
            ));
            assert_eq!(rewritten, original);
        }

        #[test]
        fn build_filter_uses_interface_constraint_without_dummy_clause() {
            let config = InterceptorConfig {
                mode: nettrap_core::config::InterceptionMode::WinDivert,
                interface: Some("7".to_string()),
                ..Default::default()
            };

            assert_eq!(
                build_filter(&config).unwrap(),
                "(ip or ipv6) and (tcp or udp) and !impostor and ifIdx == 7"
            );
        }

        #[test]
        fn build_filter_defaults_to_ipv4_and_ipv6_clause_for_windivert_mode() {
            let config = InterceptorConfig {
                mode: nettrap_core::config::InterceptionMode::WinDivert,
                ..Default::default()
            };

            assert_eq!(
                build_filter(&config).unwrap(),
                "(ip or ipv6) and (tcp or udp) and !impostor"
            );
        }

        #[test]
        fn redirect_flow_table_tracks_reverse_destination_with_a_bound() {
            let mut table = RedirectFlowTable::default();
            let key = FlowKey {
                protocol: IPPROTO_TCP,
                client: "192.0.2.10:40000".parse().unwrap(),
                original_destination: "198.51.100.20:443".parse().unwrap(),
            };
            let now = Instant::now();
            table.insert(key.clone(), 8443, now);

            assert_eq!(table.entries.len(), 1);
            assert_eq!(table.outbound_listener(&key, now), Some(8443));
            assert_eq!(
                table.inbound_endpoints(
                    &ReverseFlowKey {
                        protocol: IPPROTO_TCP,
                        client: "198.51.100.20:443".parse().unwrap(),
                        listener_port: 8443,
                    },
                    now,
                ),
                Some((
                    "198.51.100.20:443".parse().unwrap(),
                    "192.0.2.10:40000".parse().unwrap(),
                ))
            );

            for _ in 0..MAX_REDIRECT_EXPIRY_ENTRIES * 2 {
                table.touch(&key, Instant::now());
            }
            assert!(table.expiry.len() <= MAX_REDIRECT_EXPIRY_ENTRIES);

            for port in 0..MAX_REDIRECT_FLOWS + 1 {
                let key = FlowKey {
                    protocol: IPPROTO_UDP,
                    client: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port as u16),
                    original_destination: SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        10000 + (port as u16 % 1000),
                    ),
                };
                table.insert(key, 1000, now);
            }
            assert!(table.entries.len() <= MAX_REDIRECT_FLOWS);
        }

        #[test]
        fn redirect_flow_table_recovers_when_reverse_index_is_missing() {
            let mut table = RedirectFlowTable::default();
            let key = FlowKey {
                protocol: IPPROTO_TCP,
                client: "192.0.2.10:40000".parse().unwrap(),
                original_destination: "198.51.100.20:443".parse().unwrap(),
            };
            let now = Instant::now();
            table.insert(key, 8443, now);
            table.reverse.clear();

            assert_eq!(
                table.inbound_endpoints(
                    &ReverseFlowKey {
                        protocol: IPPROTO_TCP,
                        client: "198.51.100.20:443".parse().unwrap(),
                        listener_port: 8443,
                    },
                    now,
                ),
                Some((
                    "198.51.100.20:443".parse().unwrap(),
                    "192.0.2.10:40000".parse().unwrap(),
                ))
            );
        }

        #[test]
        fn redirects_ipv4_udp_and_restores_original_source_on_reply() {
            let mut outbound = vec![
                0x45,
                0,
                0,
                28,
                0,
                0,
                0,
                0,
                64,
                IPPROTO_UDP,
                0,
                0,
                192,
                0,
                2,
                10,
                198,
                51,
                100,
                20,
                0x9c,
                0x40,
                0,
                53,
                0,
                8,
                0,
                0,
            ];
            let redirects = vec![PortRedirect::new(53, false, 5353)];
            let flows = Arc::new(Mutex::new(RedirectFlowTable::default()));
            let mut outbound_addr = WindivertAddress::default();
            outbound_addr.set_direction(WINDIVERT_DIRECTION_OUT);
            let outbound_len = outbound.len();

            WinDivertInterceptor::redirect_packet(
                &mut outbound,
                outbound_len,
                &mut outbound_addr,
                &redirects,
                &flows,
            )
            .expect("outbound rewrite should succeed");

            assert_eq!(&outbound[12..16], &[198, 51, 100, 20]);
            assert_eq!(&outbound[16..20], &[192, 0, 2, 10]);
            assert_eq!(&outbound[20..22], &53u16.to_be_bytes());
            assert_eq!(&outbound[22..24], &5353u16.to_be_bytes());
            assert_eq!(outbound_addr.direction(), WINDIVERT_DIRECTION_IN);

            let mut inbound = vec![
                0x45,
                0,
                0,
                28,
                0,
                0,
                0,
                0,
                64,
                IPPROTO_UDP,
                0,
                0,
                192,
                0,
                2,
                10,
                198,
                51,
                100,
                20,
                0x14,
                0xe9,
                0x9c,
                0x40,
                0,
                8,
                0,
                0,
            ];
            let mut inbound_addr = WindivertAddress::default();
            inbound_addr.set_direction(WINDIVERT_DIRECTION_IN);
            let inbound_len = inbound.len();

            let mut outbound_reply = inbound.clone();
            let mut outbound_reply_addr = WindivertAddress::default();
            outbound_reply_addr.set_direction(WINDIVERT_DIRECTION_OUT);
            let outbound_reply_len = outbound_reply.len();
            WinDivertInterceptor::redirect_packet(
                &mut outbound_reply,
                outbound_reply_len,
                &mut outbound_reply_addr,
                &redirects,
                &flows,
            )
            .expect("outbound loopback reply rewrite should succeed");
            assert_eq!(&outbound_reply[12..16], &[198, 51, 100, 20]);
            assert_eq!(&outbound_reply[16..20], &[192, 0, 2, 10]);
            assert_eq!(&outbound_reply[20..22], &53u16.to_be_bytes());
            assert_eq!(&outbound_reply[22..24], &40000u16.to_be_bytes());

            WinDivertInterceptor::redirect_packet(
                &mut inbound,
                inbound_len,
                &mut inbound_addr,
                &redirects,
                &flows,
            )
            .expect("inbound rewrite should succeed");

            assert_eq!(&inbound[12..16], &[198, 51, 100, 20]);
            assert_eq!(&inbound[16..20], &[192, 0, 2, 10]);
            assert_eq!(&inbound[20..22], &53u16.to_be_bytes());
        }

        #[test]
        fn redirects_ipv4_tcp_and_restores_original_source_on_reply() {
            let mut outbound = vec![
                0x45,
                0,
                0,
                40,
                0,
                0,
                0,
                0,
                64,
                IPPROTO_TCP,
                0,
                0,
                192,
                0,
                2,
                10,
                198,
                51,
                100,
                20,
                0x9c,
                0x40,
                0,
                80,
                0,
                0,
                0,
                1,
                0,
                0,
                0,
                0,
                0x50,
                0x02,
                0x20,
                0,
                0,
                0,
                0,
                0,
            ];
            let redirects = vec![PortRedirect::new(80, true, 8080)];
            let flows = Arc::new(Mutex::new(RedirectFlowTable::default()));
            let mut outbound_addr = WindivertAddress::default();
            outbound_addr.set_direction(WINDIVERT_DIRECTION_OUT);
            let outbound_len = outbound.len();

            WinDivertInterceptor::redirect_packet(
                &mut outbound,
                outbound_len,
                &mut outbound_addr,
                &redirects,
                &flows,
            )
            .expect("outbound TCP rewrite should succeed");

            assert_eq!(&outbound[12..16], &[198, 51, 100, 20]);
            assert_eq!(&outbound[16..20], &[192, 0, 2, 10]);
            assert_eq!(&outbound[20..22], &80u16.to_be_bytes());
            assert_eq!(&outbound[22..24], &8080u16.to_be_bytes());
            assert_eq!(outbound_addr.direction(), WINDIVERT_DIRECTION_IN);

            let mut reply = vec![
                0x45,
                0,
                0,
                40,
                0,
                0,
                0,
                0,
                64,
                IPPROTO_TCP,
                0,
                0,
                192,
                0,
                2,
                10,
                198,
                51,
                100,
                20,
                0x1f,
                0x90,
                0x9c,
                0x40,
                0,
                0,
                0,
                2,
                0,
                0,
                0,
                1,
                0x50,
                0x10,
                0x20,
                0,
                0,
                0,
                0,
                0,
            ];
            let mut reply_addr = WindivertAddress::default();
            reply_addr.set_direction(WINDIVERT_DIRECTION_OUT);
            let reply_len = reply.len();

            WinDivertInterceptor::redirect_packet(
                &mut reply,
                reply_len,
                &mut reply_addr,
                &redirects,
                &flows,
            )
            .expect("loopback TCP reply rewrite should succeed");

            assert_eq!(&reply[12..16], &[198, 51, 100, 20]);
            assert_eq!(&reply[16..20], &[192, 0, 2, 10]);
            assert_eq!(&reply[20..22], &80u16.to_be_bytes());
            assert_eq!(&reply[22..24], &40000u16.to_be_bytes());
        }

        #[test]
        fn redirects_ipv6_udp_and_restores_original_source_on_reply() {
            let mut outbound = vec![
                0x60,
                0,
                0,
                0,
                0,
                8,
                IPPROTO_UDP,
                64,
                0x20,
                0x01,
                0x0d,
                0xb8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0x10,
                0x20,
                0x01,
                0x0d,
                0xb8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0x20,
                0x9c,
                0x40,
                0,
                53,
                0,
                8,
                0,
                0,
            ];
            outbound.truncate(48);
            outbound[8..24].copy_from_slice(&"2001:db8::10".parse::<Ipv6Addr>().unwrap().octets());
            outbound[24..40].copy_from_slice(&"2001:db8::20".parse::<Ipv6Addr>().unwrap().octets());
            outbound[40..48].copy_from_slice(&[0x9c, 0x40, 0, 53, 0, 8, 0, 0]);
            let redirects = vec![PortRedirect::new(53, false, 5353)];
            let flows = Arc::new(Mutex::new(RedirectFlowTable::default()));
            let mut outbound_addr = WindivertAddress::default();
            outbound_addr.set_direction(WINDIVERT_DIRECTION_OUT);
            let outbound_len = outbound.len();

            WinDivertInterceptor::redirect_packet(
                &mut outbound,
                outbound_len,
                &mut outbound_addr,
                &redirects,
                &flows,
            )
            .expect("outbound IPv6 rewrite should succeed");

            assert_eq!(
                &outbound[8..24],
                &"2001:db8::20".parse::<Ipv6Addr>().unwrap().octets()
            );
            assert_eq!(
                &outbound[24..40],
                &"2001:db8::10".parse::<Ipv6Addr>().unwrap().octets()
            );
            assert_eq!(&outbound[40..42], &53u16.to_be_bytes());
            assert_eq!(&outbound[42..44], &5353u16.to_be_bytes());

            let mut reply = vec![
                0x60,
                0,
                0,
                0,
                0,
                8,
                IPPROTO_UDP,
                64,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                1,
                0x20,
                0x01,
                0x0d,
                0xb8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0x10,
                0x14,
                0xe9,
                0x9c,
                0x40,
                0,
                8,
                0,
                0,
            ];
            reply.truncate(48);
            reply[8..24].copy_from_slice(&"2001:db8::10".parse::<Ipv6Addr>().unwrap().octets());
            reply[24..40].copy_from_slice(&"2001:db8::20".parse::<Ipv6Addr>().unwrap().octets());
            reply[40..48].copy_from_slice(&[0x14, 0xe9, 0x9c, 0x40, 0, 8, 0, 0]);
            let mut reply_addr = WindivertAddress::default();
            reply_addr.set_direction(WINDIVERT_DIRECTION_OUT);
            let reply_len = reply.len();

            WinDivertInterceptor::redirect_packet(
                &mut reply,
                reply_len,
                &mut reply_addr,
                &redirects,
                &flows,
            )
            .expect("loopback IPv6 reply rewrite should succeed");

            assert_eq!(
                &reply[8..24],
                &"2001:db8::20".parse::<Ipv6Addr>().unwrap().octets()
            );
            assert_eq!(
                &reply[24..40],
                &"2001:db8::10".parse::<Ipv6Addr>().unwrap().octets()
            );
            assert_eq!(&reply[40..42], &53u16.to_be_bytes());
            assert_eq!(&reply[42..44], &40000u16.to_be_bytes());
        }

        #[test]
        fn redirects_ipv6_tcp_and_restores_original_source_on_reply() {
            let client = "2001:db8::10".parse::<Ipv6Addr>().unwrap();
            let destination = "2001:db8::20".parse::<Ipv6Addr>().unwrap();
            let redirects = vec![PortRedirect::new(443, true, 8443)];
            let flows = Arc::new(Mutex::new(RedirectFlowTable::default()));

            let mut outbound = vec![0u8; 60];
            outbound[0] = 0x60;
            outbound[4..6].copy_from_slice(&20u16.to_be_bytes());
            outbound[6] = IPPROTO_TCP;
            outbound[7] = 64;
            outbound[8..24].copy_from_slice(&client.octets());
            outbound[24..40].copy_from_slice(&destination.octets());
            outbound[40..42].copy_from_slice(&40000u16.to_be_bytes());
            outbound[42..44].copy_from_slice(&443u16.to_be_bytes());
            outbound[52] = 0x50;
            outbound[53] = 0x02;

            let mut outbound_addr = WindivertAddress::default();
            outbound_addr.set_direction(WINDIVERT_DIRECTION_OUT);
            let outbound_len = outbound.len();
            WinDivertInterceptor::redirect_packet(
                &mut outbound,
                outbound_len,
                &mut outbound_addr,
                &redirects,
                &flows,
            )
            .expect("outbound IPv6 TCP rewrite should succeed");

            assert_eq!(&outbound[8..24], &destination.octets());
            assert_eq!(&outbound[24..40], &client.octets());
            assert_eq!(&outbound[40..42], &443u16.to_be_bytes());
            assert_eq!(&outbound[42..44], &8443u16.to_be_bytes());

            let mut reply = vec![0u8; 60];
            reply[0] = 0x60;
            reply[4..6].copy_from_slice(&20u16.to_be_bytes());
            reply[6] = IPPROTO_TCP;
            reply[7] = 64;
            reply[8..24].copy_from_slice(&client.octets());
            reply[24..40].copy_from_slice(&destination.octets());
            reply[40..42].copy_from_slice(&8443u16.to_be_bytes());
            reply[42..44].copy_from_slice(&40000u16.to_be_bytes());
            reply[52] = 0x50;
            reply[53] = 0x10;

            let mut reply_addr = WindivertAddress::default();
            reply_addr.set_direction(WINDIVERT_DIRECTION_OUT);
            let reply_len = reply.len();
            WinDivertInterceptor::redirect_packet(
                &mut reply,
                reply_len,
                &mut reply_addr,
                &redirects,
                &flows,
            )
            .expect("IPv6 TCP reply rewrite should succeed");

            assert_eq!(&reply[8..24], &destination.octets());
            assert_eq!(&reply[24..40], &client.octets());
            assert_eq!(&reply[40..42], &443u16.to_be_bytes());
            assert_eq!(&reply[42..44], &40000u16.to_be_bytes());
        }

        #[test]
        fn rejects_non_windivert_interception_modes() {
            let config = InterceptorConfig {
                mode: nettrap_core::config::InterceptionMode::Userspace,
                ..Default::default()
            };

            let result = WinDivertInterceptor::new(config);

            assert!(result.is_err());
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn parse_windivert_interface_index(interface: Option<&str>) -> Result<Option<u32>> {
    let Some(interface) = interface else {
        return Ok(None);
    };

    if interface.is_empty() {
        return Ok(None);
    }

    if interface.chars().all(|ch| ch.is_whitespace()) {
        return Ok(None);
    }

    if interface.trim_matches([' ', '\t']) != interface
        || interface
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return Err(Error::Interception(format!(
            "WinDivert interface must be a numeric interface index, got '{interface}'"
        )));
    }

    if !interface.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::Interception(format!(
            "WinDivert interface must be a numeric interface index, got '{interface}'"
        )));
    }

    let index = interface.parse::<u32>().map_err(|err| {
        Error::Interception(format!(
            "WinDivert interface index '{interface}' is invalid: {err}"
        ))
    })?;
    Ok(Some(index))
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
        DefaultInterceptor::new(validate_interceptor_config(self.config)?)
    }

    pub fn build_pcap(self) -> Result<crate::pcap::PcapInterceptor> {
        crate::pcap::PcapInterceptor::new(validate_interceptor_config(self.config)?)
    }

    #[cfg(all(
        target_os = "windows",
        any(target_arch = "x86_64", target_arch = "x86")
    ))]
    pub fn build_windivert(self) -> Result<crate::windivert::WinDivertInterceptor> {
        crate::windivert::WinDivertInterceptor::new(validate_interceptor_config(self.config)?)
    }
}

impl Default for InterceptorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_interceptor_config(mut config: InterceptorConfig) -> Result<InterceptorConfig> {
    config.interface = validate_optional_interface(config.interface)?;
    Ok(config)
}

fn validate_optional_interface(interface: Option<String>) -> Result<Option<String>> {
    let Some(interface) = interface else {
        return Ok(None);
    };
    if interface.is_empty() || interface.chars().all(|ch| ch.is_whitespace()) {
        return Ok(None);
    }

    if interface.trim_matches([' ', '\t']) != interface
        || interface
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return Err(Error::Interception(
            "interceptor interface cannot be padded".to_string(),
        ));
    }

    Ok(Some(interface))
}

#[cfg(test)]
mod interface_tests {
    use super::{InterceptorBuilder, parse_windivert_interface_index, validate_optional_interface};

    #[test]
    fn validate_optional_interface_drops_blank_value() {
        assert_eq!(
            validate_optional_interface(Some("  ".to_string())).expect("blank should be allowed"),
            None
        );
    }

    #[test]
    fn validate_optional_interface_keeps_non_blank_value() {
        assert_eq!(
            validate_optional_interface(Some("eth0".to_string())).expect("value should pass"),
            Some("eth0".to_string())
        );
    }

    #[test]
    fn interceptor_builder_rejects_ascii_padded_interface() {
        let err = match InterceptorBuilder::new().interface(" eth0 ").build() {
            Ok(_) => panic!("ascii padded interface should be rejected"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("interceptor interface cannot be padded")
        );
    }

    #[test]
    fn parse_windivert_interface_index_accepts_numeric_selector() {
        assert_eq!(parse_windivert_interface_index(Some("7")).unwrap(), Some(7));
    }

    #[test]
    fn parse_windivert_interface_index_rejects_non_numeric_selector() {
        let err = parse_windivert_interface_index(Some("7 or true"))
            .expect_err("malformed selector should be rejected");
        assert!(err.to_string().contains("numeric interface index"));
    }

    #[test]
    fn parse_windivert_interface_index_rejects_ascii_padding() {
        let err = parse_windivert_interface_index(Some(" 42 "))
            .expect_err("padded selector should be rejected");
        assert!(err.to_string().contains("numeric interface index"));
    }

    #[test]
    fn parse_windivert_interface_index_ignores_empty_selector() {
        assert_eq!(parse_windivert_interface_index(Some("  ")).unwrap(), None);
        assert_eq!(parse_windivert_interface_index(None).unwrap(), None);
    }
}
