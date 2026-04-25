use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use pcap::{ConnectionStatus, Device, Direction, Linktype};

use crate::prelude::*;

pub struct PcapInterceptor {
    config: crate::intercept::InterceptorConfig,
    capture: Arc<Mutex<Option<pcap::Capture<pcap::Active>>>>,
    running: RwLock<bool>,
    shutdown_flag: Arc<AtomicBool>,
    interface: String,
    linktype: Arc<RwLock<Option<Linktype>>>,
}

impl PcapInterceptor {
    pub fn new(config: crate::intercept::InterceptorConfig) -> Result<Self> {
        let interface = match config.interface.clone() {
            Some(interface) => interface,
            None => Self::default_device_name()?,
        };

        Ok(Self {
            config,
            capture: Arc::new(Mutex::new(None)),
            running: RwLock::new(false),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            interface,
            linktype: Arc::new(RwLock::new(None)),
        })
    }

    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = interface.into();
        self
    }

    fn default_device_name() -> Result<String> {
        let mut devices = Device::list()
            .map_err(|e| Error::Interception(format!("Failed to list devices: {}", e)))?;
        devices.sort_by_key(Self::device_score);

        devices
            .pop()
            .map(|device| device.name)
            .ok_or_else(|| Error::Interception("No capture devices found".into()))
    }

    fn device_score(device: &Device) -> i32 {
        let mut score = 0;
        let desc = device
            .desc
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let name = device.name.to_ascii_lowercase();

        if device.flags.is_up() {
            score += 40;
        }
        if device.flags.is_running() {
            score += 30;
        }
        if !device.flags.is_loopback() {
            score += 20;
        }
        if !device.addresses.is_empty() {
            score += 20;
        }
        if device.addresses.iter().any(|addr| addr.addr.is_ipv4()) {
            score += 15;
        }
        if device.addresses.iter().any(|addr| !addr.addr.is_loopback()) {
            score += 20;
        }

        if desc.contains("ethernet") || name.contains("ethernet") {
            score += 25;
        }
        if desc.contains("wi-fi") || desc.contains("wifi") || name.contains("wi-fi") {
            score += 25;
        }
        if desc.contains("virtio") {
            score += 20;
        }
        if desc.contains("nordlynx") {
            score += 15;
        }
        if desc.contains("miniport") {
            score -= 60;
        }
        if desc.contains("network monitor") {
            score -= 80;
        }
        if desc.contains("wan") {
            score -= 40;
        }
        if desc.contains("loopback") || name.contains("loopback") {
            score -= 100;
        }

        score
            + match device.flags.connection_status {
                ConnectionStatus::Connected => 25,
                ConnectionStatus::NotApplicable => 10,
                ConnectionStatus::Unknown => 5,
                ConnectionStatus::Disconnected => 0,
            }
    }

    fn resolve_device(devices: Vec<Device>, requested: &str) -> Option<Device> {
        let requested_lower = requested.to_ascii_lowercase();

        devices
            .iter()
            .find(|device| device.name.eq_ignore_ascii_case(requested))
            .cloned()
            .or_else(|| {
                devices
                    .iter()
                    .find(|device| {
                        device
                            .desc
                            .as_deref()
                            .map(|desc| desc.eq_ignore_ascii_case(requested))
                            .unwrap_or(false)
                    })
                    .cloned()
            })
            .or_else(|| {
                devices
                    .iter()
                    .find(|device| {
                        device.name.to_ascii_lowercase().contains(&requested_lower)
                            || device
                                .desc
                                .as_deref()
                                .map(|desc| desc.to_ascii_lowercase().contains(&requested_lower))
                                .unwrap_or(false)
                    })
                    .cloned()
            })
    }

    fn parse_packet(
        data: &[u8],
        len: usize,
        linktype: Linktype,
        interface: &str,
    ) -> Result<Option<Packet>> {
        let len = len.min(data.len());
        match linktype {
            Linktype::ETHERNET => Self::parse_ethernet(data, len, interface),
            Linktype::RAW | Linktype::IPV4 => {
                Self::parse_ip_packet(data, len, 0, Some(4), interface)
            }
            Linktype::IPV6 => Self::parse_ip_packet(data, len, 0, Some(6), interface),
            Linktype::NULL | Linktype::LOOP => Self::parse_null_loopback(data, len, interface),
            _ => Self::parse_ip_packet(data, len, 0, None, interface),
        }
    }

    fn parse_ethernet(data: &[u8], len: usize, interface: &str) -> Result<Option<Packet>> {
        if len < 14 {
            return Ok(None);
        }

        let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
        let mut ip_offset = 14;

        // Handle 802.1Q VLAN tagging (and stacked QinQ), with depth limit
        // to prevent DoS from maliciously nested VLAN tags
        const MAX_VLAN_DEPTH: usize = 8;
        let mut vlan_depth = 0;
        while ethertype == 0x8100 || ethertype == 0x88A8 {
            vlan_depth += 1;
            if vlan_depth > MAX_VLAN_DEPTH {
                tracing::debug!(
                    "Dropping packet: VLAN nesting depth exceeds {}",
                    MAX_VLAN_DEPTH
                );
                return Ok(None);
            }
            if len < ip_offset + 4 {
                return Ok(None);
            }
            ethertype = u16::from_be_bytes([data[ip_offset + 2], data[ip_offset + 3]]);
            ip_offset += 4;
        }

        match ethertype {
            0x0800 => Self::parse_ipv4(data, len, ip_offset, interface),
            0x86DD => Self::parse_ipv6(data, len, ip_offset, interface),
            _ => Ok(None),
        }
    }

    fn parse_null_loopback(data: &[u8], len: usize, interface: &str) -> Result<Option<Packet>> {
        if len < 4 {
            return Ok(None);
        }

        let family = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
        match family {
            2 => Self::parse_ipv4(data, len, 4, interface),
            23 | 24 | 28 | 30 => Self::parse_ipv6(data, len, 4, interface),
            _ => Ok(None),
        }
    }

    fn parse_ip_packet(
        data: &[u8],
        len: usize,
        offset: usize,
        version_hint: Option<u8>,
        interface: &str,
    ) -> Result<Option<Packet>> {
        if len <= offset {
            return Ok(None);
        }

        let version = version_hint.unwrap_or((data[offset] >> 4) & 0x0F);
        match version {
            4 => Self::parse_ipv4(data, len, offset, interface),
            6 => Self::parse_ipv6(data, len, offset, interface),
            _ => Ok(None),
        }
    }

    fn parse_ipv4(
        data: &[u8],
        len: usize,
        ip_offset: usize,
        interface: &str,
    ) -> Result<Option<Packet>> {
        if len < ip_offset + 20 {
            return Ok(None);
        }

        let ihl = (data[ip_offset] & 0x0F) as usize * 4;
        if ihl < 20 || len < ip_offset + ihl {
            return Ok(None);
        }
        let total_len = u16::from_be_bytes([data[ip_offset + 2], data[ip_offset + 3]]) as usize;
        if total_len < ihl {
            return Ok(None);
        }
        let Some(packet_end) = ip_offset.checked_add(total_len) else {
            return Ok(None);
        };
        if packet_end > len {
            return Ok(None);
        }

        let src_ip = IpAddr::V4(Ipv4Addr::new(
            data[ip_offset + 12],
            data[ip_offset + 13],
            data[ip_offset + 14],
            data[ip_offset + 15],
        ));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(
            data[ip_offset + 16],
            data[ip_offset + 17],
            data[ip_offset + 18],
            data[ip_offset + 19],
        ));
        let protocol_num = data[ip_offset + 9];

        Self::parse_transport(
            data,
            packet_end,
            ip_offset + ihl,
            protocol_num,
            src_ip,
            dst_ip,
            interface,
        )
    }

    fn parse_ipv6(
        data: &[u8],
        len: usize,
        ip_offset: usize,
        interface: &str,
    ) -> Result<Option<Packet>> {
        if len < ip_offset + 40 {
            return Ok(None);
        }
        let payload_len = u16::from_be_bytes([data[ip_offset + 4], data[ip_offset + 5]]) as usize;
        let Some(packet_end) = ip_offset.checked_add(40 + payload_len) else {
            return Ok(None);
        };
        if packet_end > len {
            return Ok(None);
        }

        let src_ip = IpAddr::V6(Ipv6Addr::from([
            data[ip_offset + 8],
            data[ip_offset + 9],
            data[ip_offset + 10],
            data[ip_offset + 11],
            data[ip_offset + 12],
            data[ip_offset + 13],
            data[ip_offset + 14],
            data[ip_offset + 15],
            data[ip_offset + 16],
            data[ip_offset + 17],
            data[ip_offset + 18],
            data[ip_offset + 19],
            data[ip_offset + 20],
            data[ip_offset + 21],
            data[ip_offset + 22],
            data[ip_offset + 23],
        ]));
        let dst_ip = IpAddr::V6(Ipv6Addr::from([
            data[ip_offset + 24],
            data[ip_offset + 25],
            data[ip_offset + 26],
            data[ip_offset + 27],
            data[ip_offset + 28],
            data[ip_offset + 29],
            data[ip_offset + 30],
            data[ip_offset + 31],
            data[ip_offset + 32],
            data[ip_offset + 33],
            data[ip_offset + 34],
            data[ip_offset + 35],
            data[ip_offset + 36],
            data[ip_offset + 37],
            data[ip_offset + 38],
            data[ip_offset + 39],
        ]));
        let protocol_num = data[ip_offset + 6];

        Self::parse_transport(
            data,
            packet_end,
            ip_offset + 40,
            protocol_num,
            src_ip,
            dst_ip,
            interface,
        )
    }

    /// Infer packet direction based on IP addresses.
    /// Local/private source with public destination = Outbound, and vice versa.
    fn infer_direction(src_ip: &IpAddr, dst_ip: &IpAddr) -> PacketDirection {
        let src_local = src_ip.is_loopback()
            || match src_ip {
                IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
                IpAddr::V6(v6) => {
                    let o = v6.octets();
                    (o[0] & 0xFE) == 0xFC || (o[0] == 0xFE && (o[1] & 0xC0) == 0x80)
                }
            };
        let dst_local = dst_ip.is_loopback()
            || match dst_ip {
                IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
                IpAddr::V6(v6) => {
                    let o = v6.octets();
                    (o[0] & 0xFE) == 0xFC || (o[0] == 0xFE && (o[1] & 0xC0) == 0x80)
                }
            };

        match (src_local, dst_local) {
            (true, false) => PacketDirection::Outbound,
            (false, true) => PacketDirection::Inbound,
            _ => PacketDirection::Unknown,
        }
    }

    fn parse_transport(
        data: &[u8],
        packet_end: usize,
        transport_offset: usize,
        protocol: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        interface: &str,
    ) -> Result<Option<Packet>> {
        if packet_end < transport_offset {
            return Ok(None);
        }

        let direction = Self::infer_direction(&src_ip, &dst_ip);

        match protocol {
            6 => {
                if packet_end < transport_offset + 20 {
                    return Ok(None);
                }

                let tcp_header_len = ((data[transport_offset + 12] >> 4) as usize) * 4;
                if tcp_header_len < 20 || packet_end < transport_offset + tcp_header_len {
                    return Ok(None);
                }

                let src_port =
                    u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
                let dst_port =
                    u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);
                let flags = TcpFlags::from_bits_truncate_value(data[transport_offset + 13]);
                let payload_start = transport_offset + tcp_header_len;

                let mut packet = Packet::new(
                    FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Tcp),
                    direction,
                    bytes::Bytes::copy_from_slice(&data[payload_start..packet_end]),
                )
                .with_tcp_flags(flags)
                .with_interface(interface.to_string());
                packet.length = packet_end;
                Ok(Some(packet))
            }
            17 => {
                if packet_end < transport_offset + 8 {
                    return Ok(None);
                }
                let udp_len =
                    u16::from_be_bytes([data[transport_offset + 4], data[transport_offset + 5]])
                        as usize;
                if udp_len < 8 {
                    return Ok(None);
                }
                let Some(udp_end) = transport_offset.checked_add(udp_len) else {
                    return Ok(None);
                };
                if udp_end > packet_end {
                    return Ok(None);
                }

                let src_port =
                    u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
                let dst_port =
                    u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);
                let payload_start = transport_offset + 8;

                let mut packet = Packet::new(
                    FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Udp),
                    direction,
                    bytes::Bytes::copy_from_slice(&data[payload_start..udp_end]),
                )
                .with_interface(interface.to_string());
                packet.length = udp_end;
                Ok(Some(packet))
            }
            1 | 58 => {
                let payload_start = (transport_offset + 8).min(packet_end);
                let mut packet = Packet::new(
                    FiveTuple::new(src_ip, dst_ip, 0, 0, Protocol::Icmp),
                    direction,
                    bytes::Bytes::copy_from_slice(&data[payload_start..packet_end]),
                )
                .with_interface(interface.to_string());
                packet.length = packet_end;
                Ok(Some(packet))
            }
            _ => Ok(None),
        }
    }
}

#[async_trait]
impl Interceptor for PcapInterceptor {
    async fn init(&mut self) -> Result<()> {
        let devices = Device::list()
            .map_err(|e| Error::Interception(format!("Failed to list devices: {}", e)))?;
        let device = Self::resolve_device(devices, &self.interface).ok_or_else(|| {
            Error::Interception(format!("Interface {} not found", self.interface))
        })?;

        tracing::info!(
            "Initializing pcap interceptor on interface {} ({})",
            self.interface,
            device.desc.as_deref().unwrap_or("no description")
        );

        let promiscuous = if cfg!(all(target_os = "windows", target_arch = "aarch64")) {
            false
        } else {
            self.config.promiscuous
        };

        tracing::info!("Opening Npcap device (promiscuous={})", promiscuous);
        let mut cap = pcap::Capture::from_device(device)
            .map_err(|e| Error::Interception(format!("Failed to open device: {}", e)))?
            .promisc(promiscuous)
            .snaplen(self.config.buffer_size as i32)
            .timeout(250)
            .immediate_mode(true)
            .open()
            .map_err(|e| Error::Interception(format!("Failed to activate capture: {}", e)))?;

        tracing::info!("Npcap device opened; configuring filter");
        if !cfg!(all(target_os = "windows", target_arch = "aarch64")) {
            cap.direction(Direction::InOut)
                .map_err(|e| Error::Interception(format!("Failed to set direction: {}", e)))?;
        }
        cap.filter("ip or ip6", true)
            .map_err(|e| Error::Interception(format!("Failed to set filter: {}", e)))?;

        let linktype = cap.get_datalink();
        let linktype_name = linktype
            .get_name()
            .unwrap_or_else(|_| format!("LINKTYPE({})", linktype.0));
        tracing::info!("Npcap datalink type: {}", linktype_name);

        *self.linktype.write() = Some(linktype);
        *self.capture.lock() = Some(cap);
        *self.running.write() = true;

        tracing::info!("Pcap interceptor initialized successfully");
        Ok(())
    }

    async fn recv_packet(&self) -> Result<Packet> {
        let capture = self.capture.clone();
        let linktype = self.linktype.clone();
        let interface = self.interface.clone();
        let shutdown_flag = self.shutdown_flag.clone();

        tokio::task::spawn_blocking(move || {
            let mut cap_guard = capture.lock();
            let cap = cap_guard
                .as_mut()
                .ok_or_else(|| Error::InvalidState("Capture not initialized".into()))?;
            let packet_linktype = (*linktype.read()).unwrap_or_else(|| cap.get_datalink());

            loop {
                match cap.next_packet() {
                    Ok(packet) => {
                        if let Some(pkt) = Self::parse_packet(
                            packet.data,
                            packet.header.len as usize,
                            packet_linktype,
                            &interface,
                        )? {
                            return Ok(pkt);
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        if shutdown_flag.load(Ordering::Relaxed) {
                            return Err(Error::InvalidState("Shutdown requested".into()));
                        }
                        continue;
                    }
                    Err(e) => {
                        return Err(Error::Interception(format!(
                            "Failed to receive packet: {}",
                            e
                        )));
                    }
                }
            }
        })
        .await
        .map_err(|e| Error::Interception(format!("Join error: {}", e)))?
    }

    async fn send_packet(&self, _packet: Packet) -> Result<()> {
        Err(Error::NotSupported(
            "Pcap capture cannot send packets".into(),
        ))
    }

    async fn shutdown(&mut self) -> Result<()> {
        tracing::info!("Shutting down pcap interceptor");
        // Signal the recv loop to exit before acquiring the capture lock
        self.shutdown_flag.store(true, Ordering::Relaxed);
        *self.running.write() = false;
        *self.capture.lock() = None;
        *self.linktype.write() = None;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "pcap"
    }

    fn is_running(&self) -> bool {
        *self.running.read()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet_header(ethertype: u16) -> Vec<u8> {
        let mut frame = vec![0xaa; 6];
        frame.extend_from_slice(&[0xbb; 6]);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame
    }

    fn ipv4_header(total_len: usize, protocol: u8) -> Vec<u8> {
        let mut header = vec![0u8; 20];
        header[0] = 0x45;
        header[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        header[8] = 64;
        header[9] = protocol;
        header[12..16].copy_from_slice(&[10, 0, 0, 1]);
        header[16..20].copy_from_slice(&[8, 8, 8, 8]);
        header
    }

    fn udp_header(src: u16, dst: u16, len: usize) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&src.to_be_bytes());
        header.extend_from_slice(&dst.to_be_bytes());
        header.extend_from_slice(&(len as u16).to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes());
        header
    }

    #[test]
    fn pcap_ipv4_udp_ignores_ethernet_padding() {
        let udp_payload = b"abc";
        let udp_len = 8 + udp_payload.len();
        let ip_total_len = 20 + udp_len;
        let mut frame = ethernet_header(0x0800);
        frame.extend_from_slice(&ipv4_header(ip_total_len, 17));
        frame.extend_from_slice(&udp_header(1234, 53, udp_len));
        frame.extend_from_slice(udp_payload);
        frame.extend_from_slice(&[0xee; 32]);

        let packet = PcapInterceptor::parse_packet(&frame, frame.len(), Linktype::ETHERNET, "en0")
            .expect("parse should not fail")
            .expect("packet should parse");

        assert_eq!(packet.five_tuple.protocol, Protocol::Udp);
        assert_eq!(packet.payload.as_ref(), udp_payload);
        assert_eq!(packet.length, 14 + ip_total_len);
    }

    #[test]
    fn pcap_ipv4_udp_respects_declared_udp_length() {
        let udp_payload = b"abc";
        let udp_len = 8 + udp_payload.len();
        let ip_total_len = 20 + udp_len + 2;
        let mut frame = ethernet_header(0x0800);
        frame.extend_from_slice(&ipv4_header(ip_total_len, 17));
        frame.extend_from_slice(&udp_header(1234, 53, udp_len));
        frame.extend_from_slice(udp_payload);
        frame.extend_from_slice(b"xx");

        let packet = PcapInterceptor::parse_packet(&frame, frame.len(), Linktype::ETHERNET, "en0")
            .expect("parse should not fail")
            .expect("packet should parse");

        assert_eq!(packet.payload.as_ref(), udp_payload);
        assert_eq!(packet.length, 14 + 20 + udp_len);
    }

    #[test]
    fn pcap_ipv6_tcp_ignores_trailing_capture_bytes() {
        let mut frame = ethernet_header(0x86dd);
        let mut ipv6 = vec![0u8; 40];
        ipv6[0] = 0x60;
        ipv6[4..6].copy_from_slice(&20u16.to_be_bytes());
        ipv6[6] = 6;
        ipv6[7] = 64;
        ipv6[39] = 1;
        frame.extend_from_slice(&ipv6);

        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x02;
        frame.extend_from_slice(&tcp);
        frame.extend_from_slice(&[0xee; 24]);

        let packet = PcapInterceptor::parse_packet(&frame, frame.len(), Linktype::ETHERNET, "en0")
            .expect("parse should not fail")
            .expect("packet should parse");

        assert_eq!(packet.five_tuple.protocol, Protocol::Tcp);
        assert!(packet.payload.is_empty());
        assert_eq!(packet.length, 14 + 40 + 20);
    }
}
