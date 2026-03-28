use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use pcap::{ConnectionStatus, Device, Direction, Linktype};

use crate::prelude::*;

pub struct PcapInterceptor {
    config: crate::intercept::InterceptorConfig,
    capture: Arc<Mutex<Option<pcap::Capture<pcap::Active>>>>,
    running: RwLock<bool>,
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
        let desc = device.desc.as_deref().unwrap_or_default().to_ascii_lowercase();
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
        if device
            .addresses
            .iter()
            .any(|addr| !addr.addr.is_loopback())
        {
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
        match linktype {
            Linktype::ETHERNET => Self::parse_ethernet(data, len, interface),
            Linktype::RAW | Linktype::IPV4 => Self::parse_ip_packet(data, len, 0, Some(4), interface),
            Linktype::IPV6 => Self::parse_ip_packet(data, len, 0, Some(6), interface),
            Linktype::NULL | Linktype::LOOP => Self::parse_null_loopback(data, len, interface),
            _ => Self::parse_ip_packet(data, len, 0, None, interface),
        }
    }

    fn parse_ethernet(data: &[u8], len: usize, interface: &str) -> Result<Option<Packet>> {
        if len < 14 {
            return Ok(None);
        }

        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        match ethertype {
            0x0800 => Self::parse_ipv4(data, len, 14, interface),
            0x86DD => Self::parse_ipv6(data, len, 14, interface),
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

    fn parse_ipv4(data: &[u8], len: usize, ip_offset: usize, interface: &str) -> Result<Option<Packet>> {
        if len < ip_offset + 20 {
            return Ok(None);
        }

        let ihl = (data[ip_offset] & 0x0F) as usize * 4;
        if ihl < 20 || len < ip_offset + ihl {
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

        Self::parse_transport(data, len, ip_offset + ihl, protocol_num, src_ip, dst_ip, interface)
    }

    fn parse_ipv6(data: &[u8], len: usize, ip_offset: usize, interface: &str) -> Result<Option<Packet>> {
        if len < ip_offset + 40 {
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

        Self::parse_transport(data, len, ip_offset + 40, protocol_num, src_ip, dst_ip, interface)
    }

    fn parse_transport(
        data: &[u8],
        len: usize,
        transport_offset: usize,
        protocol: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        interface: &str,
    ) -> Result<Option<Packet>> {
        if len < transport_offset {
            return Ok(None);
        }

        match protocol {
            6 => {
                if len < transport_offset + 20 {
                    return Ok(None);
                }

                let tcp_header_len = ((data[transport_offset + 12] >> 4) as usize) * 4;
                if tcp_header_len < 20 || len < transport_offset + tcp_header_len {
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
                    PacketDirection::Unknown,
                    bytes::Bytes::copy_from_slice(&data[payload_start..len]),
                )
                .with_tcp_flags(flags)
                .with_interface(interface.to_string());
                packet.length = len;
                Ok(Some(packet))
            }
            17 => {
                if len < transport_offset + 8 {
                    return Ok(None);
                }

                let src_port =
                    u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
                let dst_port =
                    u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);
                let payload_start = transport_offset + 8;

                let mut packet = Packet::new(
                    FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Udp),
                    PacketDirection::Unknown,
                    bytes::Bytes::copy_from_slice(&data[payload_start..len]),
                )
                .with_interface(interface.to_string());
                packet.length = len;
                Ok(Some(packet))
            }
            1 | 58 => {
                let payload_start = (transport_offset + 8).min(len);
                let mut packet = Packet::new(
                    FiveTuple::new(src_ip, dst_ip, 0, 0, Protocol::Icmp),
                    PacketDirection::Unknown,
                    bytes::Bytes::copy_from_slice(&data[payload_start..len]),
                )
                .with_interface(interface.to_string());
                packet.length = len;
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
                    Err(pcap::Error::TimeoutExpired) => continue,
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
        Err(Error::NotSupported("Pcap capture cannot send packets".into()))
    }

    async fn shutdown(&mut self) -> Result<()> {
        tracing::info!("Shutting down pcap interceptor");
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
