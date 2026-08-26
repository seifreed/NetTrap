//! WinDivert Interceptor implementation.
//!
//! Contains the WinDivert adapter; runtime interception currently fails closed.

use crate::prelude::*;
use crate::bindings::{WinDivert, WindivertAddress, WINDIVERT_DIRECTION_OUT};
use parking_lot::RwLock;
use std::sync::Arc;

#[cfg(windows)]
pub struct WinDivertInterceptor {
    windivert: Arc<RwLock<Option<WinDivert>>>,
    handle: Arc<RwLock<Option<crate::bindings::HANDLE>>>,
    running: RwLock<bool>,
}

#[cfg(windows)]
impl WinDivertInterceptor {
    pub fn new(_config: crate::intercept::InterceptorConfig) -> Result<Self> {
        Ok(Self {
            windivert: Arc::new(RwLock::new(None)),
            handle: Arc::new(RwLock::new(None)),
            running: RwLock::new(false),
        })
    }

    fn parse_ipv4_packet(data: &[u8], len: usize) -> Result<Option<Packet>> {
        use crate::bindings::{WindivertIpHdr, WindivertTcpHdr, WindivertUdpHdr};

        let captured_len = len.min(data.len());
        if captured_len < std::mem::size_of::<WindivertIpHdr>() {
            return Ok(None);
        }

        let ip_header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const WindivertIpHdr) };
        let ihl = (ip_header.ver_hdrlen & 0x0F) as usize * 4;
        if !(20..=60).contains(&ihl) || captured_len < ihl {
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
            crate::bindings::IPPROTO_TCP => {
                if total_len < ihl + std::mem::size_of::<WindivertTcpHdr>() {
                    return Ok(None);
                }

                let tcp_header = unsafe {
                    std::ptr::read_unaligned(packet_data.as_ptr().add(ihl) as *const WindivertTcpHdr)
                };

                let src_port = u16::from_be(tcp_header.src_port);
                let dst_port = u16::from_be(tcp_header.dst_port);
                let tcp_header_len = ((tcp_header.flags0 >> 4) as usize) * 4;
                if !(20..=60).contains(&tcp_header_len) {
                    return Ok(None);
                }
                let payload_start = ihl + tcp_header_len;

                if total_len < payload_start {
                    return Ok(None);
                }

                Ok(Some(Packet::new(
                    FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Tcp),
                    PacketDirection::Outbound,
                    bytes::Bytes::copy_from_slice(&packet_data[payload_start..total_len]),
                )))
            }
            crate::bindings::IPPROTO_UDP => {
                if total_len < ihl + std::mem::size_of::<WindivertUdpHdr>() {
                    return Ok(None);
                }

                let udp_header = unsafe {
                    std::ptr::read_unaligned(packet_data.as_ptr().add(ihl) as *const WindivertUdpHdr)
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
                    PacketDirection::Outbound,
                    bytes::Bytes::copy_from_slice(&packet_data[payload_start..payload_end]),
                )))
            }
            _ => Ok(None),
        }
    }

    fn parse_ipv6_packet(data: &[u8], len: usize) -> Result<Option<Packet>> {
        use crate::bindings::{WindivertIpv6Hdr, WindivertTcpHdr, WindivertUdpHdr};

        let captured_len = len.min(data.len());
        if captured_len < std::mem::size_of::<WindivertIpv6Hdr>() {
            return Ok(None);
        }

        let ip_header =
            unsafe { std::ptr::read_unaligned(data.as_ptr() as *const WindivertIpv6Hdr) };
        let payload_len = u16::from_be(ip_header.plen) as usize;
        let total_len = 40usize
            .checked_add(payload_len)
            .filter(|total_len| *total_len <= captured_len);
        let Some(total_len) = total_len else {
            return Ok(None);
        };
        let packet_data = &data[..total_len];

        let src_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_header.src_addr));
        let dst_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_header.dst_addr));
        let Some((protocol, transport_offset)) = Self::ipv6_transport_start(packet_data, 40)
        else {
            return Ok(None);
        };

        match protocol {
            crate::bindings::IPPROTO_TCP => {
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
                if !(20..=60).contains(&tcp_header_len) {
                    return Ok(None);
                }
                let payload_start = transport_offset + tcp_header_len;

                if total_len < payload_start {
                    return Ok(None);
                }

                Ok(Some(Packet::new(
                    FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Tcp),
                    PacketDirection::Outbound,
                    bytes::Bytes::copy_from_slice(&packet_data[payload_start..total_len]),
                )))
            }
            crate::bindings::IPPROTO_UDP => {
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
                    PacketDirection::Outbound,
                    bytes::Bytes::copy_from_slice(&packet_data[payload_start..payload_end]),
                )))
            }
            _ => Ok(None),
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

    fn parse_packet(data: &[u8], len: usize) -> Result<Option<Packet>> {
        let captured_len = len.min(data.len());
        if captured_len < 1 {
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
        Err(Error::NotSupported(
            "Windows transparent interception is disabled until packet-preserving NAT redirection is implemented and validated; use listener mode".into(),
        ))
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

    async fn send_packet(&self, packet: Packet) -> Result<()> {
        // NOTE: `Packet` only carries the application-layer payload after
        // header stripping, so the original IP/transport headers are gone.
        // `encode_ip_packet` therefore SYNTHESIZES a best-effort IP packet
        // (sequence/ack/ttl/id are defaults). This re-injection path is
        // compiled-checked only and has NOT been verified against a live
        // Windows host / real WinDivert driver.
        let handle = self.handle.read();
        let handle =
            handle.ok_or_else(|| Error::InvalidState("WinDivert not initialized".into()))?;

        let windivert = self.windivert.read();
        let windivert = windivert
            .as_ref()
            .ok_or_else(|| Error::InvalidState("WinDivert not initialized".into()))?;

        let ip = nettrap_pcap::encode_ip_packet(&packet).map_err(|e| {
            Error::Interception(format!("Failed to reconstruct IP packet for re-injection: {}", e))
        })?;

        let mut addr = WindivertAddress::default();
        addr.set_direction(WINDIVERT_DIRECTION_OUT);

        windivert
            .send(handle, &ip, &addr)
            .map_err(|e| Error::Interception(format!("WinDivertSend failed: {}", e)))?;
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        tracing::info!("Shutting down WinDivert interceptor");
        *self.running.write() = false;

        if let Some(handle) = self.handle.write().take() {
            if let Some(windivert) = self.windivert.write().take() {
                windivert
                    .close(handle)
                    .map_err(|e| Error::Interception(format!("WinDivertClose failed: {}", e)))?;
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

#[cfg(all(test, windows))]
mod tests {
    use super::WinDivertInterceptor;

    #[test]
    fn ipv4_udp_payload_ignores_padding_after_declared_lengths() {
        let mut data = vec![
            0x45,
            0x00,
            0x00,
            0x20,
            0,
            0,
            0,
            0,
            64,
            crate::bindings::IPPROTO_UDP,
            0,
            0,
            127,
            0,
            0,
            1,
            8,
            8,
            8,
            8,
            0x30,
            0x39,
            0x00,
            0x35,
            0x00,
            0x0c,
            0,
            0,
            b't',
            b'e',
            b's',
            b't',
        ];
        data.extend_from_slice(b"padding");

        let packet = WinDivertInterceptor::parse_ipv4_packet(&data, data.len())
            .expect("parse should not fail")
            .expect("packet should parse");

        assert_eq!(packet.payload.as_ref(), b"test");
    }

    #[test]
    fn ipv4_udp_rejects_length_beyond_ip_payload() {
        let data = [
            0x45,
            0x00,
            0x00,
            0x20,
            0,
            0,
            0,
            0,
            64,
            crate::bindings::IPPROTO_UDP,
            0,
            0,
            127,
            0,
            0,
            1,
            8,
            8,
            8,
            8,
            0x30,
            0x39,
            0x00,
            0x35,
            0x00,
            0x10,
            0,
            0,
            b't',
            b'e',
            b's',
            b't',
        ];

        let packet = WinDivertInterceptor::parse_ipv4_packet(&data, data.len())
            .expect("parse should not fail");

        assert!(packet.is_none());
    }

    #[test]
    fn ipv4_rejects_fragments_before_transport_parsing() {
        let mut data = [
            0x45,
            0x00,
            0x00,
            0x20,
            0,
            0,
            0x20,
            0,
            64,
            crate::bindings::IPPROTO_UDP,
            0,
            0,
            127,
            0,
            0,
            1,
            8,
            8,
            8,
            8,
            0x30,
            0x39,
            0x00,
            0x35,
            0x00,
            0x0c,
            0,
            0,
            b't',
            b'e',
            b's',
            b't',
        ];

        let first_fragment = WinDivertInterceptor::parse_ipv4_packet(&data, data.len())
            .expect("parse should not fail");
        assert!(first_fragment.is_none());

        data[6] = 0;
        data[7] = 1;
        let later_fragment = WinDivertInterceptor::parse_ipv4_packet(&data, data.len())
            .expect("parse should not fail");
        assert!(later_fragment.is_none());
    }

    #[test]
    fn ipv6_udp_after_hop_by_hop_extension_parses() {
        let mut data = vec![0x60, 0, 0, 0, 0x00, 0x14, 0, 64];
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&[0u8; 15]);
        data.push(1);
        data.extend_from_slice(&[crate::bindings::IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0]);
        data.extend_from_slice(&[
            0x30, 0x39, 0x00, 0x35, 0x00, 0x0c, 0, 0, b't', b'e', b's', b't',
        ]);

        let packet = WinDivertInterceptor::parse_packet(&data, data.len())
            .expect("parse should not fail")
            .expect("packet should parse");

        assert_eq!(packet.five_tuple.protocol, Protocol::Udp);
        assert_eq!(packet.payload.as_ref(), b"test");
    }

    #[test]
    fn ipv6_fragmented_udp_is_not_parsed_without_reassembly() {
        let mut data = vec![0x60, 0, 0, 0, 0x00, 0x14, 44, 64];
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&[0u8; 15]);
        data.push(1);
        data.extend_from_slice(&[crate::bindings::IPPROTO_UDP, 0, 0, 1, 0, 0, 0, 1]);
        data.extend_from_slice(&[0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0, 0]);

        let packet = WinDivertInterceptor::parse_packet(&data, data.len())
            .expect("parse should not fail");

        assert!(packet.is_none());
    }

    #[test]
    fn parse_packet_rejects_reported_length_beyond_buffer() {
        let data = [
            0x45,
            0x00,
            0x00,
            0x20,
            0,
            0,
            0,
            0,
            64,
            crate::bindings::IPPROTO_UDP,
            0,
            0,
            127,
            0,
            0,
            1,
            8,
            8,
            8,
            8,
            0x30,
            0x39,
            0x00,
            0x35,
            0x00,
            0x0c,
            0,
            0,
            b't',
            b'e',
            b's',
            b't',
        ];

        let packet = WinDivertInterceptor::parse_packet(&data, data.len() + 64)
            .expect("parse should not fail")
            .expect("packet should parse from captured bytes only");

        assert_eq!(packet.payload.as_ref(), b"test");
    }

    #[test]
    fn parse_packet_rejects_empty_buffer_with_reported_length() {
        let packet = WinDivertInterceptor::parse_packet(&[], 1).expect("parse should not fail");

        assert!(packet.is_none());
    }
}
