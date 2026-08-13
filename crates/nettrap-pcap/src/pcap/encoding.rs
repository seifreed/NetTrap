//! Stateless packet/IP/transport encoding and checksum helpers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::prelude::*;

/// Reconstruct a full IP packet (IPv4/IPv6 header + TCP/UDP segment with
/// checksums) from a `Packet`.
///
/// NOTE: a `Packet` only carries the application-layer payload after header
/// stripping, so the original IP/transport headers are NOT preserved — this
/// SYNTHESIZES a best-effort packet (sequence/ack numbers, IP id, TTL etc.
/// are defaults, see `encode_tcp_segment`). Suitable for PCAP encoding and
/// best-effort re-injection, not for byte-exact reproduction of a captured
/// packet.
pub fn encode_ip_packet(packet: &Packet) -> Result<Vec<u8>> {
    encode_raw_ip_packet(packet)
}

pub(crate) fn encode_raw_ip_packet(packet: &Packet) -> Result<Vec<u8>> {
    let transport = encode_transport_segment(packet)?;
    match (packet.five_tuple.src_ip, packet.five_tuple.dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => encode_ipv4_packet(packet, src, dst, &transport),
        (IpAddr::V6(src), IpAddr::V6(dst)) => encode_ipv6_packet(packet, src, dst, &transport),
        _ => Err(Error::Packet(
            "Cannot encode PCAP packet with mixed IPv4/IPv6 endpoints".into(),
        )),
    }
}

pub(crate) fn encode_transport_segment(packet: &Packet) -> Result<Vec<u8>> {
    match packet.five_tuple.protocol {
        Protocol::Tcp => encode_tcp_segment(packet),
        Protocol::Udp => encode_udp_segment(packet),
        Protocol::Icmp => encode_icmp_segment(packet),
        Protocol::Igmp | Protocol::Unknown(_) => Ok(packet.payload.to_vec()),
    }
}

pub(crate) fn encode_icmp_segment(packet: &Packet) -> Result<Vec<u8>> {
    let payload = packet.payload.as_ref();
    let segment_len = 8usize
        .checked_add(payload.len())
        .ok_or_else(|| Error::Packet("ICMP segment length overflow".into()))?;
    let mut segment = Vec::with_capacity(segment_len);

    match (packet.five_tuple.src_ip, packet.five_tuple.dst_ip) {
        (IpAddr::V4(_), IpAddr::V4(_)) => {
            let icmp_type = if packet.direction.is_inbound() { 0 } else { 8 };
            segment.extend_from_slice(&[icmp_type, 0, 0, 0, 0, 0, 0, 0]);
            segment.extend_from_slice(payload);
            let checksum = internet_checksum(&segment);
            segment[2..4].copy_from_slice(&checksum.to_be_bytes());
        }
        (IpAddr::V6(_), IpAddr::V6(_)) => {
            let icmp_type = if packet.direction.is_inbound() {
                129
            } else {
                128
            };
            segment.extend_from_slice(&[icmp_type, 0, 0, 0, 0, 0, 0, 0]);
            segment.extend_from_slice(payload);
            let checksum = transport_checksum(packet, 58, &segment)?;
            segment[2..4].copy_from_slice(&checksum.to_be_bytes());
        }
        _ => {
            return Err(Error::Packet(
                "Cannot encode ICMP segment with mixed IPv4/IPv6 endpoints".into(),
            ));
        }
    }

    Ok(segment)
}

pub(crate) fn encode_tcp_segment(packet: &Packet) -> Result<Vec<u8>> {
    let payload = packet.payload.as_ref();
    let segment_len = 20usize
        .checked_add(payload.len())
        .ok_or_else(|| Error::Packet("TCP segment length overflow".into()))?;
    if segment_len > u16::MAX as usize {
        return Err(Error::Packet(format!(
            "TCP segment too large for PCAP raw IP encoding: {} bytes",
            segment_len
        )));
    }

    let mut segment = Vec::with_capacity(segment_len);
    segment.extend_from_slice(&packet.five_tuple.src_port.to_be_bytes());
    segment.extend_from_slice(&packet.five_tuple.dst_port.to_be_bytes());
    segment.extend_from_slice(&0u32.to_be_bytes()); // sequence number
    segment.extend_from_slice(&0u32.to_be_bytes()); // acknowledgement number
    segment.push(5u8 << 4); // data offset, no options
    let flags = packet
        .tcp_flags
        .unwrap_or_else(|| {
            if payload.is_empty() {
                TcpFlags::ACK
            } else {
                TcpFlags::PSH | TcpFlags::ACK
            }
        })
        .bits();
    segment.push(flags);
    segment.extend_from_slice(&64240u16.to_be_bytes());
    segment.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    segment.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
    segment.extend_from_slice(payload);

    let checksum = transport_checksum(packet, 6, &segment)?;
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());

    Ok(segment)
}

pub(crate) fn encode_udp_segment(packet: &Packet) -> Result<Vec<u8>> {
    let payload = packet.payload.as_ref();
    let udp_len = 8usize
        .checked_add(payload.len())
        .ok_or_else(|| Error::Packet("UDP segment length overflow".into()))?;
    if udp_len > u16::MAX as usize {
        return Err(Error::Packet(format!(
            "UDP segment too large for PCAP raw IP encoding: {} bytes",
            udp_len
        )));
    }

    let mut segment = Vec::with_capacity(udp_len);
    segment.extend_from_slice(&packet.five_tuple.src_port.to_be_bytes());
    segment.extend_from_slice(&packet.five_tuple.dst_port.to_be_bytes());
    let udp_len =
        u16::try_from(udp_len).map_err(|_| Error::Packet("UDP segment length overflow".into()))?;
    segment.extend_from_slice(&udp_len.to_be_bytes());
    segment.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    segment.extend_from_slice(payload);

    let checksum = transport_checksum(packet, 17, &segment)?;
    // RFC 768: if the computed UDP checksum is zero, transmit 0xFFFF to
    // distinguish "computed zero" from "no checksum". TCP has no such rule.
    let checksum = if checksum == 0 { 0xffff } else { checksum };
    segment[6..8].copy_from_slice(&checksum.to_be_bytes());

    Ok(segment)
}

pub(crate) fn encode_ipv4_packet(
    packet: &Packet,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    transport: &[u8],
) -> Result<Vec<u8>> {
    let total_len = 20usize
        .checked_add(transport.len())
        .ok_or_else(|| Error::Packet("IPv4 packet length overflow".into()))?;
    if total_len > u16::MAX as usize {
        return Err(Error::Packet(format!(
            "IPv4 packet too large for PCAP raw IP encoding: {} bytes",
            total_len
        )));
    }

    let mut data = Vec::with_capacity(total_len);
    data.push(0x45);
    data.push(0);
    let total_len = u16::try_from(total_len)
        .map_err(|_| Error::Packet("IPv4 packet length overflow".into()))?;
    data.extend_from_slice(&total_len.to_be_bytes());
    data.extend_from_slice(&0u16.to_be_bytes()); // identification
    data.extend_from_slice(&0u16.to_be_bytes()); // flags and fragment offset
    data.push(64);
    data.push(ip_protocol_for_packet(packet, false));
    data.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    data.extend_from_slice(&src.octets());
    data.extend_from_slice(&dst.octets());
    let checksum = internet_checksum(&data[..20]);
    data[10..12].copy_from_slice(&checksum.to_be_bytes());
    data.extend_from_slice(transport);

    Ok(data)
}

pub(crate) fn encode_ipv6_packet(
    packet: &Packet,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    transport: &[u8],
) -> Result<Vec<u8>> {
    if transport.len() > u16::MAX as usize {
        return Err(Error::Packet(format!(
            "IPv6 payload too large for PCAP raw IP encoding: {} bytes",
            transport.len()
        )));
    }

    let mut data = Vec::with_capacity(40 + transport.len());
    data.extend_from_slice(&[0x60, 0, 0, 0]);
    let payload_len = u16::try_from(transport.len())
        .map_err(|_| Error::Packet("IPv6 payload length overflow".into()))?;
    data.extend_from_slice(&payload_len.to_be_bytes());
    data.push(ip_protocol_for_packet(packet, true));
    data.push(64);
    data.extend_from_slice(&src.octets());
    data.extend_from_slice(&dst.octets());
    data.extend_from_slice(transport);

    Ok(data)
}

fn ip_protocol_for_packet(packet: &Packet, ipv6: bool) -> u8 {
    if ipv6 && packet.five_tuple.protocol == Protocol::Icmp {
        58
    } else {
        packet.five_tuple.protocol.to_ip_protocol()
    }
}

pub(crate) fn transport_checksum(packet: &Packet, protocol: u8, segment: &[u8]) -> Result<u16> {
    let checksum = match (packet.five_tuple.src_ip, packet.five_tuple.dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => checksum_ipv4_pseudo(src, dst, protocol, segment)?,
        (IpAddr::V6(src), IpAddr::V6(dst)) => checksum_ipv6_pseudo(src, dst, protocol, segment)?,
        _ => {
            return Err(Error::Packet(
                "Cannot checksum transport segment with mixed IPv4/IPv6 endpoints".into(),
            ));
        }
    };

    Ok(checksum)
}

pub(crate) fn checksum_ipv4_pseudo(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    segment: &[u8],
) -> Result<u16> {
    if segment.len() > u16::MAX as usize {
        return Err(Error::Packet(format!(
            "Transport segment too large for IPv4 pseudo-header: {} bytes",
            segment.len()
        )));
    }

    let mut bytes = Vec::with_capacity(12 + segment.len() + 1);
    bytes.extend_from_slice(&src.octets());
    bytes.extend_from_slice(&dst.octets());
    bytes.push(0);
    bytes.push(protocol);
    let segment_len = u16::try_from(segment.len())
        .map_err(|_| Error::Packet("IPv4 pseudo-header segment length overflow".into()))?;
    bytes.extend_from_slice(&segment_len.to_be_bytes());
    bytes.extend_from_slice(segment);

    Ok(internet_checksum(&bytes))
}

pub(crate) fn checksum_ipv6_pseudo(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    protocol: u8,
    segment: &[u8],
) -> Result<u16> {
    if segment.len() > u32::MAX as usize {
        return Err(Error::Packet(format!(
            "Transport segment too large for IPv6 pseudo-header: {} bytes",
            segment.len()
        )));
    }

    let mut bytes = Vec::with_capacity(40 + segment.len() + 1);
    bytes.extend_from_slice(&src.octets());
    bytes.extend_from_slice(&dst.octets());
    let segment_len = u32::try_from(segment.len())
        .map_err(|_| Error::Packet("IPv6 pseudo-header segment length overflow".into()))?;
    bytes.extend_from_slice(&segment_len.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0]);
    bytes.push(protocol);
    bytes.extend_from_slice(segment);

    Ok(internet_checksum(&bytes))
}

pub(crate) fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    let bytes = sum.to_be_bytes();
    !u16::from_be_bytes([bytes[2], bytes[3]])
}

#[cfg(test)]
mod checksum_zero_regression_tests {
    use super::*;
    use nettrap_core::prelude::{FiveTuple, PacketDirection, Protocol};
    use std::net::{IpAddr, Ipv4Addr};

    /// Find a destination whose raw transport checksum folds to 0x0000 for the
    /// given protocol, by varying the two low octets of `10.0.x.y`.
    fn find_zero_checksum_dst(
        protocol: Protocol,
        build: &dyn Fn(&Packet) -> Vec<u8>,
        zero_at: usize,
    ) -> Option<Ipv4Addr> {
        let payload: bytes::Bytes = bytes::Bytes::from_static(b"");
        let src = Ipv4Addr::new(10, 0, 0, 1);
        for x in 0..=255u8 {
            for y in 1..=254u8 {
                let dst = Ipv4Addr::new(10, 0, x, y);
                let packet = Packet::new(
                    FiveTuple::new(IpAddr::V4(src), IpAddr::V4(dst), 4444, 80, protocol),
                    PacketDirection::Outbound,
                    payload.clone(),
                );
                let mut seg = build(&packet);
                seg[zero_at..zero_at + 2].copy_from_slice(&0u16.to_be_bytes());
                let proto_num = match protocol {
                    Protocol::Tcp => 6u8,
                    Protocol::Udp => 17u8,
                    _ => 0,
                };
                if transport_checksum(&packet, proto_num, &seg).unwrap() == 0 {
                    return Some(dst);
                }
            }
        }
        None
    }

    /// Regression: TCP must NOT apply the UDP "computed-zero -> 0xFFFF"
    /// substitution (RFC 9293 has no such rule). When the raw TCP checksum
    /// folds to zero the encoded segment must carry 0x0000.
    #[test]
    fn tcp_computed_zero_checksum_stays_zero() {
        let dst = find_zero_checksum_dst(
            Protocol::Tcp,
            &|p| encode_tcp_segment(p).expect("tcp segment"),
            16,
        )
        .expect("a TCP endpoint with zero checksum should exist");

        let payload: bytes::Bytes = bytes::Bytes::from_static(b"");
        let packet = Packet::new(
            FiveTuple::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(dst),
                4444,
                80,
                Protocol::Tcp,
            ),
            PacketDirection::Outbound,
            payload,
        );
        let segment = encode_tcp_segment(&packet).expect("tcp segment");
        let checksum = u16::from_be_bytes([segment[16], segment[17]]);
        assert_eq!(
            checksum, 0,
            "TCP computed-zero checksum must stay 0x0000, got 0x{checksum:04x}"
        );
    }

    /// Regression: UDP MUST apply the "computed-zero -> 0xFFFF" substitution
    /// (RFC 768) so a zero checksum is not confused with "no checksum".
    #[test]
    fn udp_computed_zero_checksum_becomes_ffff() {
        let dst = find_zero_checksum_dst(
            Protocol::Udp,
            &|p| encode_udp_segment(p).expect("udp segment"),
            6,
        )
        .expect("a UDP endpoint with zero checksum should exist");

        let payload: bytes::Bytes = bytes::Bytes::from_static(b"");
        let packet = Packet::new(
            FiveTuple::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(dst),
                4444,
                80,
                Protocol::Udp,
            ),
            PacketDirection::Outbound,
            payload,
        );
        let segment = encode_udp_segment(&packet).expect("udp segment");
        let checksum = u16::from_be_bytes([segment[6], segment[7]]);
        assert_eq!(
            checksum, 0xffff,
            "UDP computed-zero checksum must become 0xFFFF, got 0x{checksum:04x}"
        );
    }
}
