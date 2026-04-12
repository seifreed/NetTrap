use nom::{
    IResult,
    bytes::complete::take,
    number::complete::{be_u16, be_u32},
};

use crate::prelude::*;

pub fn parse_ethernet_header(data: &[u8]) -> IResult<&[u8], EthernetHeader> {
    let (data, dst_mac) = take(6u8)(data)?;
    let (data, src_mac) = take(6u8)(data)?;
    let (data, ethertype) = be_u16(data)?;

    Ok((
        data,
        EthernetHeader {
            dst_mac: dst_mac.try_into().unwrap_or([0; 6]),
            src_mac: src_mac.try_into().unwrap_or([0; 6]),
            ethertype,
        },
    ))
}

#[derive(Debug, Clone)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

pub fn parse_ipv4_header(data: &[u8]) -> IResult<&[u8], Ipv4Header> {
    let (data, version_ihl) = take(1u8)(data)?;
    let (data, dscp_ecn) = take(1u8)(data)?;
    let (data, total_length) = be_u16(data)?;
    let (data, identification) = be_u16(data)?;
    let (data, flags_fragment) = be_u16(data)?;
    let (data, ttl) = take(1u8)(data)?;
    let (data, protocol) = take(1u8)(data)?;
    let (data, _checksum) = be_u16(data)?;
    let (data, src_addr) = take(4u8)(data)?;
    let (data, dst_addr) = take(4u8)(data)?;

    let version = version_ihl[0] >> 4;
    let ihl = (version_ihl[0] & 0x0F) as usize * 4;

    Ok((
        data,
        Ipv4Header {
            version,
            ihl,
            dscp: dscp_ecn[0] >> 2,
            ecn: dscp_ecn[0] & 0x03,
            total_length,
            identification,
            flags: (flags_fragment >> 13) as u8,
            fragment_offset: flags_fragment & 0x1FFF,
            ttl: ttl[0],
            protocol: protocol[0],
            src_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                src_addr[0],
                src_addr[1],
                src_addr[2],
                src_addr[3],
            )),
            dst_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                dst_addr[0],
                dst_addr[1],
                dst_addr[2],
                dst_addr[3],
            )),
        },
    ))
}

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: usize,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub src_addr: std::net::IpAddr,
    pub dst_addr: std::net::IpAddr,
}

pub fn parse_tcp_header(data: &[u8]) -> IResult<&[u8], TcpHeader> {
    let (data, src_port) = be_u16(data)?;
    let (data, dst_port) = be_u16(data)?;
    let (data, seq_number) = be_u32(data)?;
    let (data, ack_number) = be_u32(data)?;
    let (data, data_offset_flags) = be_u16(data)?;
    let (data, window) = be_u16(data)?;
    let (data, _checksum) = be_u16(data)?;
    let (data, urgent_ptr) = be_u16(data)?;

    let data_offset = ((data_offset_flags >> 12) & 0x0F) as usize * 4;
    let flags = (data_offset_flags & 0x003F) as u8;

    Ok((
        data,
        TcpHeader {
            src_port,
            dst_port,
            seq_number,
            ack_number,
            data_offset,
            flags,
            window,
            urgent_ptr,
        },
    ))
}

#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_number: u32,
    pub ack_number: u32,
    pub data_offset: usize,
    pub flags: u8,
    pub window: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    pub fn is_syn(&self) -> bool {
        self.flags & 0x02 != 0
    }

    pub fn is_ack(&self) -> bool {
        self.flags & 0x10 != 0
    }

    pub fn is_fin(&self) -> bool {
        self.flags & 0x01 != 0
    }

    pub fn is_rst(&self) -> bool {
        self.flags & 0x04 != 0
    }

    pub fn is_psh(&self) -> bool {
        self.flags & 0x08 != 0
    }
}

pub fn parse_udp_header(data: &[u8]) -> IResult<&[u8], UdpHeader> {
    let (data, src_port) = be_u16(data)?;
    let (data, dst_port) = be_u16(data)?;
    let (data, length) = be_u16(data)?;
    let (data, _checksum) = be_u16(data)?;

    Ok((
        data,
        UdpHeader {
            src_port,
            dst_port,
            length,
        },
    ))
}

#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
}

pub fn detect_protocol(data: &[u8]) -> Option<ApplicationProtocol> {
    if data.is_empty() {
        return None;
    }

    if data.starts_with(b"GET ")
        || data.starts_with(b"POST ")
        || data.starts_with(b"PUT ")
        || data.starts_with(b"DELETE ")
        || data.starts_with(b"HEAD ")
        || data.starts_with(b"OPTIONS ")
    {
        return Some(ApplicationProtocol::Http);
    }

    if data.starts_with(b"HTTP/1.") || data.starts_with(b"HTTP/2.") {
        return Some(ApplicationProtocol::Http);
    }

    if data.len() > 5 && data[0] == 0x16 && data[1] == 0x03 {
        return Some(ApplicationProtocol::Tls);
    }

    // DNS detection: validate header structure beyond just flags
    if data.len() >= 12 {
        let flags = u16::from_be_bytes([data[0], data[1]]);
        let is_query = (flags & 0x8000) == 0;
        let opcode = (flags >> 11) & 0x0F;
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        // Valid DNS: is query, standard/inverse opcode (0-2), has 1+ questions,
        // and does NOT start with printable ASCII (which would indicate HTTP/SMTP/etc.)
        if is_query && opcode <= 2 && (1..=100).contains(&qdcount) && !data[0].is_ascii_alphabetic()
        {
            return Some(ApplicationProtocol::Dns);
        }
    }

    None
}
