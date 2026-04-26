use nom::{
    Err as NomErr, IResult,
    bytes::complete::take,
    error::{Error as NomError, ErrorKind},
    number::complete::be_u16,
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
    if data.len() < 20 {
        return Err(nom_error(data, ErrorKind::Eof));
    }

    let version_ihl = data[0];
    let version = version_ihl >> 4;
    let ihl = (version_ihl & 0x0F) as usize * 4;
    if version != 4 || ihl < 20 || ihl > data.len() {
        return Err(nom_error(data, ErrorKind::Verify));
    }

    let total_length = u16::from_be_bytes([data[2], data[3]]);
    let total_length_usize = total_length as usize;
    if total_length_usize < ihl || total_length_usize > data.len() {
        return Err(nom_error(data, ErrorKind::Verify));
    }

    let dscp_ecn = data[1];
    let identification = u16::from_be_bytes([data[4], data[5]]);
    let flags_fragment = u16::from_be_bytes([data[6], data[7]]);
    let ttl = data[8];
    let protocol = data[9];
    let src_addr = &data[12..16];
    let dst_addr = &data[16..20];

    Ok((
        &data[ihl..total_length_usize],
        Ipv4Header {
            version,
            ihl,
            dscp: dscp_ecn >> 2,
            ecn: dscp_ecn & 0x03,
            total_length,
            identification,
            flags: (flags_fragment >> 13) as u8,
            fragment_offset: flags_fragment & 0x1FFF,
            ttl,
            protocol,
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
    if data.len() < 20 {
        return Err(nom_error(data, ErrorKind::Eof));
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq_number = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack_number = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = ((data[12] >> 4) as usize) * 4;
    if data_offset < 20 || data_offset > data.len() {
        return Err(nom_error(data, ErrorKind::Verify));
    }
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);

    Ok((
        &data[data_offset..],
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
    if data.len() < 8 {
        return Err(nom_error(data, ErrorKind::Eof));
    }

    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);
    let length_usize = length as usize;
    if length_usize < 8 || length_usize > data.len() {
        return Err(nom_error(data, ErrorKind::Verify));
    }

    Ok((
        &data[8..length_usize],
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

    if let Ok(text) = std::str::from_utf8(data) {
        let first_line = text.lines().next().unwrap_or("").trim_end_matches('\r');
        if looks_like_http_request_line(first_line) || looks_like_http_response_line(first_line) {
            return Some(ApplicationProtocol::Http);
        }
    }

    if data.len() > 5 && data[0] == 0x16 && data[1] == 0x03 {
        return Some(ApplicationProtocol::Tls);
    }

    // DNS detection: validate header structure beyond just flags
    if data.len() >= 12 {
        let flags = u16::from_be_bytes([data[2], data[3]]);
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

fn looks_like_http_request_line(line: &str) -> bool {
    let mut parts = line.split(' ');
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(target) = parts.next() else {
        return false;
    };
    let Some(version) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }

    matches!(
        method,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT"
    ) && !target.is_empty()
        && !target.chars().any(char::is_whitespace)
        && matches!(version, "HTTP/1.0" | "HTTP/1.1")
}

fn looks_like_http_response_line(line: &str) -> bool {
    let mut parts = line.splitn(3, ' ');
    let Some(version) = parts.next() else {
        return false;
    };
    let Some(status) = parts.next() else {
        return false;
    };

    matches!(version, "HTTP/1.0" | "HTTP/1.1")
        && status.len() == 3
        && status.bytes().all(|byte| byte.is_ascii_digit())
}

fn nom_error(input: &[u8], kind: ErrorKind) -> NomErr<NomError<&[u8]>> {
    NomErr::Error(NomError::new(input, kind))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_header_uses_ihl_and_total_length() {
        let mut data = vec![
            0x46, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51,
            100, 2, 0xaa, 0xbb, 0xcc, 0xdd, b'd', b'a', b't', b'a',
        ];
        data.extend_from_slice(b"padding");

        let (payload, header) = parse_ipv4_header(&data).expect("valid IPv4 should parse");

        assert_eq!(header.version, 4);
        assert_eq!(header.ihl, 24);
        assert_eq!(header.total_length, 28);
        assert_eq!(payload, b"data");
    }

    #[test]
    fn ipv4_header_rejects_total_length_beyond_capture() {
        let data = [
            0x45, 0x00, 0x00, 0x28, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 8, 8, 8, 8,
        ];

        assert!(parse_ipv4_header(&data).is_err());
    }

    #[test]
    fn tcp_header_uses_data_offset() {
        let mut data = vec![
            0x30, 0x39, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 2, 0x60, 0x18, 0x20, 0, 0, 0, 0, 0, 0xaa,
            0xbb, 0xcc, 0xdd, b'o', b'k',
        ];
        data.extend_from_slice(b"padding");

        let (payload, header) = parse_tcp_header(&data).expect("valid TCP should parse");

        assert_eq!(header.data_offset, 24);
        assert_eq!(payload, b"okpadding");
    }

    #[test]
    fn udp_header_uses_declared_length() {
        let mut data = vec![
            0x30, 0x39, 0x00, 0x35, 0x00, 0x0c, 0, 0, b't', b'e', b's', b't',
        ];
        data.extend_from_slice(b"padding");

        let (payload, header) = parse_udp_header(&data).expect("valid UDP should parse");

        assert_eq!(header.length, 12);
        assert_eq!(payload, b"test");
    }

    #[test]
    fn dns_detection_reads_flags_from_dns_flags_field() {
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, b'e', b'x', b'a', b'm',
        ];
        let response = [0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

        assert_eq!(detect_protocol(&query), Some(ApplicationProtocol::Dns));
        assert_eq!(detect_protocol(&response), None);
    }

    #[test]
    fn http_detection_rejects_malformed_prefixes() {
        assert_eq!(detect_protocol(b"GET "), None);
        assert_eq!(detect_protocol(b"GET / HTTP/1.1 extra\r\n"), None);
        assert_eq!(detect_protocol(b"HTTP/1."), None);
        assert_eq!(detect_protocol(b"HTTP/2.0 200 OK\r\n"), None);
    }

    #[test]
    fn http_detection_accepts_valid_request_and_response_lines() {
        assert_eq!(
            detect_protocol(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
            Some(ApplicationProtocol::Http)
        );
        assert_eq!(
            detect_protocol(b"HTTP/1.1 200 OK\r\n\r\n"),
            Some(ApplicationProtocol::Http)
        );
    }
}
