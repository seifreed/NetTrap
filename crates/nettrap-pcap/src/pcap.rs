use parking_lot::RwLock;
use std::fs::File;
use std::path::Path;

use crate::prelude::*;

/// PCAP global header (24 bytes) - libpcap format
const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_THISZONE: i32 = 0;
const PCAP_SIGFIGS: u32 = 0;
const PCAP_SNAPLEN: u32 = 65535;
const PCAP_LINKTYPE_RAW: u32 = 101; // LINKTYPE_RAW (raw IP)

pub struct PcapWriter {
    file: RwLock<Option<File>>,
    path: String,
    enabled: RwLock<bool>,
}

impl PcapWriter {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            file: RwLock::new(None),
            path: path.into(),
            enabled: RwLock::new(false),
        }
    }

    pub fn enable(&self) {
        *self.enabled.write() = true;
    }

    pub fn disable(&self) {
        *self.enabled.write() = false;
    }

    pub fn is_enabled(&self) -> bool {
        *self.enabled.read()
    }

    pub fn open(&self) -> Result<()> {
        let path = Path::new(&self.path);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = File::create(&self.path)?;
        *self.file.write() = Some(file);
        *self.enabled.write() = true;

        // Write PCAP global header
        self.write_global_header()?;

        Ok(())
    }

    pub fn close(&self) {
        let _ = self.flush();
        *self.file.write() = None;
        *self.enabled.write() = false;
    }

    fn write_global_header(&self) -> Result<()> {
        use std::io::Write;
        let mut file = self.file.write();
        if let Some(ref mut f) = *file {
            f.write_all(&PCAP_MAGIC.to_le_bytes())?;
            f.write_all(&PCAP_VERSION_MAJOR.to_le_bytes())?;
            f.write_all(&PCAP_VERSION_MINOR.to_le_bytes())?;
            f.write_all(&PCAP_THISZONE.to_le_bytes())?;
            f.write_all(&PCAP_SIGFIGS.to_le_bytes())?;
            f.write_all(&PCAP_SNAPLEN.to_le_bytes())?;
            f.write_all(&PCAP_LINKTYPE_RAW.to_le_bytes())?;
        }
        Ok(())
    }

    /// Write a packet record in PCAP format.
    /// Each record: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4) + data
    pub fn write_packet(&self, packet: &Packet) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        use std::io::Write;
        let mut file = self.file.write();
        if let Some(ref mut f) = *file {
            let ts_sec = packet.timestamp.timestamp() as u32;
            let ts_usec = packet.timestamp.timestamp_subsec_micros();
            let data = &packet.payload;
            let incl_len = data.len() as u32;
            let orig_len = packet.length as u32;

            // Packet record header (16 bytes)
            f.write_all(&ts_sec.to_le_bytes())?;
            f.write_all(&ts_usec.to_le_bytes())?;
            f.write_all(&incl_len.to_le_bytes())?;
            f.write_all(&orig_len.to_le_bytes())?;
            // Packet data
            f.write_all(data)?;
        }

        Ok(())
    }

    /// Write raw bytes as a PCAP packet with current timestamp
    pub fn write_raw(&self, data: &[u8]) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        use std::io::Write;
        let mut file = self.file.write();
        if let Some(ref mut f) = *file {
            let now = chrono::Utc::now();
            let ts_sec = now.timestamp() as u32;
            let ts_usec = now.timestamp_subsec_micros();
            let len = data.len() as u32;

            f.write_all(&ts_sec.to_le_bytes())?;
            f.write_all(&ts_usec.to_le_bytes())?;
            f.write_all(&len.to_le_bytes())?;
            f.write_all(&len.to_le_bytes())?;
            f.write_all(data)?;
        }

        Ok(())
    }

    /// Write a pair of packets (original + mangled) for comparison
    pub fn write_packet_pair(&self, original: &Packet, mangled: &Packet) -> Result<()> {
        self.write_packet(original)?;
        self.write_packet(mangled)?;
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        use std::io::Write;
        let mut file = self.file.write();
        if let Some(ref mut f) = *file {
            f.flush()?;
        }
        Ok(())
    }
}

pub struct PcapReader {
    path: String,
}

/// Byte-swapped PCAP magic (big-endian capture on little-endian host or vice-versa)
const PCAP_MAGIC_SWAPPED: u32 = 0xd4c3b2a1;
/// Nanosecond-resolution PCAP magic
const PCAP_MAGIC_NANO: u32 = 0xa1b23c4d;
const PCAP_MAGIC_NANO_SWAPPED: u32 = 0x4d3cb2a1;

impl PcapReader {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }

    /// Read a libpcap file and return all packets.
    /// Supports both little-endian and big-endian (byte-swapped) PCAP formats,
    /// and both microsecond and nanosecond timestamp resolution.
    pub fn read_file(&self) -> Result<Vec<Packet>> {
        use std::io::Read;

        let mut file = File::open(&self.path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        if buf.len() < 24 {
            return Err(Error::Packet(
                "PCAP file too short for global header".into(),
            ));
        }

        // Parse global header (24 bytes)
        let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let (swapped, nano) = match magic {
            PCAP_MAGIC => (false, false),
            PCAP_MAGIC_SWAPPED => (true, false),
            PCAP_MAGIC_NANO => (false, true),
            PCAP_MAGIC_NANO_SWAPPED => (true, true),
            _ => {
                return Err(Error::Packet(format!(
                    "Invalid PCAP magic: 0x{:08x}",
                    magic
                )))
            }
        };

        let read_u32 = |data: &[u8], offset: usize| -> u32 {
            let raw = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            if swapped {
                raw.swap_bytes()
            } else {
                raw
            }
        };
        let read_u16 = |data: &[u8], offset: usize| -> u16 {
            let raw = u16::from_le_bytes([data[offset], data[offset + 1]]);
            if swapped {
                raw.swap_bytes()
            } else {
                raw
            }
        };

        let _version_major = read_u16(&buf, 4);
        let _version_minor = read_u16(&buf, 6);
        let _thiszone = read_u32(&buf, 8) as i32;
        let _sigfigs = read_u32(&buf, 12);
        let snaplen = read_u32(&buf, 16) as usize;
        let linktype = read_u32(&buf, 20);

        tracing::debug!(
            "PCAP: linktype={}, snaplen={}, swapped={}, nano={}",
            linktype,
            snaplen,
            swapped,
            nano
        );

        // Determine IP offset based on link type
        let link_header_len = match linktype {
            1 => 14,      // LINKTYPE_ETHERNET
            101 => 0,     // LINKTYPE_RAW
            12 | 14 => 4, // LINKTYPE_NULL / LINKTYPE_LOOP (BSD loopback)
            113 => 16,    // LINKTYPE_LINUX_SLL
            _ => 0,       // Assume raw IP for unknown types
        };

        let mut packets = Vec::new();
        let mut pos = 24; // skip global header

        while pos + 16 <= buf.len() {
            // Packet record header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4)
            let ts_sec = read_u32(&buf, pos) as i64;
            let ts_frac = read_u32(&buf, pos + 4);
            let incl_len = read_u32(&buf, pos + 8) as usize;
            let orig_len = read_u32(&buf, pos + 12) as usize;
            pos += 16;

            // Sanity check
            if incl_len > snaplen || pos + incl_len > buf.len() {
                tracing::warn!("PCAP: truncated packet at offset {}, stopping", pos);
                break;
            }

            let pkt_data = &buf[pos..pos + incl_len];
            pos += incl_len;

            // Convert timestamp
            let ts_nsec = if nano { ts_frac } else { ts_frac * 1000 };
            let timestamp =
                chrono::DateTime::from_timestamp(ts_sec, ts_nsec).unwrap_or_else(chrono::Utc::now);

            // Parse IP packet from link-layer frame
            if let Some(pkt) =
                Self::parse_link_packet(pkt_data, linktype, link_header_len, timestamp, orig_len)
            {
                packets.push(pkt);
            }
        }

        tracing::info!("PCAP: read {} packets from {}", packets.len(), self.path);
        Ok(packets)
    }

    fn parse_link_packet(
        data: &[u8],
        linktype: u32,
        link_header_len: usize,
        timestamp: chrono::DateTime<chrono::Utc>,
        orig_len: usize,
    ) -> Option<Packet> {
        if data.len() < link_header_len {
            return None;
        }

        let ip_data = match linktype {
            1 => {
                // Ethernet: check ethertype, handle VLAN
                if data.len() < 14 {
                    return None;
                }
                let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
                let mut offset = 14;
                while ethertype == 0x8100 || ethertype == 0x88A8 {
                    if data.len() < offset + 4 {
                        return None;
                    }
                    ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                    offset += 4;
                }
                match ethertype {
                    0x0800 | 0x86DD => &data[offset..],
                    _ => return None,
                }
            }
            12 | 14 => {
                // BSD null/loop: 4-byte family header
                if data.len() < 4 {
                    return None;
                }
                &data[4..]
            }
            113 => {
                // Linux SLL: 16-byte header
                if data.len() < 16 {
                    return None;
                }
                &data[16..]
            }
            _ => data, // raw IP
        };

        if ip_data.is_empty() {
            return None;
        }

        let version = (ip_data[0] >> 4) & 0x0F;
        match version {
            4 => Self::parse_ipv4_packet(ip_data, timestamp, orig_len),
            6 => Self::parse_ipv6_packet(ip_data, timestamp, orig_len),
            _ => None,
        }
    }

    fn parse_ipv4_packet(
        data: &[u8],
        timestamp: chrono::DateTime<chrono::Utc>,
        orig_len: usize,
    ) -> Option<Packet> {
        if data.len() < 20 {
            return None;
        }

        let ihl = (data[0] & 0x0F) as usize * 4;
        if ihl < 20 || data.len() < ihl {
            return None;
        }

        let protocol = data[9];
        let src_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            data[12], data[13], data[14], data[15],
        ));
        let dst_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            data[16], data[17], data[18], data[19],
        ));

        Self::parse_transport(data, ihl, protocol, src_ip, dst_ip, timestamp, orig_len)
    }

    fn parse_ipv6_packet(
        data: &[u8],
        timestamp: chrono::DateTime<chrono::Utc>,
        orig_len: usize,
    ) -> Option<Packet> {
        if data.len() < 40 {
            return None;
        }

        let protocol = data[6]; // next header
        let src_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
            data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ]));
        let dst_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from([
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
            data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
        ]));

        Self::parse_transport(data, 40, protocol, src_ip, dst_ip, timestamp, orig_len)
    }

    fn parse_transport(
        data: &[u8],
        transport_offset: usize,
        protocol: u8,
        src_ip: std::net::IpAddr,
        dst_ip: std::net::IpAddr,
        timestamp: chrono::DateTime<chrono::Utc>,
        orig_len: usize,
    ) -> Option<Packet> {
        use nettrap_core::prelude::*;

        match protocol {
            6 => {
                // TCP
                if data.len() < transport_offset + 20 {
                    return None;
                }
                let tcp_hdr_len = ((data[transport_offset + 12] >> 4) as usize) * 4;
                if !(20..=60).contains(&tcp_hdr_len) {
                    return None;
                }
                let payload_start = transport_offset + tcp_hdr_len;
                if data.len() < payload_start {
                    return None;
                }

                let src_port =
                    u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
                let dst_port =
                    u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);
                let flags = TcpFlags::from_bits_truncate_value(data[transport_offset + 13]);

                let mut pkt = Packet::new(
                    FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Tcp),
                    PacketDirection::Unknown,
                    bytes::Bytes::copy_from_slice(&data[payload_start..]),
                )
                .with_tcp_flags(flags);
                pkt.timestamp = timestamp;
                pkt.length = orig_len;
                Some(pkt)
            }
            17 => {
                // UDP
                if data.len() < transport_offset + 8 {
                    return None;
                }
                let src_port =
                    u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
                let dst_port =
                    u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);
                let payload_start = transport_offset + 8;

                let mut pkt = Packet::new(
                    FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Udp),
                    PacketDirection::Unknown,
                    bytes::Bytes::copy_from_slice(&data[payload_start.min(data.len())..]),
                );
                pkt.timestamp = timestamp;
                pkt.length = orig_len;
                Some(pkt)
            }
            1 | 58 => {
                // ICMP / ICMPv6
                let payload_start = (transport_offset + 8).min(data.len());
                let mut pkt = Packet::new(
                    FiveTuple::new(src_ip, dst_ip, 0, 0, Protocol::Icmp),
                    PacketDirection::Unknown,
                    bytes::Bytes::copy_from_slice(&data[payload_start..]),
                );
                pkt.timestamp = timestamp;
                pkt.length = orig_len;
                Some(pkt)
            }
            _ => None,
        }
    }
}
