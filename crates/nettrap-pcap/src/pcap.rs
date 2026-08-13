use parking_lot::RwLock;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::prelude::*;
use nettrap_fsutil::open_regular_file_beneath_root;

mod encoding;
pub use encoding::*;

/// PCAP global header (24 bytes) - libpcap format
const PCAP_MAGIC: u32 = 0xa1b2c3d4;
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_THISZONE: i32 = 0;
const PCAP_SIGFIGS: u32 = 0;
const PCAP_SNAPLEN: u32 = 65535;
const PCAP_LINKTYPE_ETHERNET: u32 = 1;
const PCAP_LINKTYPE_NULL: u32 = 12;
const PCAP_LINKTYPE_LOOP: u32 = 14;
const PCAP_LINKTYPE_RAW: u32 = 101;
const PCAP_LINKTYPE_LINUX_SLL: u32 = 113;
const PCAP_LINKTYPE_IPV4: u32 = 228;
const PCAP_LINKTYPE_IPV6: u32 = 229;
const MAX_PCAP_READ_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PCAP_RECORDS: usize = 100_000;
const MAX_PCAP_RECORD_BYTES: usize = PCAP_SNAPLEN as usize;

pub struct PcapWriter {
    file: RwLock<Option<File>>,
    path: PathBuf,
    enabled: RwLock<bool>,
    now: fn() -> chrono::DateTime<chrono::Utc>,
}

impl PcapWriter {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(Error::Storage(
                "PCAP output path must not be empty".to_string(),
            ));
        }

        Ok(Self {
            file: RwLock::new(None),
            path,
            enabled: RwLock::new(false),
            now: chrono::Utc::now,
        })
    }

    pub fn with_now(mut self, now: fn() -> chrono::DateTime<chrono::Utc>) -> Self {
        self.now = now;
        self
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
        let file = crate::writer::create_regular_output_file(Path::new(&self.path))?;
        *self.file.write() = Some(file);
        *self.enabled.write() = true;

        // Write PCAP global header
        self.write_global_header()?;

        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        self.flush()?;
        *self.file.write() = None;
        *self.enabled.write() = false;
        Ok(())
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
        let Some(ref mut f) = *file else {
            return Err(Error::Storage("PCAP writer is enabled but not open".into()));
        };
        let ts_sec = pcap_timestamp_seconds(packet.timestamp)?;
        let ts_usec = packet.timestamp.timestamp_subsec_micros();
        let data = encode_raw_ip_packet(packet)?;
        let incl_len = pcap_record_len(data.len())?;
        let orig_len = incl_len;

        // Packet record header (16 bytes)
        f.write_all(&ts_sec.to_le_bytes())?;
        f.write_all(&ts_usec.to_le_bytes())?;
        f.write_all(&incl_len.to_le_bytes())?;
        f.write_all(&orig_len.to_le_bytes())?;
        f.write_all(&data)?;

        Ok(())
    }

    /// Write raw bytes as a PCAP packet with current timestamp
    pub fn write_raw(&self, data: &[u8]) -> Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        use std::io::Write;
        let mut file = self.file.write();
        let Some(ref mut f) = *file else {
            return Err(Error::Storage("PCAP writer is enabled but not open".into()));
        };
        let now = (self.now)();
        let ts_sec = pcap_timestamp_seconds(now)?;
        let ts_usec = now.timestamp_subsec_micros();
        let len = pcap_record_len(data.len())?;

        f.write_all(&ts_sec.to_le_bytes())?;
        f.write_all(&ts_usec.to_le_bytes())?;
        f.write_all(&len.to_le_bytes())?;
        f.write_all(&len.to_le_bytes())?;
        f.write_all(data)?;

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

fn pcap_record_len(len: usize) -> Result<u32> {
    if len > MAX_PCAP_RECORD_BYTES {
        return Err(Error::Packet(format!(
            "PCAP record exceeds declared snaplen ({} > {} bytes)",
            len, MAX_PCAP_RECORD_BYTES
        )));
    }

    u32::try_from(len).map_err(|_| {
        Error::Packet(format!(
            "PCAP record exceeds length field limit ({} > {} bytes)",
            len,
            u32::MAX
        ))
    })
}

fn pcap_timestamp_seconds(timestamp: Timestamp) -> Result<u32> {
    let seconds = timestamp.timestamp();
    u32::try_from(seconds).map_err(|_| {
        Error::Packet(format!(
            "PCAP timestamp seconds {} cannot be represented in classic PCAP",
            seconds
        ))
    })
}

fn read_limited_pcap_bytes<R: Read>(reader: R, max_bytes: u64) -> std::io::Result<Option<Vec<u8>>> {
    let sentinel_limit = max_bytes.checked_add(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "PCAP read limit is too large",
        )
    })?;
    let mut limited = reader.take(sentinel_limit);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf)?;
    if buf.len() as u64 > max_bytes {
        Ok(None)
    } else {
        Ok(Some(buf))
    }
}

pub struct PcapReader {
    path: PathBuf,
}

/// Byte-swapped PCAP magic (big-endian capture on little-endian host or vice-versa)
const PCAP_MAGIC_SWAPPED: u32 = 0xd4c3b2a1;
/// Nanosecond-resolution PCAP magic
const PCAP_MAGIC_NANO: u32 = 0xa1b23c4d;
const PCAP_MAGIC_NANO_SWAPPED: u32 = 0x4d3cb2a1;

impl PcapReader {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Read a libpcap file and return all packets.
    /// Supports both little-endian and big-endian (byte-swapped) PCAP formats,
    /// and both microsecond and nanosecond timestamp resolution.
    pub fn read_file(&self) -> Result<Vec<Packet>> {
        let path = self.path.as_path();
        let root = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .ok_or_else(|| Error::Packet("PCAP path must point to a file".into()))?;
        let file = open_regular_file_beneath_root(root, Path::new(file_name))?;
        let file_len = file.metadata()?.len();
        if file_len > MAX_PCAP_READ_BYTES {
            return Err(Error::Packet(format!(
                "PCAP file exceeds read limit ({} > {} bytes)",
                file_len, MAX_PCAP_READ_BYTES
            )));
        }

        let Some(buf) = read_limited_pcap_bytes(file, MAX_PCAP_READ_BYTES)? else {
            return Err(Error::Packet(format!(
                "PCAP file exceeds read limit while reading (> {} bytes)",
                MAX_PCAP_READ_BYTES
            )));
        };

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
                )));
            }
        };

        let read_u32 = |data: &[u8], offset: usize| -> u32 {
            let raw = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            if swapped { raw.swap_bytes() } else { raw }
        };
        let read_u16 = |data: &[u8], offset: usize| -> u16 {
            let raw = u16::from_le_bytes([data[offset], data[offset + 1]]);
            if swapped { raw.swap_bytes() } else { raw }
        };

        // PCAP global header (24 bytes): magic 0..4, version_major 4..6,
        // version_minor 6..8, thiszone 8..12, sigfigs 12..16 are unused here;
        // only snaplen 16..20 and linktype 20..24 are needed.
        let version_major = read_u16(&buf, 4);
        let version_minor = read_u16(&buf, 6);
        if version_major != PCAP_VERSION_MAJOR || version_minor != PCAP_VERSION_MINOR {
            return Err(Error::Packet(format!(
                "unsupported PCAP version: {}.{}",
                version_major, version_minor
            )));
        }
        let snaplen = read_u32(&buf, 16) as usize;
        if snaplen > MAX_PCAP_RECORD_BYTES {
            return Err(Error::Packet(format!(
                "PCAP snaplen exceeds read limit ({} > {} bytes)",
                snaplen, MAX_PCAP_RECORD_BYTES
            )));
        }
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
            PCAP_LINKTYPE_ETHERNET => 14,
            PCAP_LINKTYPE_RAW | PCAP_LINKTYPE_IPV4 | PCAP_LINKTYPE_IPV6 => 0,
            PCAP_LINKTYPE_NULL | PCAP_LINKTYPE_LOOP => 4,
            PCAP_LINKTYPE_LINUX_SLL => 16,
            _ => {
                return Err(Error::Packet(format!(
                    "unsupported PCAP linktype: {}",
                    linktype
                )));
            }
        };

        let mut packets = Vec::new();
        let mut pos = 24; // skip global header
        let mut record_count = 0usize;

        while pos + 16 <= buf.len() {
            if record_count >= MAX_PCAP_RECORDS {
                return Err(Error::Packet(format!(
                    "PCAP file exceeds record limit (>{} records)",
                    MAX_PCAP_RECORDS
                )));
            }
            record_count += 1;

            // Packet record header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4)
            let ts_sec = read_u32(&buf, pos) as i64;
            let ts_frac = read_u32(&buf, pos + 4);
            let incl_len = read_u32(&buf, pos + 8) as usize;
            let orig_len = read_u32(&buf, pos + 12) as usize;
            pos += 16;

            let Some(packet_end) = pos.checked_add(incl_len) else {
                return Err(Error::Packet(format!(
                    "PCAP packet length overflows at offset {}",
                    pos
                )));
            };
            if incl_len > snaplen {
                return Err(Error::Packet(format!(
                    "PCAP packet length exceeds snaplen at offset {} ({} > {})",
                    pos, incl_len, snaplen
                )));
            }
            if orig_len < incl_len {
                return Err(Error::Packet(format!(
                    "PCAP original length is smaller than captured length at offset {} ({} < {})",
                    pos, orig_len, incl_len
                )));
            }
            if packet_end > buf.len() {
                return Err(Error::Packet(format!(
                    "PCAP packet is truncated at offset {}",
                    pos
                )));
            }

            let pkt_data = &buf[pos..packet_end];
            pos = packet_end;

            let ts_nsec = if nano {
                if ts_frac >= 1_000_000_000 {
                    return Err(Error::Packet(format!(
                        "PCAP nanosecond timestamp fraction is out of range at offset {} ({})",
                        pos, ts_frac
                    )));
                }
                ts_frac
            } else {
                if ts_frac >= 1_000_000 {
                    return Err(Error::Packet(format!(
                        "PCAP microsecond timestamp fraction is out of range at offset {} ({})",
                        pos, ts_frac
                    )));
                }
                ts_frac * 1000
            };
            let timestamp =
                chrono::DateTime::from_timestamp(ts_sec, ts_nsec).unwrap_or_else(|| {
                    tracing::warn!(
                        "PCAP: invalid timestamp (sec={}, nsec={}), using epoch",
                        ts_sec,
                        ts_nsec,
                    );
                    chrono::DateTime::UNIX_EPOCH
                });

            if let Some(pkt) =
                Self::parse_link_packet(pkt_data, linktype, link_header_len, timestamp, orig_len)
            {
                packets.push(pkt);
            }
        }
        if pos != buf.len() {
            return Err(Error::Packet(format!(
                "PCAP truncated record header at offset {}",
                pos
            )));
        }

        tracing::info!(
            "PCAP: read {} packets from {}",
            packets.len(),
            self.path.display()
        );
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

        let mut vlan_tag = None;
        let ip_data = match linktype {
            PCAP_LINKTYPE_ETHERNET => {
                if data.len() < 14 {
                    return None;
                }
                let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
                let mut offset = 14;
                const MAX_VLAN_DEPTH: usize = 8;
                let mut vlan_depth = 0;
                while ethertype == 0x8100 || ethertype == 0x88A8 {
                    vlan_depth += 1;
                    if vlan_depth > MAX_VLAN_DEPTH || data.len() < offset + 4 {
                        return None;
                    }
                    vlan_tag.get_or_insert(
                        u16::from_be_bytes([data[offset], data[offset + 1]]) & 0x0fff,
                    );
                    ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                    offset += 4;
                }
                match ethertype {
                    0x0800 | 0x86DD => &data[offset..],
                    _ => return None,
                }
            }
            PCAP_LINKTYPE_NULL | PCAP_LINKTYPE_LOOP => {
                // BSD null/loop: 4-byte family header
                if data.len() < 4 {
                    return None;
                }
                if !bsd_loopback_family_is_ip(&data[..4]) {
                    return None;
                }
                &data[4..]
            }
            PCAP_LINKTYPE_LINUX_SLL => {
                // Linux SLL: 16-byte header
                if data.len() < 16 {
                    return None;
                }
                let protocol = u16::from_be_bytes([data[14], data[15]]);
                if !matches!(protocol, 0x0800 | 0x86DD) {
                    return None;
                }
                &data[16..]
            }
            PCAP_LINKTYPE_RAW | PCAP_LINKTYPE_IPV4 | PCAP_LINKTYPE_IPV6 => data,
            _ => return None,
        };

        if ip_data.is_empty() {
            return None;
        }

        let version = match linktype {
            PCAP_LINKTYPE_IPV4 => 4,
            PCAP_LINKTYPE_IPV6 => 6,
            _ => (ip_data[0] >> 4) & 0x0F,
        };
        match version {
            4 => Self::parse_ipv4_packet(ip_data, timestamp, orig_len)
                .map(|packet| Self::apply_vlan_tag(packet, vlan_tag)),
            6 => Self::parse_ipv6_packet(ip_data, timestamp, orig_len)
                .map(|packet| Self::apply_vlan_tag(packet, vlan_tag)),
            _ => None,
        }
    }

    fn apply_vlan_tag(mut packet: Packet, vlan_tag: Option<u16>) -> Packet {
        if let Some(tag) = vlan_tag {
            packet = packet.with_vlan(tag);
        }
        packet
    }

    fn parse_ipv4_packet(
        data: &[u8],
        timestamp: chrono::DateTime<chrono::Utc>,
        orig_len: usize,
    ) -> Option<Packet> {
        if data.len() < 20 {
            return None;
        }
        if data[0] >> 4 != 4 {
            return None;
        }

        let ihl = (data[0] & 0x0F) as usize * 4;
        if ihl < 20 || data.len() < ihl {
            return None;
        }
        let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if total_len < ihl || total_len > data.len() {
            return None;
        }
        let fragment = u16::from_be_bytes([data[6], data[7]]);
        if fragment & 0x3fff != 0 {
            return None;
        }
        let packet_data = &data[..total_len];

        let protocol = packet_data[9];
        let src_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            packet_data[12],
            packet_data[13],
            packet_data[14],
            packet_data[15],
        ));
        let dst_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            packet_data[16],
            packet_data[17],
            packet_data[18],
            packet_data[19],
        ));

        Self::parse_transport(
            packet_data,
            ihl,
            protocol,
            src_ip,
            dst_ip,
            timestamp,
            orig_len,
        )
    }

    fn parse_ipv6_packet(
        data: &[u8],
        timestamp: chrono::DateTime<chrono::Utc>,
        orig_len: usize,
    ) -> Option<Packet> {
        if data.len() < 40 {
            return None;
        }
        if data[0] >> 4 != 6 {
            return None;
        }

        let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        let total_len = 40usize.checked_add(payload_len)?;
        if total_len > data.len() {
            return None;
        }
        let packet_data = &data[..total_len];

        let src_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from([
            packet_data[8],
            packet_data[9],
            packet_data[10],
            packet_data[11],
            packet_data[12],
            packet_data[13],
            packet_data[14],
            packet_data[15],
            packet_data[16],
            packet_data[17],
            packet_data[18],
            packet_data[19],
            packet_data[20],
            packet_data[21],
            packet_data[22],
            packet_data[23],
        ]));
        let dst_ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from([
            packet_data[24],
            packet_data[25],
            packet_data[26],
            packet_data[27],
            packet_data[28],
            packet_data[29],
            packet_data[30],
            packet_data[31],
            packet_data[32],
            packet_data[33],
            packet_data[34],
            packet_data[35],
            packet_data[36],
            packet_data[37],
            packet_data[38],
            packet_data[39],
        ]));
        let (protocol, transport_offset) = Self::ipv6_transport_start(packet_data)?;

        Self::parse_transport(
            packet_data,
            transport_offset,
            protocol,
            src_ip,
            dst_ip,
            timestamp,
            orig_len,
        )
    }

    fn ipv6_transport_start(data: &[u8]) -> Option<(u8, usize)> {
        let mut protocol = data[6];
        let mut offset = 40usize;

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
                let header_end = transport_offset.checked_add(20)?;
                if data.len() < header_end {
                    return None;
                }
                let tcp_hdr_len = ((data[transport_offset + 12] >> 4) as usize) * 4;
                if !(20..=60).contains(&tcp_hdr_len) {
                    return None;
                }
                let payload_start = transport_offset.checked_add(tcp_hdr_len)?;
                if data.len() < payload_start {
                    return None;
                }

                let src_port =
                    u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
                let dst_port =
                    u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);
                let flags = TcpFlags::from_bits_truncate_value(data[transport_offset + 13]);
                let direction = infer_tcp_direction(&src_ip, &dst_ip, flags);

                let mut pkt = Packet::new(
                    FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Tcp),
                    direction,
                    bytes::Bytes::copy_from_slice(&data[payload_start..]),
                )
                .with_tcp_flags(flags);
                pkt.timestamp = timestamp;
                pkt.length = orig_len;
                Some(pkt)
            }
            17 => {
                // UDP
                let header_end = transport_offset.checked_add(8)?;
                if data.len() < header_end {
                    return None;
                }
                let src_port =
                    u16::from_be_bytes([data[transport_offset], data[transport_offset + 1]]);
                let dst_port =
                    u16::from_be_bytes([data[transport_offset + 2], data[transport_offset + 3]]);
                let udp_len =
                    u16::from_be_bytes([data[transport_offset + 4], data[transport_offset + 5]])
                        as usize;
                let payload_end = transport_offset.checked_add(udp_len)?;
                if udp_len < 8 || payload_end > data.len() {
                    return None;
                }
                let payload_start = transport_offset.checked_add(8)?;
                let direction = infer_direction(&src_ip, &dst_ip);

                let mut pkt = Packet::new(
                    FiveTuple::new(src_ip, dst_ip, src_port, dst_port, Protocol::Udp),
                    direction,
                    bytes::Bytes::copy_from_slice(&data[payload_start..payload_end]),
                );
                pkt.timestamp = timestamp;
                pkt.length = orig_len;
                Some(pkt)
            }
            1 | 58 => {
                let payload_start = transport_offset.checked_add(8)?;
                if data.len() < payload_start {
                    return None;
                }
                let direction = infer_direction(&src_ip, &dst_ip);
                let mut pkt = Packet::new(
                    FiveTuple::new(src_ip, dst_ip, 0, 0, Protocol::Icmp),
                    direction,
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

fn bsd_loopback_family_is_ip(header: &[u8]) -> bool {
    matches!(
        header,
        [2, 0, 0, 0]
            | [0, 0, 0, 2]
            | [24, 0, 0, 0]
            | [0, 0, 0, 24]
            | [28, 0, 0, 0]
            | [0, 0, 0, 28]
            | [30, 0, 0, 0]
            | [0, 0, 0, 30]
    )
}

fn infer_tcp_direction(
    src_ip: &std::net::IpAddr,
    dst_ip: &std::net::IpAddr,
    flags: TcpFlags,
) -> PacketDirection {
    if flags.contains(TcpFlags::SYN) && !flags.contains(TcpFlags::ACK) {
        return PacketDirection::Outbound;
    }
    if flags.contains(TcpFlags::SYN) && flags.contains(TcpFlags::ACK) {
        return PacketDirection::Inbound;
    }

    infer_direction(src_ip, dst_ip)
}

fn infer_direction(src_ip: &std::net::IpAddr, dst_ip: &std::net::IpAddr) -> PacketDirection {
    let src_local = is_local_address(src_ip);
    let dst_local = is_local_address(dst_ip);

    match (src_local, dst_local) {
        (true, false) => PacketDirection::Outbound,
        (false, true) => PacketDirection::Inbound,
        _ => PacketDirection::Unknown,
    }
}

fn is_local_address(ip: &std::net::IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }

    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return mapped.is_private() || mapped.is_link_local() || mapped.is_loopback();
            }
            let octets = v6.octets();
            (octets[0] & 0xFE) == 0xFC || (octets[0] == 0xFE && (octets[1] & 0xC0) == 0x80)
        }
    }
}

#[cfg(test)]
#[path = "pcap_tests.rs"]
mod tests;
