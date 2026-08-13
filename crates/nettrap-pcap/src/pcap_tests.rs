use super::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn timestamp() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

fn vlan_ethernet_header(vlan_tag: u16, inner_ethertype: u16) -> Vec<u8> {
    let mut frame = vec![0xaa; 6];
    frame.extend_from_slice(&[0xbb; 6]);
    frame.extend_from_slice(&0x8100u16.to_be_bytes());
    frame.extend_from_slice(&(vlan_tag & 0x0fff).to_be_bytes());
    frame.extend_from_slice(&inner_ethertype.to_be_bytes());
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

fn read_temp_pcap(bytes: &[u8], name: &str) -> Result<Vec<Packet>> {
    let path = std::env::temp_dir().join(format!(
        "nettrap-{name}-{}-{}.pcap",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::write(&path, bytes).expect("write pcap");
    let result = PcapReader::new(&path).read_file();
    let _ = std::fs::remove_file(path);
    result
}

fn pcap_with_record(incl_len: u32, orig_len: u32, payload: &[u8], snaplen: u32) -> Vec<u8> {
    pcap_with_record_and_timestamp_and_linktype(
        incl_len,
        orig_len,
        payload,
        snaplen,
        PCAP_MAGIC,
        (0, 0),
        PCAP_LINKTYPE_RAW,
    )
}

fn pcap_with_record_and_timestamp(
    incl_len: u32,
    orig_len: u32,
    payload: &[u8],
    snaplen: u32,
    magic: u32,
    ts_sec: u32,
    ts_frac: u32,
) -> Vec<u8> {
    pcap_with_record_and_timestamp_and_linktype(
        incl_len,
        orig_len,
        payload,
        snaplen,
        magic,
        (ts_sec, ts_frac),
        PCAP_LINKTYPE_RAW,
    )
}

fn pcap_with_record_and_timestamp_and_linktype(
    incl_len: u32,
    orig_len: u32,
    payload: &[u8],
    snaplen: u32,
    magic: u32,
    timestamp: (u32, u32),
    linktype: u32,
) -> Vec<u8> {
    let (ts_sec, ts_frac) = timestamp;
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&magic.to_le_bytes());
    pcap.extend_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
    pcap.extend_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
    pcap.extend_from_slice(&PCAP_THISZONE.to_le_bytes());
    pcap.extend_from_slice(&PCAP_SIGFIGS.to_le_bytes());
    pcap.extend_from_slice(&snaplen.to_le_bytes());
    pcap.extend_from_slice(&linktype.to_le_bytes());
    pcap.extend_from_slice(&ts_sec.to_le_bytes());
    pcap.extend_from_slice(&ts_frac.to_le_bytes());
    pcap.extend_from_slice(&incl_len.to_le_bytes());
    pcap.extend_from_slice(&orig_len.to_le_bytes());
    pcap.extend_from_slice(payload);
    pcap
}

#[test]
fn ipv4_udp_payload_ignores_padding_after_declared_lengths() {
    let mut data = vec![
        0x45, 0x00, 0x00, 0x20, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 8, 8, 8, 8, 0x30, 0x39,
        0x00, 0x35, 0x00, 0x0c, 0, 0, b't', b'e', b's', b't',
    ];
    data.extend_from_slice(b"padding");

    let packet =
        PcapReader::parse_ipv4_packet(&data, timestamp(), data.len()).expect("packet should parse");

    assert_eq!(packet.five_tuple.protocol, Protocol::Udp);
    assert_eq!(packet.payload.as_ref(), b"test");
}

#[test]
fn ethernet_vlan_tag_is_preserved_on_parsed_packet() {
    let udp_payload = b"abc";
    let udp_len = 8 + udp_payload.len();
    let ip_total_len = 20 + udp_len;
    let mut frame = vlan_ethernet_header(37, 0x0800);
    frame.extend_from_slice(&ipv4_header(ip_total_len, 17));
    frame.extend_from_slice(&udp_header(1234, 53, udp_len));
    frame.extend_from_slice(udp_payload);

    let packet = PcapReader::parse_link_packet(&frame, 1, 14, timestamp(), frame.len())
        .expect("packet should parse");

    assert_eq!(packet.vlan_tag, Some(37));
    assert_eq!(packet.payload.as_ref(), udp_payload);
}

#[test]
fn linux_sll_rejects_non_ip_protocol_even_when_payload_looks_like_ipv4() {
    let mut frame = vec![0u8; 16];
    frame[14..16].copy_from_slice(&0x0806u16.to_be_bytes());
    frame.extend_from_slice(&ipv4_header(20, 1));

    assert!(PcapReader::parse_link_packet(&frame, 113, 16, timestamp(), frame.len()).is_none());
}

#[test]
fn bsd_loopback_rejects_non_ip_family_even_when_payload_looks_like_ipv4() {
    let mut frame = 1u32.to_ne_bytes().to_vec();
    frame.extend_from_slice(&ipv4_header(20, 1));

    assert!(PcapReader::parse_link_packet(&frame, 12, 4, timestamp(), frame.len()).is_none());
}

#[test]
fn bsd_loopback_accepts_ipv4_family() {
    let mut frame = 2u32.to_ne_bytes().to_vec();
    frame.extend_from_slice(&ipv4_header(28, 1));
    frame.extend_from_slice(&[8, 0, 0, 0, 0, 0, 0, 0]);

    let packet = PcapReader::parse_link_packet(&frame, 12, 4, timestamp(), frame.len())
        .expect("IPv4 loopback frame should parse");

    assert_eq!(packet.five_tuple.protocol, Protocol::Icmp);
}

#[test]
fn ipv4_udp_rejects_length_beyond_ip_payload() {
    let data = [
        0x45, 0x00, 0x00, 0x20, 0, 0, 0, 0, 64, 17, 0, 0, 127, 0, 0, 1, 8, 8, 8, 8, 0x30, 0x39,
        0x00, 0x35, 0x00, 0x10, 0, 0, b't', b'e', b's', b't',
    ];

    assert!(PcapReader::parse_ipv4_packet(&data, timestamp(), data.len()).is_none());
}

#[test]
fn ipv4_parser_rejects_non_ipv4_version() {
    let mut data = ipv4_header(28, 17);
    data[0] = 0x65;
    data.extend_from_slice(&udp_header(1234, 53, 8));

    assert!(PcapReader::parse_ipv4_packet(&data, timestamp(), data.len()).is_none());
}

#[test]
fn ipv4_rejects_fragmented_packets_before_transport_parsing() {
    let mut data = ipv4_header(28, 17);
    data[6..8].copy_from_slice(&0x2001u16.to_be_bytes());
    data.extend_from_slice(&udp_header(1234, 53, 8));

    assert!(PcapReader::parse_ipv4_packet(&data, timestamp(), data.len()).is_none());
}

#[test]
fn parse_transport_rejects_unrepresentable_offset_without_panicking() {
    for protocol in [1, 6, 17] {
        assert!(
            PcapReader::parse_transport(
                &[],
                usize::MAX,
                protocol,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                timestamp(),
                0,
            )
            .is_none()
        );
    }
}

#[test]
fn ipv4_tcp_payload_ignores_padding_after_total_length() {
    let mut data = vec![
        0x45, 0x00, 0x00, 0x2b, 0, 0, 0, 0, 64, 6, 0, 0, 192, 168, 1, 10, 93, 184, 216, 34, 0x1f,
        0x90, 0x00, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x18, 0x20, 0x00, 0, 0, 0, 0, b'a', b'b',
        b'c',
    ];
    data.extend_from_slice(b"padding");

    let packet =
        PcapReader::parse_ipv4_packet(&data, timestamp(), data.len()).expect("packet should parse");

    assert_eq!(packet.five_tuple.protocol, Protocol::Tcp);
    assert_eq!(packet.payload.as_ref(), b"abc");
}

#[test]
fn ipv6_udp_payload_ignores_padding_after_payload_length() {
    let mut data = vec![0x60, 0, 0, 0, 0x00, 0x0c, 17, 64];
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&[0u8; 15]);
    data.push(1);
    data.extend_from_slice(&[
        0x30, 0x39, 0x00, 0x35, 0x00, 0x0c, 0, 0, b't', b'e', b's', b't',
    ]);
    data.extend_from_slice(b"padding");

    let packet =
        PcapReader::parse_ipv6_packet(&data, timestamp(), data.len()).expect("packet should parse");

    assert_eq!(packet.five_tuple.protocol, Protocol::Udp);
    assert_eq!(packet.payload.as_ref(), b"test");
}

#[test]
fn ipv6_udp_after_hop_by_hop_extension_parses() {
    let mut data = vec![0x60, 0, 0, 0, 0x00, 0x14, 0, 64];
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&[0u8; 15]);
    data.push(1);
    data.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
    data.extend_from_slice(&[
        0x30, 0x39, 0x00, 0x35, 0x00, 0x0c, 0, 0, b't', b'e', b's', b't',
    ]);

    let packet =
        PcapReader::parse_ipv6_packet(&data, timestamp(), data.len()).expect("packet should parse");

    assert_eq!(packet.five_tuple.protocol, Protocol::Udp);
    assert_eq!(packet.payload.as_ref(), b"test");
}

#[test]
fn ipv6_fragmented_udp_is_not_parsed_without_reassembly() {
    let mut data = vec![0x60, 0, 0, 0, 0x00, 0x14, 44, 64];
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&[0u8; 15]);
    data.push(1);
    data.extend_from_slice(&[17, 0, 0, 1, 0, 0, 0, 1]);
    data.extend_from_slice(&[
        0x30, 0x39, 0x00, 0x35, 0x00, 0x0c, 0, 0, b't', b'e', b's', b't',
    ]);

    assert!(PcapReader::parse_ipv6_packet(&data, timestamp(), data.len()).is_none());
}

#[test]
fn ipv6_parser_rejects_non_ipv6_version() {
    let mut data = vec![0x40, 0, 0, 0, 0x00, 0x08, 17, 64];
    data.extend_from_slice(&[0u8; 32]);
    data.extend_from_slice(&udp_header(1234, 53, 8));

    assert!(PcapReader::parse_ipv6_packet(&data, timestamp(), data.len()).is_none());
}

#[test]
fn ipv4_icmp_rejects_truncated_header() {
    let data = [
        0x45, 0x00, 0x00, 0x18, 0, 0, 0, 0, 64, 1, 0, 0, 127, 0, 0, 1, 8, 8, 8, 8, 8, 0, 0, 0,
    ];

    assert!(PcapReader::parse_ipv4_packet(&data, timestamp(), data.len()).is_none());
}

#[test]
fn ipv6_icmp_rejects_truncated_header() {
    let mut data = vec![0x60, 0, 0, 0, 0x00, 0x04, 58, 64];
    data.extend_from_slice(&[0u8; 16]);
    data.extend_from_slice(&[0u8; 15]);
    data.push(1);
    data.extend_from_slice(&[128, 0, 0, 0]);

    assert!(PcapReader::parse_ipv6_packet(&data, timestamp(), data.len()).is_none());
}

#[test]
fn read_file_rejects_oversized_pcap_before_loading() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-pcap-oversized-{}-{}.pcap",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let file = File::create(&path).expect("create sparse pcap");
    file.set_len(MAX_PCAP_READ_BYTES + 1)
        .expect("extend sparse pcap");

    let err = PcapReader::new(&path)
        .read_file()
        .expect_err("oversized pcap should be rejected");

    assert!(err.to_string().contains("exceeds read limit"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn read_limited_pcap_bytes_rejects_unrepresentable_sentinel_limit() {
    let err = read_limited_pcap_bytes(std::io::empty(), u64::MAX)
        .expect_err("overflowing sentinel limit should fail");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("read limit is too large"));
}

#[test]
fn read_file_rejects_too_many_records_before_parsing_payloads() {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&PCAP_MAGIC.to_le_bytes());
    pcap.extend_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
    pcap.extend_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
    pcap.extend_from_slice(&PCAP_THISZONE.to_le_bytes());
    pcap.extend_from_slice(&PCAP_SIGFIGS.to_le_bytes());
    pcap.extend_from_slice(&PCAP_SNAPLEN.to_le_bytes());
    pcap.extend_from_slice(&PCAP_LINKTYPE_RAW.to_le_bytes());
    for _ in 0..=MAX_PCAP_RECORDS {
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
    }

    let err =
        read_temp_pcap(&pcap, "pcap-too-many-records").expect_err("record floods should fail");

    assert!(err.to_string().contains("exceeds record limit"));
}

#[test]
fn read_file_rejects_record_with_original_length_smaller_than_capture_length() {
    let payload = ipv4_header(20, 1);
    let pcap = pcap_with_record(payload.len() as u32, 1, &payload, PCAP_SNAPLEN);

    let err = read_temp_pcap(&pcap, "pcap-bad-orig-len")
        .expect_err("contradictory record lengths should fail");

    assert!(err.to_string().contains("original length is smaller"));
}

#[test]
fn read_file_rejects_record_larger_than_capture_snaplen() {
    let payload = ipv4_header(20, 1);
    let pcap = pcap_with_record(payload.len() as u32, payload.len() as u32, &payload, 1);

    let err = read_temp_pcap(&pcap, "pcap-bad-snaplen")
        .expect_err("records larger than snaplen should fail");

    assert!(err.to_string().contains("exceeds snaplen"));
}

#[test]
fn read_file_rejects_unsupported_pcap_version() {
    let payload = ipv4_header(20, 1);
    let mut pcap = pcap_with_record(
        payload.len() as u32,
        payload.len() as u32,
        &payload,
        PCAP_SNAPLEN,
    );
    pcap[4..6].copy_from_slice(&3u16.to_le_bytes());

    let err = read_temp_pcap(&pcap, "pcap-bad-version")
        .expect_err("unsupported PCAP versions should fail");

    assert!(err.to_string().contains("unsupported PCAP version"));
}

#[test]
fn read_file_rejects_declared_snaplen_above_reader_limit() {
    let payload = ipv4_header(20, 1);
    let pcap = pcap_with_record(
        payload.len() as u32,
        payload.len() as u32,
        &payload,
        PCAP_SNAPLEN + 1,
    );

    let err = read_temp_pcap(&pcap, "pcap-huge-snaplen")
        .expect_err("oversized snaplen should fail before record parsing");

    assert!(err.to_string().contains("snaplen exceeds read limit"));
}

#[test]
fn read_file_rejects_trailing_partial_record_header() {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&PCAP_MAGIC.to_le_bytes());
    pcap.extend_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
    pcap.extend_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
    pcap.extend_from_slice(&PCAP_THISZONE.to_le_bytes());
    pcap.extend_from_slice(&PCAP_SIGFIGS.to_le_bytes());
    pcap.extend_from_slice(&PCAP_SNAPLEN.to_le_bytes());
    pcap.extend_from_slice(&PCAP_LINKTYPE_RAW.to_le_bytes());
    pcap.extend_from_slice(&[0; 4]);

    let err = read_temp_pcap(&pcap, "pcap-partial-record")
        .expect_err("partial trailing record header should fail");

    assert!(err.to_string().contains("truncated record header"));
}

#[test]
fn read_file_rejects_unknown_linktype_instead_of_assuming_raw_ip() {
    let payload = ipv4_header(20, 1);
    let pcap = pcap_with_record_and_timestamp_and_linktype(
        payload.len() as u32,
        payload.len() as u32,
        &payload,
        PCAP_SNAPLEN,
        PCAP_MAGIC,
        (0, 0),
        999,
    );

    let err = read_temp_pcap(&pcap, "pcap-unknown-linktype")
        .expect_err("unknown linktype should fail closed");

    assert!(err.to_string().contains("unsupported PCAP linktype"));
}

#[test]
fn read_file_rejects_microsecond_timestamp_fraction_out_of_range() {
    let payload = ipv4_header(20, 1);
    let pcap = pcap_with_record_and_timestamp(
        payload.len() as u32,
        payload.len() as u32,
        &payload,
        PCAP_SNAPLEN,
        PCAP_MAGIC,
        0,
        1_000_000,
    );

    let err = read_temp_pcap(&pcap, "pcap-bad-usec")
        .expect_err("out-of-range microsecond timestamp should fail");

    assert!(err.to_string().contains("microsecond timestamp fraction"));
}

#[test]
fn read_file_rejects_nanosecond_timestamp_fraction_out_of_range() {
    let payload = ipv4_header(20, 1);
    let pcap = pcap_with_record_and_timestamp(
        payload.len() as u32,
        payload.len() as u32,
        &payload,
        PCAP_SNAPLEN,
        PCAP_MAGIC_NANO,
        0,
        1_000_000_000,
    );

    let err = read_temp_pcap(&pcap, "pcap-bad-nsec")
        .expect_err("out-of-range nanosecond timestamp should fail");

    assert!(err.to_string().contains("nanosecond timestamp fraction"));
}

#[test]
fn read_file_loads_relative_regular_file() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-pcap-relative-{}-{}.pcapdir",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    let _cwd_lock = crate::test_util::lock_current_dir();
    let previous_dir = std::env::current_dir().expect("current dir");
    std::env::set_current_dir(&root).expect("switch to temp root");
    std::fs::write("capture.pcap", b"not a pcap").expect("write capture");

    let err = PcapReader::new("capture.pcap")
        .read_file()
        .expect_err("relative capture should be read or rejected as a real file");

    std::env::set_current_dir(previous_dir).expect("restore current dir");
    assert!(matches!(err, Error::Packet(_)));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn read_file_accepts_non_utf8_input_path() {
    use std::os::unix::ffi::OsStringExt;

    let root = std::env::temp_dir().join(format!("nettrap-pcap-nonutf8-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("create temp root");
    let path = root.join(std::ffi::OsString::from_vec(b"capture-\xff.pcap".to_vec()));
    std::fs::write(&path, b"not a pcap").expect("write capture");

    let err = PcapReader::new(&path)
        .read_file()
        .expect_err("non-UTF8 input path should be preserved and opened");

    assert!(matches!(err, Error::Packet(_)));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn read_file_rejects_symlinked_parent_directory() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-pcap-parent-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let real_parent = root.join("real");
    let linked_parent = root.join("linked");
    std::fs::create_dir_all(&real_parent).expect("create real parent");
    std::fs::write(real_parent.join("capture.pcap"), b"not a pcap").expect("write capture");
    std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");

    let err = PcapReader::new(linked_parent.join("capture.pcap"))
        .read_file()
        .expect_err("symlinked parent should be rejected");

    assert!(matches!(err, Error::Io(ref io) if io.kind() == std::io::ErrorKind::InvalidInput));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn writer_rejects_symlinked_parent_directory() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-pcap-writer-parent-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let real_parent = root.join("real");
    let linked_parent = root.join("linked");
    std::fs::create_dir_all(&real_parent).expect("create real parent");
    std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("create symlink parent");

    let writer = PcapWriter::new(linked_parent.join("capture.pcap")).expect("valid pcap path");
    let err = writer
        .open()
        .expect_err("symlinked parent should be rejected");

    assert!(err.to_string().contains("symlink"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn writer_encodes_payload_as_raw_ipv4_udp_packet() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-pcap-write-{}-{}.pcap",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let writer = PcapWriter::new(&path).expect("valid pcap path");
    writer.open().expect("pcap writer should open");

    let packet = Packet::new(
        FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            12345,
            53,
            Protocol::Udp,
        ),
        PacketDirection::Outbound,
        bytes::Bytes::from_static(b"test"),
    );
    writer
        .write_packet(&packet)
        .expect("packet should be encoded");
    writer.close().expect("pcap writer should close");

    let bytes = std::fs::read(&path).expect("pcap should be readable");
    let record = &bytes[24 + 16..];
    assert_eq!(record[0] >> 4, 4);
    assert_eq!(record[9], 17);
    assert_eq!(u16::from_be_bytes([record[20], record[21]]), 12345);
    assert_eq!(u16::from_be_bytes([record[22], record[23]]), 53);
    assert_eq!(&record[28..], b"test");

    let packets = PcapReader::new(&path)
        .read_file()
        .expect("writer output should parse");
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].payload.as_ref(), b"test");
    assert_eq!(packets[0].direction, PacketDirection::Outbound);

    let encoded = encode_ip_packet(&packet).expect("encode_ip_packet");
    assert_eq!(encoded.as_slice(), record);

    let _ = std::fs::remove_file(path);
}

#[test]
fn infer_direction_treats_ipv4_mapped_loopback_as_local() {
    let src = std::net::IpAddr::V6(std::net::Ipv6Addr::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1,
    ]));
    let dst = std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));

    assert_eq!(infer_direction(&src, &dst), PacketDirection::Outbound);
    assert_eq!(infer_direction(&dst, &src), PacketDirection::Inbound);
}

#[test]
fn infer_tcp_direction_uses_handshake_flags_before_port_heuristics() {
    let local = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
    let flags = TcpFlags::SYN;
    let syn_ack = TcpFlags::SYN | TcpFlags::ACK;

    assert_eq!(
        infer_tcp_direction(&local, &local, flags),
        PacketDirection::Outbound
    );
    assert_eq!(
        infer_tcp_direction(&local, &local, syn_ack),
        PacketDirection::Inbound
    );
}

#[test]
fn writer_accepts_simple_relative_path() {
    let _cwd_lock = crate::test_util::lock_current_dir();
    let path = format!(
        "nettrap-pcap-write-{}-{}.pcap",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let writer = PcapWriter::new(&path).expect("valid pcap path");

    writer.open().expect("pcap writer should open");
    writer.close().expect("pcap writer should close");

    assert!(
        std::path::Path::new(&path).is_file(),
        "pcap writer should create {path}"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn new_rejects_empty_pcap_path() {
    let err = match PcapWriter::new(std::path::PathBuf::new()) {
        Ok(_) => panic!("empty pcap path should fail"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("must not be empty"));
}

#[test]
fn writer_uses_the_injected_clock_for_raw_packet_timestamps() {
    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_704_067_200, 123_456_000).expect("valid instant")
    }

    let path = std::env::temp_dir().join(format!(
        "nettrap-pcap-raw-now-{}-{}.pcap",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let writer = PcapWriter::new(&path)
        .expect("valid pcap path")
        .with_now(fixed_now);
    writer.open().expect("pcap writer should open");
    writer.write_raw(b"raw").expect("raw packet should write");
    writer.close().expect("pcap writer should close");

    let bytes = std::fs::read(&path).expect("pcap should be readable");
    let record = &bytes[24..24 + 16];
    assert_eq!(
        u32::from_le_bytes(record[0..4].try_into().expect("ts_sec")),
        1_704_067_200
    );
    assert_eq!(
        u32::from_le_bytes(record[4..8].try_into().expect("ts_usec")),
        123_456
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn enabled_writer_rejects_packet_write_without_open_file() {
    let writer = PcapWriter::new("not-created.pcap").expect("valid pcap path");
    writer.enable();
    let packet = Packet::new(
        FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            12345,
            53,
            Protocol::Udp,
        ),
        PacketDirection::Outbound,
        bytes::Bytes::from_static(b"test"),
    );

    let err = writer
        .write_packet(&packet)
        .expect_err("enabled writer without file should fail");

    assert!(err.to_string().contains("enabled but not open"));
}

#[test]
fn enabled_writer_rejects_raw_write_without_open_file() {
    let writer = PcapWriter::new("not-created.pcap").expect("valid pcap path");
    writer.enable();

    let err = writer
        .write_raw(b"test")
        .expect_err("enabled writer without file should fail");

    assert!(err.to_string().contains("enabled but not open"));
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn writer_accepts_non_utf8_output_path() {
    use std::os::unix::ffi::OsStringExt;

    let root = std::env::temp_dir().join(format!(
        "nettrap-pcap-writer-nonutf8-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    let path = root.join(std::ffi::OsString::from_vec(b"capture-\xff.pcap".to_vec()));

    let writer = PcapWriter::new(&path).expect("valid pcap path");
    writer.open().expect("pcap writer should open");
    writer.close().expect("pcap writer should close");

    assert!(path.is_file());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn pcap_record_len_rejects_values_larger_than_declared_snaplen() {
    assert_eq!(
        pcap_record_len(MAX_PCAP_RECORD_BYTES).expect("maximum snaplen record should fit"),
        PCAP_SNAPLEN
    );

    let err = pcap_record_len(MAX_PCAP_RECORD_BYTES + 1)
        .expect_err("record larger than declared snaplen should fail");

    assert!(err.to_string().contains("exceeds declared snaplen"));
}

#[test]
fn writer_rejects_raw_payload_larger_than_declared_snaplen() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-pcap-raw-oversized-{}-{}.pcap",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let writer = PcapWriter::new(&path).expect("valid pcap path");
    writer.open().expect("pcap writer should open");
    let oversized = vec![0u8; MAX_PCAP_RECORD_BYTES + 1];

    let err = writer
        .write_raw(&oversized)
        .expect_err("raw payload larger than snaplen should fail");

    assert!(err.to_string().contains("exceeds declared snaplen"));
    writer.close().expect("pcap writer should close");
    let _ = std::fs::remove_file(path);
}

#[test]
fn pcap_timestamp_seconds_rejects_values_outside_classic_pcap_range() {
    use chrono::TimeZone;

    let max = chrono::Utc
        .timestamp_opt(i64::from(u32::MAX), 0)
        .single()
        .expect("maximum classic PCAP timestamp should be representable by chrono");
    assert_eq!(pcap_timestamp_seconds(max).unwrap(), u32::MAX);

    let before_epoch = chrono::Utc
        .timestamp_opt(-1, 0)
        .single()
        .expect("negative timestamp should be representable by chrono");
    let err =
        pcap_timestamp_seconds(before_epoch).expect_err("negative PCAP timestamp should fail");
    assert!(err.to_string().contains("cannot be represented"));

    let after_max = chrono::Utc
        .timestamp_opt(i64::from(u32::MAX) + 1, 0)
        .single()
        .expect("post-range timestamp should be representable by chrono");
    let err = pcap_timestamp_seconds(after_max).expect_err("oversized PCAP timestamp should fail");
    assert!(err.to_string().contains("cannot be represented"));
}

#[test]
fn read_limited_pcap_bytes_rejects_reader_past_limit() {
    let data = std::io::Cursor::new(vec![0u8; 5]);

    let result = read_limited_pcap_bytes(data, 4).expect("limited read should complete");

    assert!(result.is_none());
}

#[test]
fn encode_ip_packet_builds_ipv4_tcp_with_checksums() {
    let packet = Packet::new(
        FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            4444,
            80,
            Protocol::Tcp,
        ),
        PacketDirection::Outbound,
        bytes::Bytes::from_static(b"GET / HTTP/1.0\r\n\r\n"),
    );
    let ip = encode_ip_packet(&packet).expect("tcp encode");
    assert_eq!(ip[0] >> 4, 4, "IPv4 version");
    assert_eq!(ip[9], 6, "IP protocol = TCP");
    assert_eq!(u16::from_be_bytes([ip[2], ip[3]]) as usize, ip.len());
    assert_eq!(u16::from_be_bytes([ip[20], ip[21]]), 4444);
    assert_eq!(u16::from_be_bytes([ip[22], ip[23]]), 80);
    assert!(ip.ends_with(b"GET / HTTP/1.0\r\n\r\n"));
}

#[test]
fn encode_ip_packet_builds_parseable_ipv4_icmp_with_header() {
    let packet = Packet::new(
        FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            0,
            0,
            Protocol::Icmp,
        ),
        PacketDirection::Outbound,
        bytes::Bytes::from_static(b"ping"),
    );

    let ip = encode_ip_packet(&packet).expect("icmp encode");

    assert_eq!(ip[9], 1);
    assert_eq!(ip[20], 8);
    assert_eq!(internet_checksum(&ip[20..]), 0);
    let parsed = PcapReader::parse_link_packet(&ip, PCAP_LINKTYPE_RAW, 0, timestamp(), ip.len())
        .expect("encoded packet should parse");
    assert_eq!(parsed.payload.as_ref(), b"ping");
}

#[test]
fn encode_ip_packet_builds_parseable_ipv6_icmp_with_header() {
    let packet = Packet::new(
        FiveTuple::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            0,
            0,
            Protocol::Icmp,
        ),
        PacketDirection::Inbound,
        bytes::Bytes::from_static(b"pong"),
    );

    let ip = encode_ip_packet(&packet).expect("icmpv6 encode");

    assert_eq!(ip[6], 58);
    assert_eq!(ip[40], 129);
    let parsed = PcapReader::parse_link_packet(&ip, PCAP_LINKTYPE_RAW, 0, timestamp(), ip.len())
        .expect("encoded packet should parse");
    assert_eq!(parsed.payload.as_ref(), b"pong");
}
