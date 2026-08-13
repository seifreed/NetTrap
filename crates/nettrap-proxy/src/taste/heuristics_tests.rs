use super::*;

fn tftp_rrq(filename: &[u8], mode: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(filename);
    packet.push(0);
    packet.extend_from_slice(mode);
    packet.push(0);
    packet
}

fn rdp_connection_request() -> Vec<u8> {
    vec![
        0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
}

fn valid_snmp_get_request() -> Vec<u8> {
    vec![
        0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x19,
        0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08,
        0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
    ]
}

fn push_ber_len(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len <= u8::MAX as usize {
        buf.extend_from_slice(&[0x81, len as u8]);
    } else if len <= u16::MAX as usize {
        buf.push(0x82);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0x84);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

fn snmp_get_request_with_community_len(community_len: usize) -> Vec<u8> {
    let mut pdu = vec![
        0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08,
        0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
    ];
    let mut message = vec![0x02, 0x01, 0x01, 0x04];
    push_ber_len(&mut message, community_len);
    message.extend(std::iter::repeat_n(b'a', community_len));
    message.push(0xa0);
    push_ber_len(&mut message, pdu.len());
    message.append(&mut pdu);

    let mut packet = vec![0x30];
    push_ber_len(&mut packet, message.len());
    packet.extend(message);
    packet
}

fn ssdp_m_search(mx_header: Option<&str>) -> Vec<u8> {
    let mut request = String::from(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: upnp:rootdevice\r\n",
    );
    if let Some(mx_header) = mx_header {
        request.push_str(mx_header);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request.into_bytes()
}

#[test]
fn looks_like_rdp_tpkt_accepts_exact_connection_request() {
    assert!(looks_like_rdp_tpkt(&rdp_connection_request()));
}

#[test]
fn looks_like_rdp_tpkt_rejects_trailing_junk_and_coalesced_tpkt() {
    let mut packet = rdp_connection_request();
    packet.extend_from_slice(b"extra");

    assert!(!looks_like_rdp_tpkt(&packet));

    let mut packet = rdp_connection_request();
    packet.extend_from_slice(&rdp_connection_request());

    assert!(!looks_like_rdp_tpkt(&packet));
    assert!(!looks_like_rdp_tpkt(&rdp_connection_request().repeat(4096)));

    let mut packet = rdp_connection_request();
    packet[4] = 0x05;

    assert!(!looks_like_rdp_tpkt(&packet));
}

#[test]
fn ber_length_rejects_non_canonical_long_form() {
    assert_eq!(ber_length(&[0x81, 0x7f]), None);
    assert_eq!(ber_length(&[0x82, 0x00, 0x80]), None);
    assert_eq!(ber_length(&[0x81, 0x80]), Some((128, 2)));
}

#[test]
fn looks_like_snmp_request_rejects_non_canonical_zero_integers() {
    let mut packet = valid_snmp_get_request();
    packet[19] = 0x02;
    packet.insert(20, 0x00);
    packet[1] += 1;
    packet[14] += 1;

    assert!(!looks_like_snmp_request(&packet));
}

#[test]
fn looks_like_snmp_request_rejects_oversized_community() {
    let packet = snmp_get_request_with_community_len(MAX_SNMP_COMMUNITY_BYTES + 1);

    assert!(!looks_like_snmp_request(&packet));
}

#[test]
fn looks_like_snmp_request_accepts_community_at_limit() {
    let packet = snmp_get_request_with_community_len(MAX_SNMP_COMMUNITY_BYTES);

    assert!(looks_like_snmp_request(&packet));
}

#[test]
fn looks_like_snmp_request_accepts_getbulk_request() {
    let mut packet = snmp_get_request_with_community_len(6);
    packet[13] = 0xa5;
    packet[20] = 0x01;
    packet[23] = 0x02;

    assert!(looks_like_snmp_request(&packet));
}

#[test]
fn looks_like_snmp_request_rejects_negative_getbulk_counts() {
    let mut non_repeaters = snmp_get_request_with_community_len(6);
    non_repeaters[13] = 0xa5;
    non_repeaters[1] += 1;
    non_repeaters[14] += 1;
    non_repeaters.splice(18..21, [0x02, 0x02, 0x80, 0x00]);

    let mut max_repetitions = snmp_get_request_with_community_len(6);
    max_repetitions[13] = 0xa5;
    max_repetitions[1] += 1;
    max_repetitions[14] += 1;
    max_repetitions.splice(21..24, [0x02, 0x02, 0x80, 0x00]);

    assert!(!looks_like_snmp_request(&non_repeaters));
    assert!(!looks_like_snmp_request(&max_repetitions));
}

#[test]
fn looks_like_ssdp_request_requires_numeric_mx_header() {
    assert!(looks_like_ssdp_request(&ssdp_m_search(Some("MX: 1"))));
    assert!(!looks_like_ssdp_request(&ssdp_m_search(None)));
    assert!(!looks_like_ssdp_request(&ssdp_m_search(Some("MX: soon"))));
}

#[test]
fn looks_like_ssdp_request_rejects_unsupported_search_target() {
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:service:WANPPPConnection:1\r\n\r\n";

    assert!(!looks_like_ssdp_request(request));
}

#[test]
fn looks_like_ssdp_request_accepts_obs_text_in_unselected_header_values() {
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nX-Test: hi\x85\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";

    assert!(looks_like_ssdp_request(request));
}

#[test]
fn looks_like_ssdp_request_rejects_signed_host_port() {
    let request = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:+1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";

    assert!(!looks_like_ssdp_request(request));
}

#[test]
fn looks_like_ssdp_request_rejects_invalid_header_line_endings() {
    let request = b"M-SEARCH * HTTP/1.1\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";
    assert!(!looks_like_ssdp_request(request));
}

#[test]
fn looks_like_ssdp_request_rejects_unicode_line_separators_in_headers() {
    let mut request = String::from(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: upnp:rootdevice\r\nMX: 1\u{2028}AL: bad\r\n\r\n",
    );

    assert!(!looks_like_ssdp_request(request.as_bytes()));

    request = String::from(
        "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNTS: ssdp:alive\r\nNT: upnp:rootdevice\r\nUSN: uuid:device\r\nLOCATION: http://example.test/device.xml\u{2028}AL: bad\r\nCACHE-CONTROL: max-age=1800\r\n\r\n",
    );

    assert!(!looks_like_ssdp_request(request.as_bytes()));
}

#[test]
fn looks_like_mqtt_client_packet_rejects_reserved_publish_qos() {
    assert!(!looks_like_mqtt_client_packet(&[
        0x36, 0x05, 0x00, 0x01, b'a', 0x00, 0x01,
    ]));
}

#[test]
fn looks_like_mqtt_client_packet_rejects_frames_over_handler_limit() {
    let mut packet = vec![0x10, 0xff, 0xff, 0x3f];
    packet.extend_from_slice(&[0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c]);
    packet.extend_from_slice(&[0x00, 0x01, b'a']);
    packet.resize(MQTT_MAX_PACKET_BYTES + 1, 0);

    assert!(!looks_like_mqtt_client_packet(&packet));
}

#[test]
fn looks_like_mqtt_client_packet_accepts_subscribe_with_properties() {
    assert!(looks_like_mqtt_client_packet(&[
        0x82, 0x07, 0x00, 0x01, 0x00, 0x00, 0x01, b'a', 0x00,
    ]));
}

#[test]
fn looks_like_mqtt_client_packet_rejects_unknown_subscribe_properties() {
    assert!(!looks_like_mqtt_client_packet(&[
        0x82, 0x08, 0x00, 0x01, 0x01, 0x99, 0x00, 0x01, b'a', 0x00,
    ]));
}

#[test]
fn looks_like_mqtt_client_packet_accepts_mqtt5_subscription_options() {
    assert!(looks_like_mqtt_client_packet(&[
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, b'a', 0x04,
    ]));
}

#[test]
fn looks_like_mqtt_client_packet_rejects_reserved_subscription_options() {
    assert!(!looks_like_mqtt_client_packet(&[
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, b'a', 0x30,
    ]));
}

#[test]
fn looks_like_mqtt_client_packet_rejects_forbidden_utf8_codepoints() {
    let connect = [
        0x10, 0x0f, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x03, b'a',
        0x1f, b'b',
    ];
    let publish = [0x30, 0x04, 0x00, 0x01, 0x1f, b'x'];
    let subscribe = [0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 0x1f, 0x00];

    assert!(!looks_like_mqtt_client_packet(&connect));
    assert!(!looks_like_mqtt_client_packet(&publish));
    assert!(!looks_like_mqtt_client_packet(&subscribe));
}

#[test]
fn looks_like_mqtt_client_packet_rejects_coalesced_tcp_packets() {
    let connect = [
        0x10, 0x0f, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x03, b'a',
        b'b', b'c',
    ];
    let publish_followed_by_ping = [0x30, 0x04, 0x00, 0x01, b'a', b'x', 0xc0, 0x00];
    let subscribe_followed_by_ping = [0x82, 0x06, 0x00, 0x01, 0x00, 0x01, b'a', 0x00, 0xc0, 0x00];
    let publish_followed_by_many = [0x30, 0x04, 0x00, 0x01, b'a', b'x', 0xc0, 0x00, 0xe0, 0x00];

    let mut coalesced_connect = connect.to_vec();
    coalesced_connect.extend_from_slice(&[0xc0, 0x00]);

    assert!(!looks_like_mqtt_client_packet(&coalesced_connect));
    assert!(!looks_like_mqtt_client_packet(&publish_followed_by_ping));
    assert!(!looks_like_mqtt_client_packet(&publish_followed_by_many));
    assert!(!looks_like_mqtt_client_packet(&subscribe_followed_by_ping));
    assert!(!looks_like_mqtt_client_packet(&[0xc0, 0x00, 0xe0, 0x00]));
    assert!(!looks_like_mqtt_client_packet(&[
        0xc0, 0x00, 0xe0, 0x02, 0x00
    ]));
}

#[test]
fn first_text_line_rejects_unicode_line_separators() {
    assert!(first_text_line("PING\u{2028}extra\r\n".as_bytes()).is_none());
    assert!(first_text_line("PING\u{2029}extra\r\n".as_bytes()).is_none());
    assert!(first_text_line("PING\u{0085}extra\r\n".as_bytes()).is_none());
}

#[test]
fn first_text_line_ignores_non_utf8_bytes_after_first_line() {
    assert_eq!(first_text_line(b"PING\r\nX-Test: hi\x85\r\n"), Some("PING"));
}

#[test]
fn first_ascii_token_rejects_unicode_line_separators() {
    assert!(first_ascii_token("PING\u{2028}extra\r\n".as_bytes()).is_none());
    assert!(first_ascii_token("PING\u{2029}extra\r\n".as_bytes()).is_none());
    assert!(first_ascii_token("PING\u{0085}extra\r\n".as_bytes()).is_none());
}

#[test]
fn first_ascii_token_rejects_embedded_crlf_injection() {
    assert!(first_ascii_token("PING\r\nEXTRA".as_bytes()).is_none());
    assert_eq!(first_ascii_token("PING\r\n".as_bytes()), Some("PING"));
    assert_eq!(first_ascii_token("PING".as_bytes()), Some("PING"));
}

#[test]
fn redis_replication_args_reject_invalid_hosts() {
    assert!(!redis_replication_args_are_valid(&["bad..example", "6379"]));
    assert!(!redis_replication_args_are_valid(&["bad_example", "6379"]));
    assert!(!redis_replication_args_are_valid(&["0.0.0.0", "6379"]));
    assert!(!redis_replication_args_are_valid(&["127.0.0.1", "6379"]));
    assert!(!redis_replication_args_are_valid(&["224.0.0.1", "6379"]));
    assert!(!redis_replication_args_are_valid(&[
        "255.255.255.255",
        "6379"
    ]));
    assert!(!redis_replication_args_are_valid(&[
        "[::ffff:127.0.0.1]",
        "6379"
    ]));
    assert!(redis_replication_args_are_valid(&["[::1]", "6379"]));
    assert!(!redis_replication_args_are_valid(&["[::]", "6379"]));
    assert!(redis_replication_args_are_valid(&["example.test.", "6379"]));
}

#[test]
fn redis_replication_args_reject_overlong_hostnames() {
    let hostname = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );

    assert_eq!(hostname.len(), 254);
    assert!(!redis_replication_args_are_valid(&[&hostname, "6379"]));
}

#[test]
fn looks_like_tftp_request_accepts_benign_dotted_filename() {
    assert!(looks_like_tftp_request(&tftp_rrq(b"file..bin", b"octet")));
}

#[test]
fn looks_like_tftp_request_rejects_path_traversal_component() {
    assert!(!looks_like_tftp_request(&tftp_rrq(
        b"../secret.bin",
        b"octet"
    )));
    assert!(!looks_like_tftp_request(&tftp_rrq(b".", b"octet")));
    assert!(!looks_like_tftp_request(&tftp_rrq(b"firmware/.", b"octet")));
}

#[test]
fn looks_like_tftp_request_rejects_colon_separated_filenames() {
    assert!(!looks_like_tftp_request(&tftp_rrq(
        b"C:/secret.bin",
        b"octet"
    )));
    assert!(!looks_like_tftp_request(&tftp_rrq(
        b"firmware:stream",
        b"octet"
    )));
}

#[test]
fn looks_like_http_start_line_rejects_unspecified_authority_targets() {
    assert!(!looks_like_http_start_line(
        b"CONNECT 0.0.0.0:443 HTTP/1.1\r\n"
    ));
    assert!(!looks_like_http_start_line(
        b"CONNECT [::]:443 HTTP/1.1\r\n"
    ));
    assert!(!looks_like_http_start_line(
        b"CONNECT [::ffff:0.0.0.0]:443 HTTP/1.1\r\n"
    ));
    assert!(!looks_like_http_start_line(
        b"GET http://0.0.0.0/path HTTP/1.1\r\n"
    ));
    assert!(!looks_like_http_start_line(
        b"GET http://[::]/path HTTP/1.1\r\n"
    ));
}

#[test]
fn looks_like_http_start_line_rejects_loopback_authority_targets() {
    assert!(!looks_like_http_start_line(
        b"CONNECT 127.0.0.1:443 HTTP/1.1\r\n"
    ));
    assert!(!looks_like_http_start_line(
        b"CONNECT [::1]:443 HTTP/1.1\r\n"
    ));
    assert!(!looks_like_http_start_line(
        b"CONNECT [::ffff:127.0.0.1]:443 HTTP/1.1\r\n"
    ));
    assert!(!looks_like_http_start_line(
        b"GET http://127.0.0.1/path HTTP/1.1\r\n"
    ));
    assert!(!looks_like_http_start_line(
        b"GET http://[::1]/path HTTP/1.1\r\n"
    ));
}

#[test]
fn looks_like_http_start_line_accepts_non_special_ipv6_authority_targets_with_ports() {
    assert!(looks_like_http_start_line(
        b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"
    ));
}

#[test]
fn looks_like_http_start_line_rejects_multicast_and_broadcast_authority_targets() {
    assert!(!looks_like_http_start_line(
        b"CONNECT 224.0.0.1:443 HTTP/1.1\r\n"
    ));
    assert!(!looks_like_http_start_line(
        b"CONNECT 255.255.255.255:443 HTTP/1.1\r\n"
    ));
    assert!(!looks_like_http_start_line(
        b"GET http://224.0.0.1/path HTTP/1.1\r\n"
    ));
    assert!(!looks_like_http_start_line(
        b"GET http://255.255.255.255/path HTTP/1.1\r\n"
    ));
}

#[test]
fn looks_like_http_start_line_rejects_unicode_line_separators_in_targets() {
    assert!(!looks_like_http_start_line(
        b"GET /submit\xe2\x80\xa8X:1 HTTP/1.1\r\n"
    ));
    assert!(!looks_like_http_start_line(
        b"CONNECT example.test\xe2\x80\xa8:443 HTTP/1.1\r\n"
    ));
}

#[test]
fn looks_like_http_start_line_rejects_invalid_line_endings() {
    assert!(!looks_like_http_start_line(b"GET / HTTP/1.1\n"));
    assert!(!looks_like_http_start_line(b"GET / HTTP/1.1\rHost: x"));
    assert!(!looks_like_http_request_line_shape(b"GET / HTTP/1.1\n"));
    assert!(looks_like_http_start_line(
        b"POST / HTTP/1.1\r\nHost: example.test\r\n\r\nline\nline"
    ));
}

#[test]
fn looks_like_sip_request_line_rejects_invalid_header_line_endings() {
    assert!(!looks_like_sip_request_line(
            b"OPTIONS sip:service@example.com SIP/2.0\nVia: SIP/2.0/UDP client.example.com\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:service@example.com>\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        ));
    assert!(!looks_like_sip_request_line(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nVia: SIP/2.0/UDP client.example.com\rFrom: <sip:alice@example.com>\r\nTo: <sip:service@example.com>\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        ));
}

#[test]
fn looks_like_sip_request_line_accepts_compact_headers() {
    assert!(looks_like_sip_request_line(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nv: SIP/2.0/UDP client.example.com\r\nf: <sip:alice@example.com>\r\nt: <sip:service@example.com>\r\ni: abc\r\nCSeq: 1 OPTIONS\r\nl: 4\r\n\r\nbody"
        ));
}

#[test]
fn looks_like_sip_request_line_accepts_uppercase_compact_headers() {
    assert!(looks_like_sip_request_line(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nV: SIP/2.0/UDP client.example.com\r\nF: <sip:alice@example.com>\r\nT: <sip:service@example.com>\r\nI: abc\r\nCSeq: 1 OPTIONS\r\nL: 4\r\n\r\nbody"
        ));
}

#[test]
fn looks_like_sip_request_line_rejects_duplicate_unique_headers() {
    assert!(!looks_like_sip_request_line(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nVia: SIP/2.0/UDP client.example.com\r\nFrom: <sip:alice@example.com>\r\nFrom: <sip:bob@example.com>\r\nTo: <sip:service@example.com>\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        ));
    assert!(!looks_like_sip_request_line(
            b"OPTIONS sip:service@example.com SIP/2.0\r\nVia: SIP/2.0/UDP client.example.com\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:service@example.com>\r\nI: abc\r\nCall-ID: abc\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        ));
}

#[test]
fn looks_like_http_start_line_rejects_overlong_authority_hostnames() {
    let hostname = ["a"; 128].join(".");

    assert!(hostname.len() > 253);

    let connect = format!("CONNECT {}:443 HTTP/1.1\r\n", hostname);
    let absolute = format!("GET http://{}/path HTTP/1.1\r\n", hostname);

    assert!(!looks_like_http_start_line(connect.as_bytes()));
    assert!(!looks_like_http_start_line(absolute.as_bytes()));
}

#[test]
fn looks_like_nkn_json_rpc_accepts_unknown_fields_without_value_materialization() {
    assert!(looks_like_nkn_json_rpc(
        br#"{"jsonrpc":"2.0","method":"getnodestate","padding":{"nested":["ignored"]}}"#
    ));
}

#[test]
fn looks_like_nkn_json_rpc_rejects_oversized_unknown_fields() {
    let oversized = format!(
        r#"{{"jsonrpc":"2.0","method":"getnodestate","padding":"{}"}}"#,
        "a".repeat(MAX_NKN_JSON_RPC_TASTE_BYTES)
    );

    assert!(!looks_like_nkn_json_rpc(oversized.as_bytes()));
}

#[test]
fn looks_like_nkn_json_rpc_request_rejects_oversized_methods() {
    let oversized = format!(
        r#"{{"jsonrpc":"2.0","method":"{}","id":1}}"#,
        "a".repeat(MAX_NKN_JSON_RPC_METHOD_BYTES + 1)
    );

    assert!(!looks_like_nkn_json_rpc_request(oversized.as_bytes()));
}
