use super::{
    BerLengthField, MAX_NKN_FRAME_SIZE, MAX_POSTGRES_FRAME_SIZE, MAX_REDIS_BULK_SIZE,
    MAX_SSH_PACKET_SIZE, TcpFrameMode, TcpFrameResult, extract_ldap_frame, extract_memcached_frame,
    extract_mqtt_frame, extract_nkn_frame, extract_postgres_frame, extract_rdp_frame,
    extract_redis_resp_array_frame, extract_smtp_data_frame_with_limit, extract_socks_frame,
    extract_ssh_payload_frame, extract_tls_frame, listener_name_matches_protocol,
    memcached_storage_body_len, parse_ber_length, port_frame_mode, protocol_frame_mode,
    write_tcp_with_timeout,
};
use crate::listener_context::ListenerContext;
use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
use crate::process_filter::ProcessFilter;
use std::sync::Arc;
use std::time::Duration;

fn test_listener_context() -> ListenerContext {
    let config = crate::listener_config::ListenerConfig {
        name: "raw".to_string(),
        port: 8080,
        timeout_ms: 10,
        ..Default::default()
    };
    let security = ListenerSecurity::new(ProcessFilter::new(), Vec::new(), Vec::new())
        .expect("security should initialize");
    let runtime = ListenerRuntime::new(ListenerRuntimeResources {
        ca: None,
        router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
        attribution: None,
        attribution_timeout: Duration::from_millis(5000),
        pcap_writer: None,
        nbi_collector: Arc::new(
            crate::nbi::NbiCollector::new(None).expect("collector should build"),
        ),
        session_tracker: Arc::new(crate::session::SessionTracker::new()),
        port_forward_table: Arc::new(crate::session::PortForwardTable::new()),
        flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
    });
    ListenerContext::new(config, security, runtime)
}

#[test]
fn listener_name_matches_protocol_rejects_unicode_whitespace_padding() {
    assert!(!listener_name_matches_protocol("http\u{00a0}", "http"));
}

#[test]
fn listener_name_matches_protocol_rejects_c1_control_padding() {
    assert!(!listener_name_matches_protocol("http\u{009f}", "http"));
}

#[test]
fn listener_name_matches_protocol_rejects_ascii_padding() {
    assert!(!listener_name_matches_protocol(" http ", "http"));
}

#[test]
fn memcached_storage_body_len_rejects_unicode_whitespace_separators() {
    assert!(memcached_storage_body_len("set key 0 0\u{00a0}5").is_err());
}

#[test]
fn memcached_storage_body_len_rejects_compressed_ascii_spaces() {
    assert!(memcached_storage_body_len("set key 0 0  5").is_err());
}

#[test]
fn memcached_storage_framing_rejects_tab_separated_header() {
    let mut buffer = b"set\tkey\t0\t0\t5\r\nvalue\r\nNEXT".to_vec();

    assert_eq!(
        extract_memcached_frame(&mut buffer),
        TcpFrameResult::Invalid {
            response: Some(b"ERROR\r\n".to_vec())
        }
    );
    assert!(buffer.is_empty());
}

#[test]
fn memcached_framing_rejects_bare_lf_lines() {
    let mut buffer = b"stats\n".to_vec();

    assert_eq!(
        extract_memcached_frame(&mut buffer),
        TcpFrameResult::Invalid {
            response: Some(b"ERROR\r\n".to_vec())
        }
    );
    assert!(buffer.is_empty());
}

#[test]
fn redis_framing_rejects_null_bulk_command_parts() {
    let mut buffer = b"*1\r\n$-1\r\n".to_vec();

    assert_eq!(
        extract_redis_resp_array_frame(&mut buffer),
        TcpFrameResult::Invalid { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn redis_framing_rejects_empty_arrays() {
    let mut buffer = b"*0\r\n".to_vec();

    assert_eq!(
        extract_redis_resp_array_frame(&mut buffer),
        TcpFrameResult::Invalid { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn redis_framing_rejects_oversized_declared_bulk_before_body() {
    let mut buffer = format!("*1\r\n${}\r\n", MAX_REDIS_BULK_SIZE + 1).into_bytes();

    assert_eq!(
        extract_redis_resp_array_frame(&mut buffer),
        TcpFrameResult::TooLarge { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn socks5_greeting_allows_nonzero_auth_method() {
    let mut buffer = vec![0x05, 0x01, 0x01];

    assert_eq!(
        extract_socks_frame(&mut buffer),
        TcpFrameResult::Complete(vec![0x05, 0x01, 0x01])
    );
    assert!(buffer.is_empty());
}

#[test]
fn socks5_greeting_allows_noauth_in_later_method_slot() {
    let mut buffer = vec![0x05, 0x02, 0x02, 0x00];

    assert_eq!(
        extract_socks_frame(&mut buffer),
        TcpFrameResult::Complete(vec![0x05, 0x02, 0x02, 0x00])
    );
    assert!(buffer.is_empty());
}

#[test]
fn socks5_request_rejects_nonzero_reserved_byte() {
    let mut buffer = vec![0x05, 0x01, 0x01, 0x01, 192, 0, 2, 10, 0x00, 0x50];

    assert_eq!(
        extract_socks_frame(&mut buffer),
        TcpFrameResult::Invalid { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn socks5_framing_does_not_split_coalesced_handshake_and_request() {
    let mut buffer = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x00];

    assert_eq!(
        extract_socks_frame(&mut buffer),
        TcpFrameResult::Complete(vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x00])
    );
    assert!(buffer.is_empty());
}

#[test]
fn socks4_framing_extracts_one_request_and_keeps_trailing_bytes() {
    let mut buffer = vec![0x04, 0x01, 0x00, 0x50, 192, 0, 2, 10, b'u', 0x00, b'x'];

    assert_eq!(
        extract_socks_frame(&mut buffer),
        TcpFrameResult::Complete(vec![0x04, 0x01, 0x00, 0x50, 192, 0, 2, 10, b'u', 0x00])
    );
    assert_eq!(buffer, vec![b'x']);
}

#[test]
fn socks4a_framing_extracts_one_request_and_keeps_trailing_bytes() {
    let mut buffer = vec![
        0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, b'u', 0x00, b'e', b'x', 0x00, b'x',
    ];

    assert_eq!(
        extract_socks_frame(&mut buffer),
        TcpFrameResult::Complete(vec![
            0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, b'u', 0x00, b'e', b'x', 0x00
        ])
    );
    assert_eq!(buffer, vec![b'x']);
}

#[test]
fn mqtt_framing_rejects_invalid_fixed_header_flags() {
    let mut buffer = vec![0x88, 0x00];

    assert_eq!(
        extract_mqtt_frame(&mut buffer),
        TcpFrameResult::Invalid { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn mqtt_framing_rejects_pingresp_with_nonzero_remaining_length() {
    let mut buffer = vec![0xd0, 0x01, 0x00];

    assert_eq!(
        extract_mqtt_frame(&mut buffer),
        TcpFrameResult::Invalid { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn mqtt_framing_rejects_connack_frame_from_client() {
    let mut buffer = vec![0x20, 0x02, 0x00, 0x00];

    assert_eq!(
        extract_mqtt_frame(&mut buffer),
        TcpFrameResult::Invalid { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn rdp_framing_rejects_short_tpkt_packet() {
    let mut buffer = vec![0x03, 0x00, 0x00, 0x06, 0x11, 0xe0];

    assert_eq!(
        extract_rdp_frame(&mut buffer),
        TcpFrameResult::Invalid { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn rdp_framing_rejects_nonzero_tpkt_reserved_byte() {
    let mut buffer = vec![0x03, 0xff, 0x00, 0x07, 0x02, 0xf0, 0x80];

    assert_eq!(
        extract_rdp_frame(&mut buffer),
        TcpFrameResult::Invalid { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn ldap_ber_length_rejects_non_canonical_long_form() {
    assert_eq!(parse_ber_length(&[0x81, 0x7f]), BerLengthField::Invalid);
    assert_eq!(
        parse_ber_length(&[0x82, 0x00, 0x80]),
        BerLengthField::Invalid
    );
    assert_eq!(
        parse_ber_length(&[0x81, 0x80]),
        BerLengthField::Complete {
            payload_len: 128,
            len_bytes: 2,
        }
    );
}

#[test]
fn ldap_framing_rejects_non_canonical_sequence_length() {
    let mut buffer = vec![0x30, 0x81, 0x03, 0x02, 0x01, 0x01];

    assert_eq!(
        extract_ldap_frame(&mut buffer),
        TcpFrameResult::Invalid { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn tls_framing_rejects_zero_length_record() {
    let mut buffer = vec![0x16, 0x03, 0x03, 0x00, 0x00];

    assert!(matches!(
        extract_tls_frame(&mut buffer),
        TcpFrameResult::Invalid { response: Some(_) }
    ));
    assert!(buffer.is_empty());
}

#[test]
fn tls_framing_rejects_too_short_handshake_record() {
    let mut buffer = vec![0x16, 0x03, 0x03, 0x00, 0x01, 0x01];

    assert!(matches!(
        extract_tls_frame(&mut buffer),
        TcpFrameResult::Invalid { response: Some(_) }
    ));
    assert!(buffer.is_empty());
}

#[test]
fn protocol_frame_mode_treats_tls_service_aliases_as_line_protocols() {
    assert_eq!(protocol_frame_mode("ftps", false), Some(TcpFrameMode::Line));
    assert_eq!(
        protocol_frame_mode("smtps", false),
        Some(TcpFrameMode::Line)
    );
    assert_eq!(
        protocol_frame_mode("pop3s", false),
        Some(TcpFrameMode::Line)
    );
    assert_eq!(protocol_frame_mode("imap", false), Some(TcpFrameMode::Line));
    assert_eq!(
        protocol_frame_mode("imaps", false),
        Some(TcpFrameMode::Line)
    );
    assert_eq!(protocol_frame_mode("ircs", false), Some(TcpFrameMode::Line));
    assert_eq!(
        protocol_frame_mode("telnets", false),
        Some(TcpFrameMode::Line)
    );
    assert_eq!(
        protocol_frame_mode("ldaps", false),
        Some(TcpFrameMode::Ldap)
    );
    assert_eq!(protocol_frame_mode("ssl", false), Some(TcpFrameMode::Tls));
}

#[test]
fn port_frame_mode_treats_imap_port_as_line_protocol() {
    let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
    assert_eq!(
        port_frame_mode(143, b"", &router, false),
        Some(TcpFrameMode::Line)
    );
}

#[test]
fn port_frame_mode_treats_irc_tls_port_as_tls() {
    let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
    let tls_client_hello = [
        0x16, 0x03, 0x03, 0x00, 0x20, 0x01, 0x00, 0x00, 0x1c, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    assert_eq!(
        port_frame_mode(6697, &tls_client_hello, &router, false),
        Some(TcpFrameMode::Tls)
    );
    assert_eq!(
        port_frame_mode(6697, b"", &router, false),
        Some(TcpFrameMode::Tls)
    );
}

#[test]
fn port_frame_mode_detects_dns_over_tcp_on_alternate_ports() {
    let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
    let mut msg = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    msg.push(7);
    msg.extend_from_slice(b"example");
    msg.push(3);
    msg.extend_from_slice(b"com");
    msg.push(0);
    msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&msg);

    assert_eq!(
        port_frame_mode(5353, &framed, &router, false),
        Some(TcpFrameMode::DnsTcp)
    );
}

#[test]
fn port_frame_mode_detects_fragmented_dns_over_tcp_on_alternate_ports() {
    let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
    let framed = [
        0x00, 0x20, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7, 0,
    ];

    assert_eq!(
        port_frame_mode(5353, &framed, &router, false),
        Some(TcpFrameMode::DnsTcp)
    );
}

#[test]
fn port_frame_mode_rejects_dns_header_without_question_data_on_alternate_ports() {
    let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
    let framed = [
        0x00, 0x10, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0,
    ];

    assert_eq!(port_frame_mode(5353, &framed, &router, false), None);
}

#[test]
fn port_frame_mode_does_not_force_dns_on_non_dns_length_prefixed_payload() {
    let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
    let framed = [0x00, 0x04, b't', b'e', b's', b't'];

    assert_eq!(port_frame_mode(5353, &framed, &router, false), None);
}

#[test]
fn ssh_payload_framing_waits_for_declared_packet_length() {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&8u32.to_be_bytes());
    buffer.extend_from_slice(&[4, 20, 0]);

    assert_eq!(
        extract_ssh_payload_frame(&mut buffer),
        TcpFrameResult::Incomplete
    );
    assert_eq!(buffer.len(), 7);
}

#[test]
fn ssh_payload_framing_extracts_exact_packet_and_keeps_trailing_bytes() {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&8u32.to_be_bytes());
    buffer.extend_from_slice(&[4, 20, 0, 0, 0, 0, 0, 0]);
    buffer.extend_from_slice(b"next");

    let frame = extract_ssh_payload_frame(&mut buffer);

    let TcpFrameResult::Complete(frame) = frame else {
        panic!("SSH payload frame should complete");
    };
    assert_eq!(frame.len(), 12);
    assert_eq!(buffer, b"next");
}

#[test]
fn ssh_payload_framing_rejects_oversized_declared_packet() {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&(MAX_SSH_PACKET_SIZE as u32).to_be_bytes());
    buffer.push(4);

    assert_eq!(
        extract_ssh_payload_frame(&mut buffer),
        TcpFrameResult::TooLarge { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn postgres_typed_framing_rejects_oversized_declared_message() {
    let mut buffer = vec![b'Q'];
    buffer.extend_from_slice(&((MAX_POSTGRES_FRAME_SIZE as u32) + 1).to_be_bytes());

    assert_eq!(
        extract_postgres_frame(&mut buffer),
        TcpFrameResult::TooLarge { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn postgres_typed_framing_counts_message_type_in_size_limit() {
    let mut buffer = vec![b'Q'];
    buffer.extend_from_slice(&(MAX_POSTGRES_FRAME_SIZE as u32).to_be_bytes());

    assert_eq!(
        extract_postgres_frame(&mut buffer),
        TcpFrameResult::TooLarge { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn postgres_typed_framing_rejects_too_short_declared_message() {
    let mut buffer = vec![b'Q', 0x00, 0x00, 0x00, 0x03];

    assert_eq!(
        extract_postgres_frame(&mut buffer),
        TcpFrameResult::Invalid { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn postgres_startup_framing_rejects_oversized_declared_message() {
    let mut buffer = ((MAX_POSTGRES_FRAME_SIZE as u32) + 1)
        .to_be_bytes()
        .to_vec();

    assert_eq!(
        extract_postgres_frame(&mut buffer),
        TcpFrameResult::TooLarge { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn smtp_data_framing_rejects_complete_frame_over_limit() {
    let mut buffer = b"123456789\r\n.\r\n".to_vec();

    assert_eq!(
        extract_smtp_data_frame_with_limit(&mut buffer, 8),
        TcpFrameResult::TooLarge {
            response: Some(b"552 Message too large\r\n".to_vec())
        }
    );
    assert!(buffer.is_empty());
}

#[test]
fn nkn_framing_rejects_oversized_json_rpc_before_parse() {
    let mut buffer = format!(
        r#"{{"jsonrpc":"2.0","method":"getnodestate","padding":"{}"}}"#,
        "a".repeat(MAX_NKN_FRAME_SIZE)
    )
    .into_bytes();

    assert_eq!(
        extract_nkn_frame(&mut buffer),
        TcpFrameResult::TooLarge { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn nkn_framing_rejects_trailing_bytes_after_json_rpc() {
    let mut buffer =
        br#"{"jsonrpc":"2.0","method":"getnodestate","unknown":{"nested":["ignored"]}}tail"#
            .to_vec();

    assert_eq!(
        extract_nkn_frame(&mut buffer),
        TcpFrameResult::Invalid { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn nkn_framing_consumes_trailing_json_whitespace() {
    let mut buffer = br#"{"jsonrpc":"2.0","method":"getnodestate","id":1}"#.to_vec();
    buffer.extend_from_slice(b"\r\n\t");

    let frame = extract_nkn_frame(&mut buffer);

    let TcpFrameResult::Complete(frame) = frame else {
        panic!("NKN JSON-RPC frame should complete");
    };
    assert!(frame.ends_with(b"\r\n\t"));
    assert!(buffer.is_empty());
}

#[tokio::test]
async fn write_tcp_with_timeout_returns_timed_out_under_backpressure() {
    let ctx = test_listener_context();
    let (mut server, _client) = tokio::io::duplex(64);
    let peer = "127.0.0.1:42424".parse().expect("valid peer");
    let payload = vec![b'x'; 1024 * 1024];

    let err = write_tcp_with_timeout(&ctx, &mut server, &payload, &peer, "TCP")
        .await
        .expect_err("unread peer should trigger write timeout");

    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}
