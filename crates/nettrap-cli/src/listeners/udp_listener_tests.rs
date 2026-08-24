use super::*;
use crate::listener_context::ListenerContext;
use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
use crate::process_filter::ProcessFilter;
use crate::session::{PortForwardTable, SessionTracker};
use std::collections::HashMap;
use std::sync::Arc;

#[test]
fn qotd_is_an_alias_for_udp_quotd() {
    assert!(udp_listener_name_matches_protocol("qotd", "quotd"));
    assert!(udp_listener_name_matches_protocol("QOTD", "quotd"));
    assert!(udp_listener_name_matches_protocol("qotd_17", "quotd"));
    assert!(udp_listener_name_matches_protocol("qotd-banner", "quotd"));
    assert_eq!(explicit_udp_protocol_name("qotd"), Some("quotd"));
    assert_eq!(explicit_udp_protocol_name("quotd"), Some("quotd"));
    assert_eq!(canonical_udp_protocol_alias("queue"), "queue");
    assert!(!udp_listener_name_matches_protocol("quic", "quotd"));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_udp_sockaddr_in_original_destination_preserves_ip_and_port() {
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 5353u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes([198, 51, 100, 7]).to_be(),
        },
        sin_zero: [0; 8],
    };

    assert_eq!(
        session_destination_from_sockaddr_in(addr),
        Some(SessionDestination::new_unchecked("198.51.100.7", 5353))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_udp_sockaddr_in6_original_destination_preserves_ip_and_port() {
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 5353u16.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
        },
        sin6_scope_id: 0,
    };

    assert_eq!(
        session_destination_from_sockaddr_in6(addr),
        Some(SessionDestination::new_unchecked("2001:db8::7", 5353))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_udp_sockaddr_in6_original_destination_canonicalizes_ipv4_mapped_address() {
    let addr = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 5353u16.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 198, 51, 100, 7],
        },
        sin6_scope_id: 0,
    };

    assert_eq!(
        session_destination_from_sockaddr_in6(addr),
        Some(SessionDestination::new_unchecked("198.51.100.7", 5353))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_udp_sockaddr_in_original_destination_rejects_unspecified_ip() {
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 5353u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_be_bytes([0, 0, 0, 0]).to_be(),
        },
        sin_zero: [0; 8],
    };

    assert_eq!(session_destination_from_sockaddr_in(addr), None);
}

#[test]
fn attributed_udp_process_is_recorded_and_filtered() {
    let tracker = Arc::new(SessionTracker::new());
    let ctx = ListenerContext::builder()
        .name("dns")
        .port(53)
        .build(
            ListenerSecurity::new(
                ProcessFilter::build(
                    Vec::new(),
                    Vec::new(),
                    vec!["allowed.exe".into()],
                    Vec::new(),
                )
                .expect("host rules should compile"),
                Vec::new(),
                Vec::new(),
            )
            .expect("host rules should compile"),
            ListenerRuntime::new(ListenerRuntimeResources {
                ca: None,
                router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                attribution: None,
                attribution_timeout: std::time::Duration::from_millis(5000),
                pcap_writer: None,
                nbi_collector: Arc::new(
                    crate::nbi::NbiCollector::new(None).expect("collector should build"),
                ),
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::new(PortForwardTable::new()),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53000".parse().unwrap();
    let attr = nettrap_core::prelude::Attribution::new(
        nettrap_core::prelude::ProcessInfo::new(4242, "allowed.exe"),
        nettrap_core::prelude::AttributionConfidence::High,
        nettrap_core::prelude::AttributionMethod::SocketTable,
    );

    let destination = SessionDestination::unknown(53);
    tracker.register(&src, &destination, "dns", "UDP");

    assert!(apply_attributed_process_filter(
        &ctx,
        &src,
        &destination,
        &attr
    ));
    assert_eq!(
        tracker.get_process(&src, "UDP", &destination),
        Some((Some("allowed.exe".to_string()), Some(4242)))
    );
}

#[test]
fn blocked_udp_process_keeps_session_visible_until_ttl() {
    let tracker = Arc::new(SessionTracker::new());
    let ctx = ListenerContext::builder()
        .name("dns")
        .port(53)
        .build(
            ListenerSecurity::new(
                ProcessFilter::build(
                    Vec::new(),
                    Vec::new(),
                    vec!["allowed.exe".into()],
                    Vec::new(),
                )
                .expect("host rules should compile"),
                Vec::new(),
                Vec::new(),
            )
            .expect("host rules should compile"),
            ListenerRuntime::new(ListenerRuntimeResources {
                ca: None,
                router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                attribution: None,
                attribution_timeout: std::time::Duration::from_millis(5000),
                pcap_writer: None,
                nbi_collector: Arc::new(
                    crate::nbi::NbiCollector::new(None).expect("collector should build"),
                ),
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::new(PortForwardTable::new()),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53001".parse().unwrap();
    let attr = nettrap_core::prelude::Attribution::new(
        nettrap_core::prelude::ProcessInfo::new(4243, "blocked.exe"),
        nettrap_core::prelude::AttributionConfidence::High,
        nettrap_core::prelude::AttributionMethod::SocketTable,
    );

    let destination = SessionDestination::unknown(53);
    tracker.register(&src, &destination, "dns", "UDP");

    assert!(!apply_attributed_process_filter(
        &ctx,
        &src,
        &destination,
        &attr
    ));
    assert_eq!(tracker.active_count(), 1);
    assert_eq!(
        tracker.get_process(&src, "UDP", &destination),
        Some((Some("blocked.exe".to_string()), Some(4243)))
    );
}

#[test]
fn direct_destination_uses_explicit_bind_when_socket_addr_is_unspecified() {
    let local_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
    let bind_addr: IpAddr = "192.168.10.25".parse().unwrap();

    let destination = direct_destination_from_local_addr(local_addr, bind_addr);

    assert_eq!(
        destination,
        SessionDestination::new_unchecked("192.168.10.25", 5353)
    );
}

#[test]
fn direct_destination_canonicalizes_ipv4_mapped_explicit_bind() {
    let local_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
    let bind_addr: IpAddr = "::ffff:192.168.10.25".parse().unwrap();

    let destination = direct_destination_from_local_addr(local_addr, bind_addr);

    assert_eq!(
        destination,
        SessionDestination::new_unchecked("192.168.10.25", 5353)
    );
}

fn udp_test_context(
    listener_port: u16,
    router: Arc<nettrap_proxy::ProtocolRouter>,
    custom_response: Option<String>,
) -> ListenerContext {
    udp_test_context_named("raw", listener_port, router, custom_response)
}

fn udp_test_context_named(
    name: &str,
    listener_port: u16,
    router: Arc<nettrap_proxy::ProtocolRouter>,
    custom_response: Option<String>,
) -> ListenerContext {
    ListenerContext::builder()
        .name(name)
        .port(listener_port)
        .custom_response(custom_response)
        .build(
            ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                .expect("empty host rules should compile"),
            ListenerRuntime::new(ListenerRuntimeResources {
                ca: None,
                router,
                attribution: None,
                attribution_timeout: std::time::Duration::from_millis(5000),
                pcap_writer: None,
                nbi_collector: Arc::new(
                    crate::nbi::NbiCollector::new(None).expect("collector should build"),
                ),
                session_tracker: Arc::new(SessionTracker::new()),
                port_forward_table: Arc::new(PortForwardTable::new()),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        )
        .expect("listener context should build")
}

fn dns_query_bytes() -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&0x1234u16.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.push(7);
    query.extend_from_slice(b"example");
    query.push(3);
    query.extend_from_slice(b"com");
    query.push(0);
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

fn flow_bytes(
    ctx: &ListenerContext,
    src: SocketAddr,
    destination: &SessionDestination,
) -> (u64, u64) {
    let five_tuple = nettrap_core::prelude::FiveTuple::new(
        src.ip(),
        destination
            .ip()
            .parse()
            .expect("test destination should be an IP"),
        src.port(),
        destination.port(),
        nettrap_core::prelude::Protocol::Udp,
    );
    let key = nettrap_core::prelude::FlowKey::from_five_tuple(&five_tuple);
    let flow = ctx
        .runtime
        .flow_manager
        .get(&key)
        .expect("flow should exist");
    (flow.metadata.bytes_received, flow.metadata.bytes_sent)
}

#[test]
fn udp_forward_target_rejects_self_and_invalid_destinations() {
    let listener: SocketAddr = "127.0.0.1:5353".parse().expect("listener address");
    let self_destination = SessionDestination::new_unchecked("127.0.0.1", 5353);
    let other_destination = SessionDestination::new_unchecked("127.0.0.1", 5354);
    let unspecified = SessionDestination::new_unchecked("0.0.0.0", 5354);

    assert_eq!(
        resolve_udp_forward_target(&self_destination, listener),
        None
    );
    assert_eq!(
        resolve_udp_forward_target(&other_destination, listener),
        Some("127.0.0.1:5354".parse().expect("target address"))
    );
    assert_eq!(resolve_udp_forward_target(&unspecified, listener), None);
}

#[tokio::test]
async fn udp_forward_relay_returns_upstream_response_to_client() {
    let listener_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind listener socket");
    let client_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind client socket");
    let upstream_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind upstream socket");
    let client_addr = client_socket.local_addr().expect("client address");
    let upstream_addr = upstream_socket.local_addr().expect("upstream address");
    let ctx = udp_test_context(
        listener_socket
            .local_addr()
            .expect("listener address")
            .port(),
        Arc::new(nettrap_proxy::ProtocolRouter::new()),
        None,
    );
    let destination =
        SessionDestination::new_unchecked(upstream_addr.ip().to_string(), upstream_addr.port());

    let upstream_task = tokio::spawn(async move {
        let mut query = [0_u8; 32];
        let (length, peer) = upstream_socket
            .recv_from(&mut query)
            .await
            .expect("receive forwarded query");
        assert_eq!(&query[..length], b"ping");
        upstream_socket
            .send_to(b"pong", peer)
            .await
            .expect("send upstream response");
    });

    forward_udp_datagram(
        &ctx,
        &listener_socket,
        b"ping",
        &client_addr,
        &destination,
        false,
    )
    .await
    .expect("forward datagram");

    let mut response = [0_u8; 32];
    let (length, peer) = client_socket
        .recv_from(&mut response)
        .await
        .expect("receive forwarded response");
    assert_eq!(&response[..length], b"pong");
    assert_eq!(
        peer,
        listener_socket.local_addr().expect("listener address")
    );
    upstream_task.await.expect("upstream task");
}

#[test]
fn explicit_udp_protocol_names_require_exact_or_separator_match() {
    assert_eq!(explicit_udp_protocol_name("daytime-alt"), Some("daytime"));
    assert_eq!(explicit_udp_protocol_name("time_37"), Some("time"));
    assert_eq!(explicit_udp_protocol_name("timeout"), None);
    assert_eq!(explicit_udp_protocol_name("raw"), Some("raw"));
    assert_eq!(explicit_udp_protocol_name("echo"), Some("raw"));
    assert_eq!(explicit_udp_protocol_name("echo_7"), Some("raw"));
}

#[test]
fn explicit_udp_protocol_names_reject_unicode_whitespace_padding() {
    assert_eq!(explicit_udp_protocol_name("dns\u{00a0}"), None);
}

#[test]
fn explicit_udp_protocol_names_reject_c1_controls_padding() {
    assert_eq!(explicit_udp_protocol_name("dns\u{009f}"), None);
}

#[test]
fn explicit_udp_protocol_names_reject_ascii_padding() {
    assert_eq!(explicit_udp_protocol_name(" dns "), None);
}

#[tokio::test]
async fn udp_raw_uses_custom_response() {
    let bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .expect("bind UDP listener socket");
    let listener_port = socket.local_addr().expect("listener addr").port();
    let receiver = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .expect("bind UDP receiver");
    let src = receiver.local_addr().expect("receiver addr");
    let router = Arc::new(nettrap_proxy::ProtocolRouter::new());
    router.register("raw", Box::new(nettrap_proxy::RawTaste), false);
    let ctx = udp_test_context(listener_port, router, Some("static:pong".to_string()));
    let destination = SessionDestination::new_unchecked(bind_ip.to_string(), listener_port);
    let dns_handler = nettrap_proto_dns::handler::DnsHandler::new();
    let tftp_handler = nettrap_proto_tftp::TftpHandler::new();
    let chargen_handler = nettrap_proto_chargen::ChargenHandler::new();
    let handlers = UdpHandlers {
        dns: &dns_handler,
        tftp: &tftp_handler,
        chargen: &chargen_handler,
    };
    let transfers = Arc::new(Mutex::new(HashMap::new()));

    handle_detected_udp(
        &ctx,
        &socket,
        &handlers,
        &transfers,
        UdpPacket {
            output_path: None,
            query_data: b"ping",
            src: &src,
            destination: &destination,
            len: 4,
        },
    )
    .await;

    let mut buf = [0u8; 16];
    let (len, peer) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        receiver.recv_from(&mut buf),
    )
    .await
    .expect("raw response timed out")
    .expect("receive raw response");
    assert_eq!(&buf[..len], b"pong");
    assert_eq!(peer, socket.local_addr().expect("listener addr"));
}

#[tokio::test]
async fn udp_raw_silent_custom_response_sends_no_datagram() {
    let bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .expect("bind UDP listener socket");
    let listener_port = socket.local_addr().expect("listener addr").port();
    let receiver = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .expect("bind UDP receiver");
    let src = receiver.local_addr().expect("receiver addr");
    let router = Arc::new(nettrap_proxy::ProtocolRouter::new());
    router.register("raw", Box::new(nettrap_proxy::RawTaste), false);
    let ctx = udp_test_context(listener_port, router, Some("silent".to_string()));
    let destination = SessionDestination::new_unchecked(bind_ip.to_string(), listener_port);
    let dns_handler = nettrap_proto_dns::handler::DnsHandler::new();
    let tftp_handler = nettrap_proto_tftp::TftpHandler::new();
    let chargen_handler = nettrap_proto_chargen::ChargenHandler::new();
    let handlers = UdpHandlers {
        dns: &dns_handler,
        tftp: &tftp_handler,
        chargen: &chargen_handler,
    };
    let transfers = Arc::new(Mutex::new(HashMap::new()));

    handle_detected_udp(
        &ctx,
        &socket,
        &handlers,
        &transfers,
        UdpPacket {
            output_path: None,
            query_data: b"ping",
            src: &src,
            destination: &destination,
            len: 4,
        },
    )
    .await;

    let mut buf = [0u8; 16];
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        receiver.recv_from(&mut buf),
    )
    .await;
    assert!(result.is_err(), "silent raw response should not send data");
}

#[tokio::test]
async fn dns_handler_records_received_bytes_on_parse_error() {
    let bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .expect("bind UDP listener socket");
    let listener_port = socket.local_addr().expect("listener addr").port();
    let router = Arc::new(nettrap_proxy::ProtocolRouter::new());
    let ctx = udp_test_context_named("dns", listener_port, router, None);
    let src = SocketAddr::new(bind_ip, 53000);
    let destination = SessionDestination::new_unchecked(bind_ip.to_string(), listener_port);
    ctx.register_session(&src, "UDP", Some(destination.clone()));

    handle_dns(
        &ctx,
        &socket,
        &nettrap_proto_dns::handler::DnsHandler::new(),
        UdpPacket {
            output_path: None,
            query_data: b"\x00",
            src: &src,
            destination: &destination,
            len: 1,
        },
    )
    .await;

    assert_eq!(flow_bytes(&ctx, src, &destination), (1, 0));
}

#[tokio::test]
async fn dns_handler_records_zero_sent_bytes_when_send_fails() {
    let bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .expect("bind UDP listener socket");
    let listener_port = socket.local_addr().expect("listener addr").port();
    let router = Arc::new(nettrap_proxy::ProtocolRouter::new());
    let ctx = udp_test_context_named("dns", listener_port, router, None);
    let src = "[::1]:53000".parse::<SocketAddr>().expect("IPv6 source");
    let destination = SessionDestination::new_unchecked(bind_ip.to_string(), listener_port);
    ctx.register_session(&src, "UDP", Some(destination.clone()));
    let query = dns_query_bytes();

    handle_dns(
        &ctx,
        &socket,
        &nettrap_proto_dns::handler::DnsHandler::new(),
        UdpPacket {
            output_path: None,
            query_data: &query,
            src: &src,
            destination: &destination,
            len: query.len(),
        },
    )
    .await;

    assert_eq!(flow_bytes(&ctx, src, &destination), (query.len() as u64, 0));
}

#[tokio::test]
async fn unknown_detected_udp_records_received_and_sent_bytes() {
    let bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .expect("bind UDP listener socket");
    let listener_port = socket.local_addr().expect("listener addr").port();
    let receiver = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .expect("bind UDP receiver");
    let src = receiver.local_addr().expect("receiver addr");
    let router = Arc::new(nettrap_proxy::ProtocolRouter::new());
    let nbi_path = std::env::temp_dir().join(format!(
        "nettrap-unknown-udp-nbi-{}-{}.jsonl",
        std::process::id(),
        listener_port
    ));
    let collector = Arc::new(
        crate::nbi::NbiCollector::new(Some(nbi_path.clone())).expect("collector should build"),
    );
    let ctx = ListenerContext::builder()
        .name("raw")
        .port(listener_port)
        .build(
            ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                .expect("empty host rules should compile"),
            ListenerRuntime::new(ListenerRuntimeResources {
                ca: None,
                router,
                attribution: None,
                attribution_timeout: std::time::Duration::from_millis(5000),
                pcap_writer: None,
                nbi_collector: Arc::clone(&collector),
                session_tracker: Arc::new(SessionTracker::new()),
                port_forward_table: Arc::new(PortForwardTable::new()),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        )
        .expect("listener context should build");
    let destination = SessionDestination::new_unchecked(bind_ip.to_string(), listener_port);
    ctx.register_session(&src, "UDP", Some(destination.clone()));

    handle_unknown_detected_udp(
        &ctx,
        &socket,
        UdpPacket {
            output_path: None,
            query_data: b"ping",
            src: &src,
            destination: &destination,
            len: 4,
        },
        "synthetic",
    )
    .await;
    collector.flush_all_pending().await;

    let mut buf = [0u8; 16];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        receiver.recv_from(&mut buf),
    )
    .await
    .expect("unknown detected response timed out")
    .expect("receive unknown detected response");
    assert_eq!(&buf[..len], b"OK\n");
    assert_eq!(flow_bytes(&ctx, src, &destination), (4, 3));

    let content = tokio::fs::read_to_string(&nbi_path)
        .await
        .expect("NBI JSONL should be written");
    let event: nettrap_core::nbi::NetworkBehaviorIndicator =
        serde_json::from_str(content.lines().next().expect("NBI line"))
            .expect("NBI line should deserialize");
    assert_eq!(event.protocol, "RAW");
    assert_eq!(
        event
            .indicators
            .get("detected_protocol")
            .map(String::as_str),
        Some("synthetic")
    );
    let _ = tokio::fs::remove_file(nbi_path).await;
}

#[tokio::test]
async fn explicit_udp_daytime_responds_on_custom_port_without_router_taste() {
    let bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .expect("bind UDP listener socket");
    let listener_port = socket.local_addr().expect("listener addr").port();
    let receiver = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .expect("bind UDP receiver");
    let src = receiver.local_addr().expect("receiver addr");
    let router = Arc::new(nettrap_proxy::ProtocolRouter::new());
    let ctx = udp_test_context_named("daytime-custom", listener_port, router, None);
    let destination = SessionDestination::new_unchecked(bind_ip.to_string(), listener_port);
    let dns_handler = nettrap_proto_dns::handler::DnsHandler::new();
    let tftp_handler = nettrap_proto_tftp::TftpHandler::new();
    let chargen_handler = nettrap_proto_chargen::ChargenHandler::new();
    let handlers = UdpHandlers {
        dns: &dns_handler,
        tftp: &tftp_handler,
        chargen: &chargen_handler,
    };
    let transfers = Arc::new(Mutex::new(HashMap::new()));
    let protocol = explicit_udp_protocol_name(ctx.name()).expect("explicit UDP protocol");

    handle_explicit_udp_protocol(
        &ctx,
        &socket,
        &handlers,
        &transfers,
        UdpPacket {
            output_path: None,
            query_data: b"",
            src: &src,
            destination: &destination,
            len: 0,
        },
        protocol,
    )
    .await;

    let mut buf = [0u8; 128];
    let (len, peer) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        receiver.recv_from(&mut buf),
    )
    .await
    .expect("daytime response timed out")
    .expect("receive daytime response");
    assert!(len > 0);
    assert_eq!(peer, socket.local_addr().expect("listener addr"));
}

#[cfg(unix)]
#[tokio::test]
async fn recv_udp_packet_resolves_wildcard_destination_ip() {
    let bind_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let socket = UdpSocket::bind(SocketAddr::new(bind_addr, 0))
        .await
        .expect("bind wildcard UDP socket");
    configure_udp_destination_capture(&socket, bind_addr).expect("enable UDP destination capture");

    let listener_port = socket.local_addr().expect("listener addr").port();
    let sender = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("bind sender");
    sender
        .send_to(
            b"ping",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listener_port),
        )
        .await
        .expect("send UDP datagram");

    let mut buf = [0u8; 32];
    let capture = configure_udp_destination_capture(&socket, bind_addr)
        .expect("enable UDP destination capture");
    let (len, src, destination) = recv_udp_packet(&socket, &capture, &mut buf, listener_port)
        .await
        .expect("recv UDP datagram with destination");

    assert_eq!(&buf[..len], b"ping");
    assert_eq!(src.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(
        destination,
        Some(SessionDestination::new_unchecked(
            Ipv4Addr::LOCALHOST.to_string(),
            listener_port
        ))
    );
}

#[tokio::test]
async fn udp_listener_keeps_session_and_flow_alive_after_single_datagram() {
    let tracker = Arc::new(SessionTracker::new());
    let flow_manager = Arc::new(nettrap_flow::FlowManager::default());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .expect("bind UDP listener socket");
    let listener_port = socket.local_addr().expect("listener addr").port();

    let ctx = ListenerContext::builder()
        .name("raw")
        .port(listener_port)
        .build(
            ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                .expect("empty host rules should compile"),
            ListenerRuntime::new(ListenerRuntimeResources {
                ca: None,
                router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                attribution: None,
                attribution_timeout: std::time::Duration::from_millis(5000),
                pcap_writer: None,
                nbi_collector: Arc::new(
                    crate::nbi::NbiCollector::new(None).expect("collector should build"),
                ),
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::clone(&flow_manager),
            }),
        )
        .expect("listener context should build");

    let listener = tokio::spawn(async move { run_udp_listener(ctx, socket, bind_ip, None).await });
    let sender = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
        .await
        .expect("bind sender");
    let src = sender.local_addr().expect("sender addr");
    sender
        .send_to(b"hello", SocketAddr::new(bind_ip, listener_port))
        .await
        .expect("send UDP datagram");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let destination = SessionDestination::new_unchecked(bind_ip.to_string(), listener_port);
    let flow_key =
        nettrap_core::prelude::FlowKey::from_five_tuple(&nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            bind_ip,
            src.port(),
            listener_port,
            nettrap_core::prelude::Protocol::Udp,
        ));

    assert_eq!(tracker.active_count(), 1);
    assert_eq!(
        tracker.get_destination_for_port(&src, "UDP", listener_port),
        Some(destination)
    );
    assert!(flow_manager.get(&flow_key).is_some());

    listener.abort();
    let _ = listener.await;
}
