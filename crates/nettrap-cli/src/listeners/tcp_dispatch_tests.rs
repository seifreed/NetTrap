use std::sync::Arc;

use super::*;
use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
use crate::process_filter::ProcessFilter;
use crate::session::{PortForwardTable, SessionTracker};

fn test_session_handlers() -> SessionHandlers {
    SessionHandlers {
        smtp: nettrap_proto_smtp::SmtpHandler::new().with_now(crate::faketime::fake_now),
        ftp: nettrap_proto_ftp::FtpHandler::new(),
        pop3: nettrap_proto_pop3::Pop3Handler::new().with_now(crate::faketime::fake_now),
        irc: nettrap_proto_irc::IrcHandler::new(),
        imap: crate::handler_registry::ImapHandler::new(),
        telnet: nettrap_proto_telnet::TelnetHandler::new().with_now(crate::faketime::fake_now),
        smb: nettrap_proto_smb::SmbHandler::new(),
        rdp: nettrap_proto_rdp::RdpHandler::new(),
        redis: nettrap_proto_redis::RedisHandler::new(),
        mysql: nettrap_proto_mysql::MysqlHandler::new(),
        ldap: nettrap_proto_ldap::LdapHandler::new(),
        socks: nettrap_proto_socks::SocksHandler::new(),
        memcached: nettrap_proto_memcached::MemcachedHandler::new()
            .with_now(crate::faketime::fake_now),
        mqtt: nettrap_proto_mqtt::MqttHandler::new(),
        postgres: nettrap_proto_postgres::PostgresHandler::new(),
        chargen: nettrap_proto_chargen::ChargenHandler::new(),
    }
}

fn test_listener_context(name: &str, port: u16) -> Arc<ListenerContext> {
    test_listener_context_with_dirs(name, port, None, None)
}

fn test_listener_context_with_smtp_dir(
    name: &str,
    port: u16,
    smtp_dir: Option<std::path::PathBuf>,
) -> Arc<ListenerContext> {
    test_listener_context_with_dirs(name, port, smtp_dir, None)
}

fn test_listener_context_with_nbi_path(
    name: &str,
    port: u16,
    nbi_path: Option<std::path::PathBuf>,
) -> Arc<ListenerContext> {
    test_listener_context_with_dirs(name, port, None, nbi_path)
}

fn test_listener_context_with_dirs(
    name: &str,
    port: u16,
    smtp_dir: Option<std::path::PathBuf>,
    nbi_path: Option<std::path::PathBuf>,
) -> Arc<ListenerContext> {
    Arc::new(
        ListenerContext::builder()
            .name(name)
            .port(port)
            .smtp_dir(smtp_dir)
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
                        crate::nbi::NbiCollector::new(nbi_path).expect("collector should build"),
                    ),
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build"),
    )
}

#[test]
fn frame_dns_tcp_response_rejects_payloads_that_do_not_fit_length_prefix() {
    let response = vec![0u8; usize::from(u16::MAX) + 1];

    assert!(frame_dns_tcp_response(&response).is_none());
}

#[test]
fn frame_dns_tcp_response_allows_maximum_length_payload() {
    let response = vec![0x41u8; usize::from(u16::MAX)];
    let framed = frame_dns_tcp_response(&response).expect("maximum DNS TCP payload fits");

    assert_eq!(&framed[..2], &u16::MAX.to_be_bytes());
    assert_eq!(&framed[2..], response.as_slice());
}

#[tokio::test]
async fn handle_ssh_uses_configured_banner_when_first_response_includes_banner() {
    let ctx = Arc::new(
        ListenerContext::builder()
            .name("ssh")
            .port(22)
            .banner(Some("SSH-2.0-CustomSSH_1.0".to_string()))
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
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build"),
    );
    let peer: std::net::SocketAddr = "127.0.0.1:53000".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.22", 22);
    let mut first_packet = true;

    let response = handle_ssh(
        &ctx,
        b"SSH-2.0-TestClient\r\n",
        &peer,
        &destination,
        None,
        &mut first_packet,
        false,
    )
    .await;

    assert!(response.starts_with(b"SSH-2.0-CustomSSH_1.0\r\n"));
    assert!(!first_packet);
}

#[tokio::test]
async fn handle_ssh_rejects_invalid_configured_banner_without_defaulting() {
    let ctx = Arc::new(
        ListenerContext::builder()
            .name("ssh")
            .port(22)
            .banner(Some("SSH-2.0-Custom\r\nSSH-2.0-injected".to_string()))
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
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build"),
    );
    let peer: std::net::SocketAddr = "127.0.0.1:53000".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.22", 22);
    let mut first_packet = true;

    let response = handle_ssh(
        &ctx,
        b"SSH-2.0-TestClient\r\n",
        &peer,
        &destination,
        None,
        &mut first_packet,
        false,
    )
    .await;

    assert!(response.is_empty());
    assert!(!first_packet);
}

#[tokio::test]
async fn handle_dns_tcp_returns_error_for_malformed_dns_payloads() {
    let ctx = Arc::new(
        ListenerContext::builder()
            .name("dns")
            .port(53)
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
                    session_tracker: Arc::new(SessionTracker::new()),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build"),
    );
    let peer: std::net::SocketAddr = "127.0.0.1:53000".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.7", 53);
    let data = [0x00, 0x01, 0xff];

    let err = handle_dns_tcp(&ctx, &data, &peer, &destination, None)
        .await
        .expect_err("malformed DNS payload should fail");

    assert!(
        err.to_string().contains("DNS TCP error"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn handle_smtp_named_rejects_invalid_utf8_commands() {
    let ctx = test_listener_context("smtp", 25);
    let peer: std::net::SocketAddr = "127.0.0.1:53000".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 25);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();
    let mut session = TcpSessionState::default();

    let err = handle_smtp_named(request, b"\xff\xfe\xfd", &handlers, &mut session)
        .await
        .expect_err("invalid UTF-8 should fail");

    assert!(err.to_string().contains("invalid UTF-8"));
}

#[tokio::test]
async fn handle_smtp_named_accepts_binary_data_frames() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "nettrap-smtp-named-binary-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    let ctx = test_listener_context_with_smtp_dir("smtp", 25, Some(root.clone()));
    let peer: std::net::SocketAddr = "127.0.0.1:53000".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 25);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();
    let mut session = TcpSessionState {
        smtp_data_mode: true,
        ..Default::default()
    };
    let data = b"Subject: binary\r\n\r\nbody \xff\xfe\r\n.\r\n";

    let response = handle_smtp_named(request, data, &handlers, &mut session)
        .await
        .expect("binary SMTP DATA should be queued");

    assert!(response.starts_with(b"250 OK Queued as "));
    assert!(!session.smtp_data_mode);
    let saved = std::fs::read_dir(&root)
        .expect("read mailbox dir")
        .next()
        .expect("saved email should exist")
        .expect("mailbox entry");
    let saved_bytes = std::fs::read(saved.path()).expect("saved email should be readable");
    assert_eq!(saved_bytes, b"Subject: binary\r\n\r\nbody \xff\xfe\r\n");

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn handle_ftp_named_rejects_invalid_utf8_commands() {
    let ctx = test_listener_context("ftp", 21);
    let peer: std::net::SocketAddr = "127.0.0.1:53001".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 21);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();
    let mut session = TcpSessionState::default();

    let response = handle_ftp_named(request, b"\xff\xfe\xfd", &handlers, &mut session).await;

    assert!(response.starts_with(b"502"));
}

#[tokio::test]
async fn handle_ftp_named_rejects_unicode_whitespace_padding() {
    let ctx = test_listener_context("ftp", 21);
    let peer: std::net::SocketAddr = "127.0.0.1:53011".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 21);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();
    let mut session = TcpSessionState::default();

    let response = handle_ftp_named(
        request,
        " QUIT\u{00a0}\r\n".as_bytes(),
        &handlers,
        &mut session,
    )
    .await;

    assert!(response.starts_with(b"502"));
}

#[tokio::test]
async fn handle_ftp_named_rejects_bare_lf_terminated_commands() {
    let ctx = test_listener_context("ftp", 21);
    let peer: std::net::SocketAddr = "127.0.0.1:53011".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 21);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();
    let mut session = TcpSessionState::default();

    let response = handle_ftp_named(request, b"QUIT\n", &handlers, &mut session).await;

    assert!(response.starts_with(b"502"));
}

#[tokio::test]
async fn handle_pop3_named_rejects_unicode_whitespace_padding() {
    let ctx = test_listener_context("pop3", 110);
    let peer: std::net::SocketAddr = "127.0.0.1:53002".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 110);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();

    let response = handle_pop3_named(request, "QUIT\u{00a0}\r\n".as_bytes(), &handlers).await;

    assert!(String::from_utf8_lossy(&response).contains("Invalid argument"));
}

#[tokio::test]
async fn handle_pop3_named_rejects_bare_lf_terminated_commands() {
    let ctx = test_listener_context("pop3", 110);
    let peer: std::net::SocketAddr = "127.0.0.1:53002".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 110);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();

    let response = handle_pop3_named(request, b"STAT\n", &handlers).await;

    assert_eq!(response, b"-ERR Invalid argument\r\n");
}

#[tokio::test]
async fn handle_mqtt_named_preserves_protocol_version_for_session() {
    let ctx = test_listener_context("mqtt", 1883);
    let peer: std::net::SocketAddr = "127.0.0.1:53003".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 1883);
    let handlers = test_session_handlers();
    let connect = [
        0x10, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
    ];

    let response = handle_mqtt_named(
        TcpRequestContext {
            ctx: &ctx,
            peer: &peer,
            output_path: None,
            destination: &destination,
            control_local_addr: None,
            http_over_tls: false,
            ssh_banner_sent: false,
        },
        &connect,
        &handlers,
    )
    .await;
    assert_eq!(response, vec![0x20, 0x02, 0x00, 0x00]);

    let response = handle_mqtt_named(
        TcpRequestContext {
            ctx: &ctx,
            peer: &peer,
            output_path: None,
            destination: &destination,
            control_local_addr: None,
            http_over_tls: false,
            ssh_banner_sent: false,
        },
        &[0x82, 0x06, 0x12, 0x34, 0x00, 0x01, b'a', 0x00],
        &handlers,
    )
    .await;

    assert_eq!(response, vec![0x90, 0x03, 0x12, 0x34, 0x00]);
}

#[tokio::test]
async fn handle_imap_named_rejects_bare_lf_terminated_commands() {
    let ctx = test_listener_context("imap", 143);
    let peer: std::net::SocketAddr = "127.0.0.1:53002".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 143);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();

    let response = handle_imap_named(request, b"A001 CAPABILITY\n", &handlers).await;

    assert_eq!(response, b"* BAD Invalid IMAP command\r\n");
}

#[tokio::test]
async fn handle_finger_named_rejects_invalid_utf8_without_listing_users() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "nettrap-tcp-finger-nbi-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    let nbi_path = root.join("events.jsonl");
    let ctx = test_listener_context_with_nbi_path("finger", 79, Some(nbi_path.clone()));
    let peer: std::net::SocketAddr = "127.0.0.1:53002".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 79);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };

    let response = handle_finger_named(request, b"\xff\xfe\xfd").await;
    ctx.runtime.nbi_collector.flush_all_pending().await;
    ctx.runtime.nbi_collector.stop_background_tasks();
    let response = String::from_utf8(response).expect("finger response is utf-8");

    assert_eq!(response, "No such user.\r\n");
    assert!(!response.contains("INVALID-PORT"));
    let events = crate::output::load_nbis_from_jsonl(&nbi_path).expect("load NBI JSONL");
    let event = events.first().expect("finger event should be recorded");
    assert_eq!(
        event.indicators.get("data_length").map(String::as_str),
        Some("3")
    );
    assert_eq!(
        event
            .indicators
            .get("detected_protocol")
            .map(String::as_str),
        Some("finger")
    );

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn handle_finger_named_rejects_bare_lf_terminated_user_queries() {
    let ctx = test_listener_context("finger", 79);
    let peer: std::net::SocketAddr = "127.0.0.1:53002".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 79);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };

    let response = handle_finger_named(request, b"root\n").await;
    let response = String::from_utf8(response).expect("finger response is utf-8");

    assert_eq!(response, "No such user.\r\n");
    assert!(!response.contains("Login: root\r\n"));
}

#[tokio::test]
async fn handle_ident_named_reports_invalid_utf8_queries() {
    let ctx = test_listener_context("ident", 113);
    let peer: std::net::SocketAddr = "127.0.0.1:53003".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 113);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };

    let response = handle_ident_named(request, b"\xff\xfe\xfd").await;

    assert_eq!(response, b" : ERROR : INVALID-PORT\r\n");
}

#[tokio::test]
async fn handle_ident_named_rejects_bare_lf_terminated_queries() {
    let ctx = test_listener_context("ident", 113);
    let peer: std::net::SocketAddr = "127.0.0.1:53003".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 113);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };

    let response = handle_ident_named(request, b"6191, 23\n").await;

    assert_eq!(response, b" : ERROR : INVALID-PORT\r\n");
}

#[tokio::test]
async fn handle_syslogrecv_named_records_parsed_facility_and_severity() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "nettrap-tcp-syslog-nbi-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    let nbi_path = root.join("events.jsonl");
    let ctx = test_listener_context_with_nbi_path("syslogrecv", 514, Some(nbi_path.clone()));
    let peer: std::net::SocketAddr = "127.0.0.1:53005".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 514);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };

    let response = handle_syslogrecv_named(request, b"<13>message").await;
    ctx.runtime.nbi_collector.flush_all_pending().await;
    ctx.runtime.nbi_collector.stop_background_tasks();

    assert!(response.is_empty());
    let events = crate::output::load_nbis_from_jsonl(&nbi_path).expect("load NBI JSONL");
    let event = events.first().expect("syslog event should be recorded");
    assert_eq!(
        event.indicators.get("facility").map(String::as_str),
        Some("user")
    );
    assert_eq!(
        event.indicators.get("severity").map(String::as_str),
        Some("notice")
    );
    assert_eq!(event.indicators.get("hexdump"), None);
    assert_eq!(
        event
            .indicators
            .get("detected_protocol")
            .map(String::as_str),
        Some("syslogrecv")
    );

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn handle_telnet_named_rejects_invalid_utf8_commands() {
    let ctx = test_listener_context("telnet", 23);
    let peer: std::net::SocketAddr = "127.0.0.1:53004".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 23);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();
    let mut session = TcpSessionState::default();

    let response = handle_telnet_named(request, b"\xff\xfe\xfd", &handlers, &mut session).await;

    assert!(response.is_empty());
}

#[tokio::test]
async fn handle_telnet_named_redacts_credentials_in_event_log() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-tcp-telnet-log-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).expect("create temp root");
    let output_path = root.join("events.jsonl");
    let ctx = test_listener_context("telnet", 23);
    let peer: std::net::SocketAddr = "127.0.0.1:53004".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 23);
    let handlers = test_session_handlers();
    let mut session = TcpSessionState::default();

    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: Some(&output_path),
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let _ = handle_telnet_named(request, b"alice\r\n", &handlers, &mut session).await;

    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: Some(&output_path),
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let _ = handle_telnet_named(request, b"hunter2\r\n", &handlers, &mut session).await;

    let log = std::fs::read_to_string(&output_path).expect("event log should be readable");
    assert!(!log.contains("alice"));
    assert!(!log.contains("hunter2"));
    assert!(
        log.lines()
            .filter(|line| line.contains("telnet_username") || line.contains("telnet_credentials"))
            .all(|line| line.contains(REDACTED_TELNET_AUTH_FIELD))
    );

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn handle_telnet_named_rejects_bare_lf_terminated_commands() {
    let ctx = test_listener_context("telnet", 23);
    let peer: std::net::SocketAddr = "127.0.0.1:53004".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 23);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();
    let mut session = TcpSessionState {
        telnet_state: nettrap_proto_telnet::TelnetState::Shell,
        ..TcpSessionState::default()
    };

    let response = handle_telnet_named(request, b"id\n", &handlers, &mut session).await;

    assert!(response.is_empty());
    assert_eq!(
        session.telnet_state,
        nettrap_proto_telnet::TelnetState::Shell
    );
}

#[tokio::test]
async fn handle_telnet_named_rejects_bare_cr_terminated_commands() {
    let ctx = test_listener_context("telnet", 23);
    let peer: std::net::SocketAddr = "127.0.0.1:53004".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 23);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();
    let mut session = TcpSessionState {
        telnet_state: nettrap_proto_telnet::TelnetState::Shell,
        ..TcpSessionState::default()
    };

    let response = handle_telnet_named(request, b"id\r", &handlers, &mut session).await;

    assert!(response.is_empty());
    assert_eq!(
        session.telnet_state,
        nettrap_proto_telnet::TelnetState::Shell
    );
}

#[tokio::test]
async fn handle_telnet_named_rejects_embedded_crlf_in_commands() {
    let ctx = test_listener_context("telnet", 23);
    let peer: std::net::SocketAddr = "127.0.0.1:53004".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 23);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();
    let mut session = TcpSessionState {
        telnet_state: nettrap_proto_telnet::TelnetState::Shell,
        ..TcpSessionState::default()
    };

    let response = handle_telnet_named(request, b"id\r\nhelp\r\n", &handlers, &mut session).await;

    assert!(response.is_empty());
    assert_eq!(
        session.telnet_state,
        nettrap_proto_telnet::TelnetState::Shell
    );
}

#[tokio::test]
async fn handle_irc_named_rejects_unicode_whitespace_padding() {
    let ctx = test_listener_context("irc", 6667);
    let peer: std::net::SocketAddr = "127.0.0.1:53005".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 6667);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();
    let mut session = TcpSessionState::default();

    let response = handle_irc_named(
        request,
        "QUIT\u{00a0}\r\n".as_bytes(),
        &handlers,
        &mut session,
    )
    .await;

    assert!(String::from_utf8_lossy(&response).contains("Unknown command"));
}

#[tokio::test]
async fn handle_irc_named_rejects_embedded_nul_bytes() {
    let ctx = test_listener_context("irc", 6667);
    let peer: std::net::SocketAddr = "127.0.0.1:53005".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 6667);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();
    let mut session = TcpSessionState::default();

    let response = handle_irc_named(request, b"QUIT\0now\r\n", &handlers, &mut session).await;

    assert_eq!(response, b":nettrap 421 * INVALID :Unknown command\r\n");
}

#[tokio::test]
async fn handle_irc_named_rejects_bare_lf_terminated_commands() {
    let ctx = test_listener_context("irc", 6667);
    let peer: std::net::SocketAddr = "127.0.0.1:53005".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 6667);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();
    let mut session = TcpSessionState::default();

    let response = handle_irc_named(request, b"QUIT\n", &handlers, &mut session).await;

    assert_eq!(response, b":nettrap 421 * INVALID :Unknown command\r\n");
}

#[tokio::test]
async fn handle_irc_named_rejects_embedded_crlf_in_commands() {
    let ctx = test_listener_context("irc", 6667);
    let peer: std::net::SocketAddr = "127.0.0.1:53005".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 6667);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();
    let mut session = TcpSessionState::default();

    let response =
        handle_irc_named(request, b"QUIT\r\nNICK test\r\n", &handlers, &mut session).await;

    assert_eq!(response, b":nettrap 421 * INVALID :Unknown command\r\n");
}

#[tokio::test]
async fn handle_irc_named_rejects_unicode_whitespace_in_nick() {
    let ctx = test_listener_context("irc", 6667);
    let peer: std::net::SocketAddr = "127.0.0.1:53015".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 6667);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();
    let mut session = TcpSessionState::default();

    let response = handle_irc_named(
        request,
        "NICK ro\u{00a0}ot\r\n".as_bytes(),
        &handlers,
        &mut session,
    )
    .await;

    assert!(response.is_empty());
    assert_eq!(session.irc_nick, "unknown");
}

#[tokio::test]
async fn handle_irc_named_rejects_ascii_padded_nick() {
    let ctx = test_listener_context("irc", 6667);
    let peer: std::net::SocketAddr = "127.0.0.1:53016".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 6667);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();
    let mut session = TcpSessionState::default();

    let response = handle_irc_named(
        request,
        "NICK  root \r\n".as_bytes(),
        &handlers,
        &mut session,
    )
    .await;

    assert!(response.is_empty());
    assert_eq!(session.irc_nick, "unknown");
}

#[tokio::test]
async fn handle_chargen_named_advances_offset_across_calls() {
    let ctx = test_listener_context("chargen", 19);
    let peer: std::net::SocketAddr = "127.0.0.1:53030".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 19);
    let request = TcpRequestContext {
        ctx: &ctx,
        peer: &peer,
        output_path: None,
        destination: &destination,
        control_local_addr: None,
        http_over_tls: false,
        ssh_banner_sent: false,
    };
    let handlers = test_session_handlers();

    let first = handle_chargen_named(request, b"", &handlers).await;
    let second = handle_chargen_named(request, b"", &handlers).await;

    assert_ne!(first, second);
    assert_eq!(first.len(), 6 * 74);
    assert_eq!(second.len(), 6 * 74);
}

#[tokio::test]
async fn dispatch_named_tcp_protocol_accepts_tls_service_aliases() {
    let handlers = test_session_handlers();
    let mut session = TcpSessionState::default();

    let ftps_ctx = test_listener_context("ftps", 990);
    let ftps_peer: std::net::SocketAddr = "127.0.0.1:53020".parse().expect("peer");
    let ftps_destination = SessionDestination::new_unchecked("10.0.0.5", 990);
    let ftps_request = TcpRequestContext {
        ctx: &ftps_ctx,
        peer: &ftps_peer,
        output_path: None,
        destination: &ftps_destination,
        control_local_addr: None,
        http_over_tls: true,
        ssh_banner_sent: false,
    };
    assert!(
        dispatch_named_tcp_protocol(
            ftps_request,
            "ftps",
            b"USER anonymous\r\n",
            &handlers,
            None,
            &mut session
        )
        .await
        .expect("ftps dispatch should succeed")
        .is_some()
    );

    let imaps_ctx = test_listener_context("imaps", 993);
    let imaps_peer: std::net::SocketAddr = "127.0.0.1:53024".parse().expect("peer");
    let imaps_destination = SessionDestination::new_unchecked("10.0.0.5", 993);
    let imaps_request = TcpRequestContext {
        ctx: &imaps_ctx,
        peer: &imaps_peer,
        output_path: None,
        destination: &imaps_destination,
        control_local_addr: None,
        http_over_tls: true,
        ssh_banner_sent: false,
    };
    assert!(
        dispatch_named_tcp_protocol(
            imaps_request,
            "imaps",
            b"A001 CAPABILITY\r\n",
            &handlers,
            None,
            &mut session
        )
        .await
        .expect("imaps dispatch should succeed")
        .is_some()
    );

    let ldaps_ctx = test_listener_context("ldaps", 636);
    let ldaps_peer: std::net::SocketAddr = "127.0.0.1:53022".parse().expect("peer");
    let ldaps_destination = SessionDestination::new_unchecked("10.0.0.5", 636);
    let ldaps_request = TcpRequestContext {
        ctx: &ldaps_ctx,
        peer: &ldaps_peer,
        output_path: None,
        destination: &ldaps_destination,
        control_local_addr: None,
        http_over_tls: true,
        ssh_banner_sent: false,
    };
    assert!(
        dispatch_named_tcp_protocol(
            ldaps_request,
            "ldaps",
            b"cn=admin,dc=example,dc=test",
            &handlers,
            None,
            &mut session
        )
        .await
        .expect("ldaps dispatch should succeed")
        .is_some()
    );

    let ssl_ctx = test_listener_context("ssl", 443);
    let ssl_peer: std::net::SocketAddr = "127.0.0.1:53023".parse().expect("peer");
    let ssl_destination = SessionDestination::new_unchecked("10.0.0.5", 443);
    let ssl_request = TcpRequestContext {
        ctx: &ssl_ctx,
        peer: &ssl_peer,
        output_path: None,
        destination: &ssl_destination,
        control_local_addr: None,
        http_over_tls: true,
        ssh_banner_sent: false,
    };
    assert!(
        dispatch_named_tcp_protocol(
            ssl_request,
            "ssl",
            b"\x16\x03\x03\x00\x2a",
            &handlers,
            None,
            &mut session
        )
        .await
        .expect("ssl dispatch should succeed")
        .is_some()
    );

    let telnets_ctx = test_listener_context("telnets", 992);
    let telnets_peer: std::net::SocketAddr = "127.0.0.1:53021".parse().expect("peer");
    let telnets_destination = SessionDestination::new_unchecked("10.0.0.5", 992);
    let telnets_request = TcpRequestContext {
        ctx: &telnets_ctx,
        peer: &telnets_peer,
        output_path: None,
        destination: &telnets_destination,
        control_local_addr: None,
        http_over_tls: true,
        ssh_banner_sent: false,
    };
    assert!(
        dispatch_named_tcp_protocol(
            telnets_request,
            "telnets",
            b"QUIT\r\n",
            &handlers,
            None,
            &mut session
        )
        .await
        .expect("telnets dispatch should succeed")
        .is_some()
    );
}

#[test]
fn telnet_command_closes_session_uses_normalized_command() {
    assert!(telnet_command_closes_session("exit"));
    assert!(telnet_command_closes_session("quit\r\n"));
    assert!(telnet_command_closes_session("logout   "));
    assert!(!telnet_command_closes_session(" exit"));
    assert!(!telnet_command_closes_session(" exit \r\n"));
    assert!(!telnet_command_closes_session("\tquit\r\n"));
    assert!(!telnet_command_closes_session("exitnow"));
    assert!(!telnet_command_closes_session("quit now"));
    assert!(!telnet_command_closes_session("logout now"));
    assert!(!telnet_command_closes_session("quit\u{00a0}"));
    assert!(!telnet_command_closes_session("logout\u{00a0}now"));
    assert!(!telnet_command_closes_session("quit  now"));
}
