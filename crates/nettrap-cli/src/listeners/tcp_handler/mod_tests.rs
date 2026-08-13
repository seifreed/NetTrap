use super::super::tcp_ftp::{
    finish_ftp_passive_transfer, ftp_passive_response_host, handle_ftp_command,
    open_ftp_passive_data_socket, send_ftp_passive_data,
};
use super::*;
use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
use crate::process_filter::ProcessFilter;
use crate::session::{PortForwardTable, SessionTracker};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

fn expect_complete(result: TcpFrameResult) -> Vec<u8> {
    match result {
        TcpFrameResult::Complete(frame) => frame,
        other => panic!("expected complete frame, got {other:?}"),
    }
}

fn assert_incomplete(result: TcpFrameResult) {
    assert!(matches!(result, TcpFrameResult::Incomplete), "{result:?}");
}

fn expect_terminal_response(result: TcpFrameResult, status: &[u8]) -> Vec<u8> {
    match result {
        TcpFrameResult::Invalid {
            response: Some(response),
        }
        | TcpFrameResult::TooLarge {
            response: Some(response),
        } => {
            assert!(response.starts_with(status), "{:?}", response);
            response
        }
        other => panic!("expected terminal response, got {other:?}"),
    }
}

fn assert_terminal_without_response(result: TcpFrameResult) {
    assert!(
        matches!(
            result,
            TcpFrameResult::Invalid { response: None }
                | TcpFrameResult::TooLarge { response: None }
        ),
        "{result:?}"
    );
}

fn encode_mqtt_remaining_len(mut value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return out;
        }
    }
}

fn ctx_named(name: &str) -> Arc<ListenerContext> {
    use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
    use crate::process_filter::ProcessFilter;
    use crate::session::{PortForwardTable, SessionTracker};

    Arc::new(
        ListenerContext::builder()
            .name(name)
            .port(0)
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    attribution: None,
                    attribution_timeout: Duration::from_millis(5000),
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
    )
}

fn ctx_named_with_identity(
    name: &str,
    server_name: Option<&str>,
    banner: Option<&str>,
) -> Arc<ListenerContext> {
    use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
    use crate::process_filter::ProcessFilter;
    use crate::session::{PortForwardTable, SessionTracker};

    Arc::new(
        ListenerContext::builder()
            .name(name)
            .port(23)
            .server_name(server_name.map(str::to_string))
            .banner(banner.map(str::to_string))
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(ListenerRuntimeResources {
                    ca: None,
                    router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    attribution: None,
                    attribution_timeout: Duration::from_millis(5000),
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
    )
}

#[test]
fn explicit_protocol_listener_is_not_hijacked_by_ftp_detection() {
    let dest = SessionDestination::unknown(0);
    let pop3 = ctx_named("pop3");
    assert!(!should_handle_ftp_ordered(
        &pop3,
        "pop3",
        b"USER bob\r\n",
        &dest
    ));
    assert!(!should_handle_ftp_ordered(
        &pop3,
        "pop3",
        b"PASS secret\r\n",
        &dest
    ));

    let ftp = ctx_named("ftp");
    assert!(should_handle_ftp_ordered(
        &ftp,
        "ftp",
        b"USER bob\r\n",
        &dest
    ));

    let ftps = ctx_named("ftps");
    assert!(should_handle_ftp_ordered(
        &ftps,
        "ftps",
        b"USER bob\r\n",
        &dest
    ));
}

#[test]
fn dns_tcp_frame_waits_for_full_declared_payload() {
    let mut buffer = vec![0x00, 0x05, b'h', b'e'];
    assert!(extract_length_prefixed_frame(&mut buffer).is_none());

    buffer.extend_from_slice(b"llo");
    assert_eq!(
        extract_length_prefixed_frame(&mut buffer),
        Some(vec![0x00, 0x05, b'h', b'e', b'l', b'l', b'o'])
    );
    assert!(buffer.is_empty());
}

#[test]
fn http_frame_waits_for_full_content_length() {
    let mut buffer =
        b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhel".to_vec();
    assert_incomplete(extract_http_request(&mut buffer));

    buffer.extend_from_slice(b"lo");
    let request = expect_complete(extract_http_request(&mut buffer));
    assert_eq!(
        request,
        b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello"
    );
    assert!(buffer.is_empty());
}

#[test]
fn http_frame_accepts_request_without_headers() {
    for request in [
        b"GET / HTTP/1.0\r\n\r\n".as_slice(),
        b"GET /payload.exe HTTP/1.1\r\n\r\n".as_slice(),
    ] {
        let mut buffer = request.to_vec();
        let frame = expect_complete(extract_http_request(&mut buffer));
        assert_eq!(frame, request);
        assert!(buffer.is_empty());
    }
}

#[test]
fn http_frame_rejects_invalid_content_length() {
    for request in [
        b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: abc\r\n\r\nhello"
            .as_slice(),
        b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: +5\r\n\r\nhello"
            .as_slice(),
    ] {
        let mut buffer = request.to_vec();
        expect_terminal_response(
            extract_http_request(&mut buffer),
            b"HTTP/1.1 400 Bad Request",
        );
        assert!(buffer.is_empty());
    }
}

#[test]
fn http_frame_rejects_malformed_request_line() {
    for request in [
        b"garbage\r\n\r\n".as_slice(),
        b"GET\r\n\r\n".as_slice(),
        b"GET  HTTP/1.1\r\n\r\n".as_slice(),
        b"GET / HTTP/2.0\r\n\r\n".as_slice(),
    ] {
        let mut buffer = request.to_vec();
        expect_terminal_response(
            extract_http_request(&mut buffer),
            b"HTTP/1.1 400 Bad Request",
        );
        assert!(buffer.is_empty());
    }
}

#[test]
fn http_response_parser_rejects_malformed_requests_without_defaults() {
    assert!(parse_http_for_response(b"garbage\r\n\r\n").is_err());
    assert!(parse_http_for_response(b"GET / HTTP/1.1 extra\r\n\r\n").is_err());
    assert!(
            parse_http_for_response(
                b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\nContent-Length: 4\r\n\r\nhello"
            )
            .is_err()
        );

    let Some(parsed) = parse_http_for_response(
        b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello",
    )
    .expect("valid request") else {
        panic!("request should parse");
    };

    assert_eq!(parsed.method, "POST");
    assert_eq!(parsed.target, "/upload");
    assert_eq!(parsed.path, "/upload");
    assert_eq!(parsed.host, "example.test");
    assert_eq!(parsed.body, b"hello");
    assert!(parsed.has_body);

    let Some(parsed) =
        parse_http_for_response(b"GET /upload HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .expect("valid request")
    else {
        panic!("request should parse");
    };

    assert!(!parsed.has_body);

    let Some(parsed) =
        parse_http_for_response(b"GET /alpha/../gate?id=1 HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .expect("valid request with query")
    else {
        panic!("request should parse");
    };

    assert_eq!(parsed.target, "/alpha/../gate?id=1");
    assert_eq!(parsed.path, "/gate");
}

#[test]
fn add_sent_bytes_saturates_at_u64_max() {
    assert_eq!(add_sent_bytes(u64::MAX - 1, 8), u64::MAX);
    assert_eq!(add_sent_bytes(40, 2), 42);
}

#[test]
fn tcp_frame_closes_session_for_terminal_client_commands() {
    assert!(tcp_frame_closes_session("ftp", b"QUIT\r\n"));
    assert!(tcp_frame_closes_session("smtp", b"quit\r\n"));
    assert!(tcp_frame_closes_session("pop3s", b"QUIT\r\n"));
    assert!(tcp_frame_closes_session("irc", b"QUIT :bye\r\n"));
    assert!(tcp_frame_closes_session("mqtt", &[0xe0, 0x00]));
    assert!(tcp_frame_closes_session("mqtt", &[0xe0, 0x01, 0x00]));
    assert!(tcp_frame_closes_session("mqtt", &[0xe0, 0x02, 0x00, 0x00]));
    assert!(tcp_frame_closes_session("redis", b"QUIT\r\n"));
    assert!(tcp_frame_closes_session("redis", b"*1\r\n$4\r\nquit\r\n"));
    assert!(tcp_frame_closes_session("memcached", b"quit\r\n"));
    assert!(tcp_frame_closes_session(
        "memcached",
        &[
            0x80, 0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    ));
    assert!(tcp_frame_closes_session(
        "memcached",
        &[
            0x80, 0x17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    ));
    assert!(tcp_frame_closes_session("mysql", &[1, 0, 0, 0, 0x01]));
    assert!(tcp_frame_closes_session("postgres", &[b'X', 0, 0, 0, 4]));
    assert!(tcp_frame_closes_session(
        "ssh",
        &[
            0,
            0,
            0,
            24,
            10,
            nettrap_proto_ssh::SSH_MSG_DISCONNECT,
            0,
            0,
            0,
            11,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        ]
    ));
}

#[test]
fn tcp_frame_closes_session_ignores_nonterminal_or_invalid_commands() {
    assert!(!tcp_frame_closes_session("ftp", b"QUIT now\r\n"));
    assert!(!tcp_frame_closes_session("ftp", b"QUIT \r\n"));
    assert!(!tcp_frame_closes_session("smtp", b" QUIT\r\n"));
    assert!(!tcp_frame_closes_session("smtp", b"QUIT\t\r\n"));
    assert!(!tcp_frame_closes_session("pop3", b"NOOP\r\n"));
    assert!(!tcp_frame_closes_session("pop3", b"QUIT  \r\n"));
    assert!(!tcp_frame_closes_session(
        "redis",
        b"*2\r\n$4\r\nQUIT\r\n$3\r\nnow\r\n"
    ));
    assert!(!tcp_frame_closes_session("mqtt", &[0xc0, 0x00]));
    assert!(!tcp_frame_closes_session("mqtt", &[0xef, 0x00]));
    assert!(!tcp_frame_closes_session("mqtt", &[0xe0]));
    assert!(!tcp_frame_closes_session("mqtt", &[0xe0, 0x01]));
    assert!(!tcp_frame_closes_session("mqtt", &[0xe0, 0x01, 0xff]));
    assert!(!tcp_frame_closes_session(
        "mqtt",
        &[0xe0, 0x03, 0x00, 0x00, 0x00]
    ));
    assert!(!tcp_frame_closes_session("memcached", b"quit now\r\n"));
    assert!(!tcp_frame_closes_session("memcached", b"quit  \r\n"));
    assert!(!tcp_frame_closes_session("memcached", b"quit\t\r\n"));
    assert!(!tcp_frame_closes_session(
        "memcached",
        &[
            0x80, 0x07, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    ));
    assert!(!tcp_frame_closes_session("mysql", &[2, 0, 0, 0, 0x01, 0]));
    assert!(!tcp_frame_closes_session("mysql", &[1, 0, 0, 1, 0x01]));
    assert!(!tcp_frame_closes_session("mysql", &[1, 0, 0, 0, 0x03]));
    assert!(!tcp_frame_closes_session(
        "postgres",
        &[b'X', 0, 0, 0, 5, 0]
    ));
    assert!(!tcp_frame_closes_session("postgres", &[b'Q', 0, 0, 0, 4]));
    assert!(!tcp_frame_closes_session(
        "ssh",
        &[0, 0, 0, 6, 4, nettrap_proto_ssh::SSH_MSG_IGNORE, 0, 0, 0, 0]
    ));
    assert!(!tcp_frame_closes_session(
        "ssh",
        &[
            0,
            0,
            0,
            6,
            4,
            nettrap_proto_ssh::SSH_MSG_DISCONNECT,
            0,
            0,
            0,
            0
        ]
    ));
    assert!(!tcp_frame_closes_session(
        "ssh",
        &[
            0,
            0,
            0,
            7,
            4,
            nettrap_proto_ssh::SSH_MSG_DISCONNECT,
            0,
            0,
            0,
            0
        ]
    ));
}

#[test]
fn telnet_iac_only_input_has_no_login_value() {
    assert!(telnet_line_value(&[255, 251, 1]).is_none());
    assert!(telnet_line_value(&[b'i', b'd', 255]).is_none());
    assert!(telnet_line_value(&[b'i', b'd', 255, 253]).is_none());
    assert_eq!(telnet_line_value(b"\r\n").as_deref(), Some(""));
}

#[test]
fn telnet_line_value_rejects_control_and_unicode_whitespace() {
    assert!(telnet_line_value(b"root\0admin\r\n").is_none());
    assert!(telnet_line_value("root\u{2028}admin\r\n".as_bytes()).is_none());
}

#[test]
fn telnet_close_detection_uses_normalized_command() {
    assert!(telnet_command_closes_session("quit"));
    assert!(!telnet_command_closes_session(" exit \r\n"));
    assert!(!telnet_command_closes_session("\tquit\r\n"));
    assert!(!telnet_command_closes_session("logout now"));
    assert!(!telnet_command_closes_session("exitnow"));
    assert!(!telnet_command_closes_session(""));
}

#[test]
fn session_handlers_telnet_uses_configured_banner_hostname() {
    let ctx = ctx_named_with_identity("telnet", Some("router.example"), Some("ignored.example"));
    let handlers = SessionHandlers::from_ctx(&ctx).expect("handlers should initialize");
    let banner = handlers.telnet.get_login_banner();
    let text = String::from_utf8_lossy(&banner);

    assert!(text.contains("router.example login: "));
}

#[test]
fn session_handlers_imap_uses_configured_server_name() {
    let ctx = ctx_named_with_identity("imap", Some("mail.example"), Some("ignored.example"));
    let handlers = SessionHandlers::from_ctx(&ctx).expect("handlers should initialize");
    let banner = handlers.imap.get_welcome_banner();

    assert!(banner.contains("mail.example IMAP4rev1 Service Ready"));
    assert!(!banner.contains("ignored.example"));
}

#[test]
fn session_handlers_reject_invalid_telnet_hostname_override() {
    let ctx = ctx_named_with_identity("telnet", Some("bad><name"), Some("ignored.example"));
    let result = SessionHandlers::from_ctx(&ctx);

    assert!(
        result.is_err(),
        "handlers should reject invalid telnet hostname"
    );
    assert!(
        result
            .err()
            .map(|err| err.to_string())
            .unwrap_or_default()
            .contains("invalid Telnet hostname")
    );
}

#[test]
fn line_framing_leaves_partial_command_buffered() {
    let router = nettrap_proxy::ProtocolRouter::new();
    let mut buffer = b"USER anonymous\r\nPASS se".to_vec();

    let (_, first_frame) = next_tcp_frame_with_mode(&mut buffer, "ftp", 21, &router, false, false);
    let first = expect_complete(first_frame);
    assert_eq!(first, b"USER anonymous\r\n");
    assert_eq!(buffer, b"PASS se");

    buffer.extend_from_slice(b"cret\r\n");
    let (_, second_frame) = next_tcp_frame_with_mode(&mut buffer, "ftp", 21, &router, false, false);
    let second = expect_complete(second_frame);
    assert_eq!(second, b"PASS secret\r\n");
    assert!(buffer.is_empty());
}

#[test]
fn http_frame_rejects_unsupported_transfer_encoding() {
    for request in [
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip\r\n\r\nhello"
                .as_slice(),
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n"
                .as_slice(),
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked, gzip\r\n\r\n4\r\ntest\r\n0\r\n\r\n"
                .as_slice(),
        ] {
            let mut buffer = request.to_vec();
            expect_terminal_response(
                extract_http_request(&mut buffer),
                b"HTTP/1.1 400 Bad Request",
            );
            assert!(buffer.is_empty());
        }
}

#[test]
fn http_frame_rejects_oversized_headers_without_terminator() {
    let mut buffer = vec![b'A'; MAX_HTTP_HEADER_SIZE + 1];
    expect_terminal_response(
        extract_http_request(&mut buffer),
        b"HTTP/1.1 431 Request Header Fields Too Large",
    );
    assert!(buffer.is_empty());
}

#[test]
fn http_frame_accepts_headers_at_exact_size_limit() {
    let mut buffer = b"GET / HTTP/1.1\r\nX-Pad: ".to_vec();
    let pad_len = MAX_HTTP_HEADER_SIZE - buffer.len() - 2;
    buffer.extend(vec![b'a'; pad_len]);
    buffer.extend_from_slice(b"\r\n\r\n");

    let request = expect_complete(extract_http_request(&mut buffer));
    assert!(request.starts_with(b"GET / HTTP/1.1\r\nX-Pad: "));
    assert!(request.ends_with(b"\r\n\r\n"));
    assert!(buffer.is_empty());
}

#[test]
fn http_frame_rejects_oversized_content_length() {
    let mut buffer = format!(
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
        MAX_HTTP_REQUEST_SIZE + 1
    )
    .into_bytes();
    expect_terminal_response(
        extract_http_request(&mut buffer),
        b"HTTP/1.1 413 Payload Too Large",
    );
    assert!(buffer.is_empty());
}

#[test]
fn checkip_host_matching_is_exact_or_subdomain_only() {
    assert!(crate::custom_response::host_matches_pattern(
        "checkip.dyndns.org",
        "checkip.dyndns.org"
    ));
    assert!(crate::custom_response::host_matches_pattern(
        "v2.checkip.dyndns.org",
        "checkip.dyndns.org"
    ));
    assert!(!crate::custom_response::host_matches_pattern(
        "notcheckip.example.com",
        "checkip.dyndns.org"
    ));
}

#[test]
fn checkip_response_only_applies_to_supported_paths() {
    assert!(is_dyn_dns_checkip_request("checkip.dyndns.org", "/"));
    assert!(is_dyn_dns_checkip_request(
        "v2.checkip.dyndns.org",
        "/checkip"
    ));
    assert!(!is_dyn_dns_checkip_request("checkip.dyndns.org", "/foo"));
    assert!(!is_dyn_dns_checkip_request(
        "notcheckip.example.com",
        "/checkip"
    ));
}

#[test]
fn smtp_data_frame_waits_for_terminator() {
    let mut buffer = b"Subject: test\r\n\r\nbody".to_vec();
    assert_incomplete(extract_smtp_data_frame(&mut buffer));

    buffer.extend_from_slice(b"\r\n.\r\n");
    assert_eq!(
        expect_complete(extract_smtp_data_frame(&mut buffer)),
        b"Subject: test\r\n\r\nbody\r\n.\r\n".to_vec()
    );
    assert!(buffer.is_empty());
}

#[test]
fn smtp_data_frame_accepts_empty_message_terminator() {
    let mut buffer = b".\r\nNEXT".to_vec();
    assert_eq!(
        expect_complete(extract_smtp_data_frame(&mut buffer)),
        b".\r\n".to_vec()
    );
    assert_eq!(buffer, b"NEXT".to_vec());

    let mut bare_lf = b".\nNEXT".to_vec();
    assert_incomplete(extract_smtp_data_frame(&mut bare_lf));
    assert_eq!(bare_lf, b".\nNEXT".to_vec());
}

#[test]
fn smtp_data_frame_rejects_oversized_unterminated_body() {
    let mut buffer = vec![b'A'; MAX_SMTP_DATA_SIZE + 1];
    expect_terminal_response(
        extract_smtp_data_frame(&mut buffer),
        b"552 Message too large",
    );
    assert!(buffer.is_empty());
}

#[test]
fn line_frame_rejects_oversized_unterminated_line() {
    let mut buffer = vec![b'A'; MAX_LINE_FRAME_SIZE + 1];

    assert_terminal_without_response(extract_line_frame(&mut buffer));

    assert!(buffer.is_empty());
}

#[test]
fn http_chunked_frame_waits_for_complete_message() {
    let mut buffer =
        b"POST /chunk HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntes"
            .to_vec();
    assert_incomplete(extract_http_request(&mut buffer));

    buffer.extend_from_slice(b"t\r\n0\r\n\r\n");
    let request = expect_complete(extract_http_request(&mut buffer));
    assert_eq!(
            request,
            b"POST /chunk HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n"
        );
    assert!(buffer.is_empty());
}

#[test]
fn http_chunked_frame_rejects_signed_chunk_size() {
    let mut buffer =
            b"POST /chunk HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n+4\r\ntest\r\n0\r\n\r\n"
                .to_vec();

    expect_terminal_response(
        extract_http_request(&mut buffer),
        b"HTTP/1.1 400 Bad Request",
    );
    assert!(buffer.is_empty());
}

#[test]
fn http_chunked_frame_rejects_control_bytes_in_chunk_extensions() {
    let mut buffer =
            b"POST /chunk HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4;foo=\0bar\r\ntest\r\n0\r\n\r\n"
                .to_vec();

    expect_terminal_response(
        extract_http_request(&mut buffer),
        b"HTTP/1.1 400 Bad Request",
    );
    assert!(buffer.is_empty());
}

#[test]
fn http_chunked_parser_does_not_stop_on_embedded_zero_chunk_pattern() {
    let mut buffer = b"POST /chunk HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n\r\n0\r\n\r\n\r\n0\r\n\r\n"
            .to_vec();
    let request = expect_complete(extract_http_request(&mut buffer));
    assert_eq!(
            request,
            b"POST /chunk HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n\r\n0\r\n\r\n\r\n0\r\n\r\n"
        );
    assert!(buffer.is_empty());
}

struct PendingWriter;

impl AsyncWrite for PendingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn ftp_passive_data_write_times_out() {
    let mut writer = PendingWriter;
    let transfer = nettrap_proto_ftp::FtpDataTransfer {
        start_response: nettrap_proto_ftp::FtpResponse::new(150, "Opening data connection"),
        data: b"payload".to_vec(),
        complete_response: nettrap_proto_ftp::FtpResponse::new(226, "Transfer complete"),
        receive: false,
    };

    let err = send_ftp_passive_data(&mut writer, &transfer, Duration::from_millis(1))
        .await
        .expect_err("pending writer should time out");

    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
}

#[test]
fn mqtt_frame_waits_for_complete_packet() {
    let mut buffer = vec![0x10, 0x0c, 0x00, 0x04, b'M', b'Q'];
    assert_incomplete(extract_mqtt_frame(&mut buffer));

    buffer.extend_from_slice(&[b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00]);
    let frame = expect_complete(extract_mqtt_frame(&mut buffer));
    assert_eq!(
        frame,
        vec![
            0x10, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00
        ]
    );
    assert!(buffer.is_empty());
}

#[test]
fn mqtt_frame_rejects_oversized_remaining_length() {
    let mut buffer = vec![0x10];
    buffer.extend_from_slice(&encode_mqtt_remaining_len(MAX_MQTT_FRAME_SIZE + 1));

    assert_terminal_without_response(extract_mqtt_frame(&mut buffer));

    assert!(buffer.is_empty());
}

#[test]
fn mqtt_frame_rejects_overlong_remaining_length_encoding() {
    let mut buffer = vec![0xc0, 0x80, 0x00];

    assert_terminal_without_response(extract_mqtt_frame(&mut buffer));

    assert!(buffer.is_empty());
}

#[test]
fn mqtt_frame_rejects_overflowing_remaining_length_encoding() {
    let mut buffer = vec![0x10, 0x80, 0x80, 0x80, 0x80, 0x00];

    assert_terminal_without_response(extract_mqtt_frame(&mut buffer));

    assert!(buffer.is_empty());
}

#[test]
fn mqtt_frame_mode_uses_plain_port_and_router_detection() {
    let connect = vec![
        0x10, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
    ];

    let router = nettrap_proxy::ProtocolRouter::new();
    assert_eq!(
        tcp_frame_mode("tcp", &connect, 1883, &router, false, false),
        TcpFrameMode::Mqtt
    );

    let router = nettrap_proxy::ProtocolRouter::new();
    router.register("mqtt", Box::new(nettrap_proxy::MqttTaste), false);
    assert_eq!(
        tcp_frame_mode("tcp", &connect, 12345, &router, false, false),
        TcpFrameMode::Mqtt
    );
}

#[test]
fn mqtt_frame_mode_treats_8883_client_hello_as_tls() {
    let tls_client_hello = vec![0x16, 0x03, 0x03, 0x00, 0x2a];
    let router = nettrap_proxy::ProtocolRouter::new();
    router.register("mqtt", Box::new(nettrap_proxy::MqttTaste), false);

    assert_eq!(
        tcp_frame_mode("tcp", &tls_client_hello, 8883, &router, false, false),
        TcpFrameMode::Tls
    );
    assert_eq!(
        tcp_frame_mode("mqtt", &tls_client_hello, 8883, &router, false, false),
        TcpFrameMode::Tls
    );
}

#[test]
fn tls_frame_mode_treats_do_t_and_ldaps_ports_as_tls() {
    let router = nettrap_proxy::ProtocolRouter::new();
    let tls_client_hello = vec![0x16, 0x03, 0x03, 0x00, 0x2a];

    assert_eq!(
        tcp_frame_mode("tcp", &tls_client_hello, 853, &router, false, false),
        TcpFrameMode::Tls
    );
    assert_eq!(
        tcp_frame_mode("tcp", &tls_client_hello, 636, &router, false, false),
        TcpFrameMode::Tls
    );
    assert_eq!(
        tcp_frame_mode("tcp", b"\x30\x84", 636, &router, false, false),
        TcpFrameMode::Tls
    );
    assert_eq!(
        tcp_frame_mode("tcp", &tls_client_hello, 992, &router, false, false),
        TcpFrameMode::Tls
    );
    assert_eq!(
        tcp_frame_mode("tcp", &tls_client_hello, 993, &router, false, false),
        TcpFrameMode::Tls
    );
    assert_eq!(
        tcp_frame_mode("tcp", &tls_client_hello, 994, &router, false, false),
        TcpFrameMode::Tls
    );
    assert_eq!(
        tcp_frame_mode("tcp", &tls_client_hello, 990, &router, false, false),
        TcpFrameMode::Tls
    );
}

#[test]
fn tls_frame_dispatches_as_tls_even_for_cleartext_listener_name() {
    assert_eq!(
        tcp_dispatch_name_for_frame("mqtt", TcpFrameMode::Tls),
        "tls"
    );
    assert_eq!(
        tcp_dispatch_name_for_frame("smtp", TcpFrameMode::Tls),
        "tls"
    );
    assert_eq!(
        tcp_dispatch_name_for_frame("http", TcpFrameMode::Http),
        "http"
    );
}

#[test]
fn implicit_tls_ports_suppress_cleartext_banners() {
    assert!(is_implicit_tls_port(465));
    assert!(is_implicit_tls_port(853));
    assert!(is_implicit_tls_port(992));
    assert!(is_implicit_tls_port(993));
    assert!(is_implicit_tls_port(994));
    assert!(is_implicit_tls_port(6697));
    assert!(is_implicit_tls_port(990));
    assert!(is_implicit_tls_port(8883));
    assert!(!is_implicit_tls_port(25));
    assert!(!is_implicit_tls_port(1883));
}

#[test]
fn mysql_frame_waits_for_complete_packet() {
    let mut buffer = vec![0x03, 0x00, 0x00, 0x01, 0x03, b'S'];
    assert_eq!(extract_mysql_frame(&mut buffer), TcpFrameResult::Incomplete);

    buffer.push(0);
    let TcpFrameResult::Complete(frame) = extract_mysql_frame(&mut buffer) else {
        panic!("mysql packet should be complete");
    };
    assert_eq!(frame, vec![0x03, 0x00, 0x00, 0x01, 0x03, b'S', 0]);
    assert!(buffer.is_empty());
}

#[test]
fn mysql_frame_rejects_oversized_declared_length() {
    let mut buffer = vec![0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02];
    assert_eq!(
        extract_mysql_frame(&mut buffer),
        TcpFrameResult::TooLarge { response: None }
    );
    assert!(
        buffer.is_empty(),
        "oversized mysql frame must clear the connection buffer"
    );
}

fn mysql_packet(payload: &[u8], seq: u8) -> Vec<u8> {
    let mut p = vec![
        (payload.len() & 0xff) as u8,
        ((payload.len() >> 8) & 0xff) as u8,
        ((payload.len() >> 16) & 0xff) as u8,
        seq,
    ];
    p.extend_from_slice(payload);
    p
}

#[test]
fn is_mysql_ssl_request_classifies_correctly() {
    const CLIENT_SSL: u32 = 0x0000_0800;
    const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;

    let mut ssl = vec![0u8; 32];
    ssl[..4].copy_from_slice(&(CLIENT_PROTOCOL_41 | CLIENT_SSL).to_le_bytes());
    assert!(is_mysql_ssl_request(&mysql_packet(&ssl, 1)));

    assert!(is_mysql_ssl_request(&mysql_packet(
        &CLIENT_SSL.to_le_bytes(),
        1
    )));

    let mut full = vec![0u8; 32];
    full[..4].copy_from_slice(&(CLIENT_PROTOCOL_41 | CLIENT_SSL).to_le_bytes());
    full.extend_from_slice(b"root\0");
    assert!(!is_mysql_ssl_request(&mysql_packet(&full, 1)));

    let mut malformed_ssl = vec![0u8; 32];
    malformed_ssl[..4].copy_from_slice(&(CLIENT_PROTOCOL_41 | CLIENT_SSL).to_le_bytes());
    malformed_ssl[13] = 0x01;
    assert!(!is_mysql_ssl_request(&mysql_packet(&malformed_ssl, 1)));

    let mut short_malformed = vec![0u8; 16];
    short_malformed[..4].copy_from_slice(&(CLIENT_PROTOCOL_41 | CLIENT_SSL).to_le_bytes());
    assert!(!is_mysql_ssl_request(&mysql_packet(&short_malformed, 1)));

    assert!(!is_mysql_ssl_request(&mysql_packet(&ssl, 0)));

    let mut nossl = vec![0u8; 32];
    nossl[..4].copy_from_slice(&CLIENT_PROTOCOL_41.to_le_bytes());
    assert!(!is_mysql_ssl_request(&mysql_packet(&nossl, 1)));

    let mut bad = mysql_packet(&ssl, 1);
    bad[0] = 0xff;
    assert!(!is_mysql_ssl_request(&bad));

    assert!(!is_mysql_ssl_request(&[0x04, 0x00, 0x00, 0x01]));
}

#[test]
fn postgres_frames_wait_for_startup_and_typed_messages() {
    let mut startup = vec![0x00, 0x00, 0x00];
    assert_incomplete(extract_postgres_frame(&mut startup));

    startup.extend_from_slice(&[0x08, 0x04, 0xD2, 0x16, 0x2F]);
    let startup_frame = expect_complete(extract_postgres_frame(&mut startup));
    assert_eq!(
        startup_frame,
        vec![0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F]
    );
    assert!(startup.is_empty());

    let mut query = vec![b'Q', 0x00, 0x00, 0x00];
    assert_incomplete(extract_postgres_frame(&mut query));

    query.extend_from_slice(&[0x06, b'S', 0x00]);
    let query_frame = expect_complete(extract_postgres_frame(&mut query));
    assert_eq!(query_frame, vec![b'Q', 0x00, 0x00, 0x00, 0x06, b'S', 0x00]);
    assert!(query.is_empty());
}

#[test]
fn socks_frames_wait_for_complete_greeting_and_request() {
    let mut greeting = vec![0x05, 0x01];
    assert_incomplete(extract_socks_frame(&mut greeting));

    greeting.push(0x00);
    let greeting_frame = expect_complete(extract_socks_frame(&mut greeting));
    assert_eq!(greeting_frame, vec![0x05, 0x01, 0x00]);
    assert!(greeting.is_empty());

    let mut request = vec![0x05, 0x01, 0x00, 0x03, 0x0C, b'e', b'x', b'a'];
    assert_incomplete(extract_socks_frame(&mut request));

    request.extend_from_slice(b"mple.test\0P");
    let request_frame = expect_complete(extract_socks_frame(&mut request));
    assert_eq!(
        request_frame,
        b"\x05\x01\x00\x03\x0Cexample.test\x00P".to_vec()
    );
    assert!(request.is_empty());
}

#[test]
fn socks5_coalesced_greeting_and_connect_stay_in_one_frame() {
    let mut buffer = b"\x05\x01\x00\x05\x01\x00\x03\x0Cexample.test\x00P".to_vec();

    let frame = expect_complete(extract_socks_frame(&mut buffer));
    assert_eq!(
        frame,
        b"\x05\x01\x00\x05\x01\x00\x03\x0Cexample.test\x00P".to_vec()
    );
    assert!(buffer.is_empty());
}

#[test]
fn socks5_zero_method_greeting_is_complete_frame() {
    let mut buffer = vec![0x05, 0x00];

    let greeting_frame = expect_complete(extract_socks_frame(&mut buffer));

    assert_eq!(greeting_frame, vec![0x05, 0x00]);
    assert!(buffer.is_empty());
}

#[test]
fn socks4_frame_rejects_oversized_missing_nul() {
    let mut buffer = vec![0x04; MAX_SOCKS4_FRAME_SIZE + 1];

    assert_terminal_without_response(extract_socks_frame(&mut buffer));

    assert!(buffer.is_empty());
}

#[test]
fn redis_frame_waits_for_complete_resp_array() {
    let mut buffer = b"*1\r\n$4\r\nPI".to_vec();
    assert_incomplete(extract_redis_frame(&mut buffer));

    buffer.extend_from_slice(b"NG\r\n");
    assert_eq!(
        expect_complete(extract_redis_frame(&mut buffer)),
        b"*1\r\n$4\r\nPING\r\n".to_vec()
    );
    assert!(buffer.is_empty());
}

#[test]
fn redis_frame_rejects_signed_array_counts_and_bulk_lengths() {
    let mut buffer = b"*+1\r\n$4\r\nPING\r\n".to_vec();
    assert_terminal_without_response(extract_redis_frame(&mut buffer));
    assert!(buffer.is_empty());

    let mut buffer = b"*1\r\n$+4\r\nPING\r\n".to_vec();
    assert_terminal_without_response(extract_redis_frame(&mut buffer));
    assert!(buffer.is_empty());

    let mut buffer = b"*1\r\n$-0\r\n".to_vec();
    assert_terminal_without_response(extract_redis_frame(&mut buffer));
    assert!(buffer.is_empty());
}

#[test]
fn memcached_binary_frame_waits_for_complete_body() {
    let mut buffer = vec![0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    buffer.extend_from_slice(&4u32.to_be_bytes());
    buffer.extend_from_slice(&[0; 12]);
    buffer.extend_from_slice(b"he");
    assert_incomplete(extract_memcached_frame(&mut buffer));

    buffer.extend_from_slice(b"lo");
    assert_eq!(expect_complete(extract_memcached_frame(&mut buffer)), {
        let mut frame = vec![0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        frame.extend_from_slice(&4u32.to_be_bytes());
        frame.extend_from_slice(&[0; 12]);
        frame.extend_from_slice(b"helo");
        frame
    });
    assert!(buffer.is_empty());
}

#[test]
fn memcached_text_storage_waits_for_complete_body() {
    let mut buffer = b"set key 0 0 5\r\nhel".to_vec();
    assert_incomplete(extract_memcached_frame(&mut buffer));

    buffer.extend_from_slice(b"lo\r\n");
    assert_eq!(
        expect_complete(extract_memcached_frame(&mut buffer)),
        b"set key 0 0 5\r\nhello\r\n".to_vec()
    );
    assert!(buffer.is_empty());
}

#[test]
fn memcached_text_storage_rejects_signed_body_length() {
    let mut buffer = b"set key 0 0 +5\r\nhello\r\n".to_vec();

    expect_terminal_response(extract_memcached_frame(&mut buffer), b"ERROR\r\n");

    assert!(buffer.is_empty());
}

#[test]
fn smb_frame_waits_for_complete_netbios_payload() {
    let mut buffer = vec![0x00, 0x00, 0x00, 0x05, 0xFE, b'S'];
    assert!(extract_smb_frame(&mut buffer).is_none());

    buffer.extend_from_slice(b"MB!");
    let frame = extract_smb_frame(&mut buffer).expect("smb netbios frame should be complete");
    assert_eq!(
        frame,
        vec![0x00, 0x00, 0x00, 0x05, 0xFE, b'S', b'M', b'B', b'!']
    );
    assert!(buffer.is_empty());
}

#[test]
fn smb_frame_treats_reserved_netbios_flags_as_immediate_payload() {
    let mut buffer = vec![0x00, 0x02, 0x00, 0x05, 0xFE, b'S'];

    let frame = extract_smb_frame(&mut buffer).expect("invalid netbios flags should not wait");

    assert_eq!(frame, vec![0x00, 0x02, 0x00, 0x05, 0xFE, b'S']);
    assert!(buffer.is_empty());
}

#[test]
fn rdp_frame_waits_for_complete_tpkt() {
    let mut buffer = vec![0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0];
    assert_eq!(extract_rdp_frame(&mut buffer), TcpFrameResult::Incomplete);

    buffer.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
    let frame = match extract_rdp_frame(&mut buffer) {
        TcpFrameResult::Complete(frame) => frame,
        other => panic!("rdp tpkt should be complete, got {other:?}"),
    };
    assert_eq!(
        frame,
        vec![
            0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00
        ]
    );
    assert!(buffer.is_empty());
}

#[test]
fn ldap_frame_waits_for_complete_ber_sequence() {
    let mut buffer = vec![0x30, 0x0C, 0x02, 0x01, 0x01, 0x60];
    assert_incomplete(extract_ldap_frame(&mut buffer));

    buffer.extend_from_slice(&[0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00]);
    let frame = expect_complete(extract_ldap_frame(&mut buffer));
    assert_eq!(
        frame,
        vec![
            0x30, 0x0C, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
        ]
    );
    assert!(buffer.is_empty());
}

#[test]
fn ldap_frame_rejects_invalid_long_form_length() {
    let mut buffer = vec![0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01];

    assert_terminal_without_response(extract_ldap_frame(&mut buffer));

    assert!(buffer.is_empty());
}

#[test]
fn ldap_frame_rejects_declared_payload_over_limit() {
    let mut buffer = vec![0x30, 0x84];
    buffer.extend_from_slice(&(MAX_LDAP_BER_PAYLOAD_SIZE as u32 + 1).to_be_bytes());

    assert_terminal_without_response(extract_ldap_frame(&mut buffer));

    assert!(buffer.is_empty());
}

#[test]
fn ldap_frame_keeps_partial_long_form_length_buffered() {
    let mut buffer = vec![0x30, 0x84, 0x00];

    assert_incomplete(extract_ldap_frame(&mut buffer));

    assert_eq!(buffer, vec![0x30, 0x84, 0x00]);
}

#[test]
fn tls_frame_waits_for_complete_record() {
    let mut buffer = vec![0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x02];
    assert_incomplete(extract_tls_frame(&mut buffer));

    buffer.extend_from_slice(&[0x03, 0x04]);
    assert_eq!(
        expect_complete(extract_tls_frame(&mut buffer)),
        vec![0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04]
    );
    assert!(buffer.is_empty());
}

#[test]
fn tls_frame_rejects_unsupported_record_versions() {
    let mut buffer = vec![0x16, 0x03, 0xff, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];

    assert!(matches!(
        extract_tls_frame(&mut buffer),
        TcpFrameResult::Invalid { response: Some(_) }
    ));
    assert!(buffer.is_empty());
}

#[test]
fn tls_frame_rejects_oversized_record() {
    let mut buffer = vec![0x16, 0x03, 0x03, 0xff, 0xff];

    assert!(matches!(
        extract_tls_frame(&mut buffer),
        TcpFrameResult::TooLarge { response: Some(_) }
    ));
    assert!(buffer.is_empty());
}

#[test]
fn tls_record_total_len_accepts_records_larger_than_512_bytes() {
    let record_len = 600u16;
    let header = [0x16, 0x03, 0x03, (record_len >> 8) as u8, record_len as u8];

    assert_eq!(tls_record_total_len(&header), Some(605));
}

#[tokio::test]
async fn tls_peek_reads_complete_record_larger_than_512_bytes() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener address should exist");
    let mut record = vec![0x16, 0x03, 0x03];
    record.extend_from_slice(&600u16.to_be_bytes());
    record.push(0x01);
    record.resize(605, 0);
    let expected = record.clone();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("server should accept");
        let peeked = peek_complete_tls_record(&stream, Duration::from_secs(1))
            .await
            .expect("peek should succeed")
            .expect("TLS record should be detected");

        assert_eq!(peeked, expected);

        let mut prefix = [0u8; 5];
        assert_eq!(stream.peek(&mut prefix).await.expect("peek should work"), 5);
        assert_eq!(prefix, [0x16, 0x03, 0x03, 0x02, 0x58]);
    });

    let mut client = tokio::net::TcpStream::connect(addr)
        .await
        .expect("client should connect");
    client
        .write_all(&record)
        .await
        .expect("client should write TLS record");
    server.await.expect("server task should finish");
}

#[test]
fn tcp_frame_mode_detects_tls_on_https_port_before_http() {
    let router = nettrap_proxy::ProtocolRouter::new();

    assert_eq!(
        tcp_frame_mode("tcp", &[0x16, 0x03], 443, &router, false, true),
        TcpFrameMode::Tls
    );
}

#[test]
fn tcp_frame_mode_explicit_listener_ignores_destination_port_heuristic() {
    let router = nettrap_proxy::ProtocolRouter::new();

    assert_eq!(
        tcp_frame_mode("raw", b"GET / HTTP/1.1\r\n", 80, &router, false, false),
        TcpFrameMode::Immediate
    );
    assert_eq!(
        tcp_frame_mode("ftp", b"USER anonymous\r\n", 80, &router, false, false),
        TcpFrameMode::Line
    );
}

#[test]
fn dispatcher_log_text_is_single_line() {
    let text = nettrap_core::sanitize::single_line("USER anonymous\r\nPASS injected\x1b");

    assert_eq!(text, "USER anonymous  PASS injected ");
    assert!(!text.chars().any(char::is_control));

    let long = "a".repeat(nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS + 1);
    assert_eq!(
        nettrap_core::sanitize::single_line(&long).len(),
        nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS
    );
}

#[test]
fn tcp_frame_mode_routes_registered_utility_protocols() {
    let router = nettrap_proxy::ProtocolRouter::new();

    assert_eq!(
        tcp_frame_mode("finger", b"user\r\n", 79, &router, false, false),
        TcpFrameMode::Line
    );
    assert_eq!(
        tcp_frame_mode("ident", b"1, 2\r\n", 113, &router, false, false),
        TcpFrameMode::Line
    );
    assert_eq!(
        tcp_frame_mode("syslogrecv", b"<13>test\n", 514, &router, false, false),
        TcpFrameMode::Line
    );
    assert_eq!(
        tcp_frame_mode("daytime", b"", 13, &router, false, false),
        TcpFrameMode::Immediate
    );
    assert_eq!(
        tcp_frame_mode("chargen", b"", 19, &router, false, false),
        TcpFrameMode::Immediate
    );
}

#[test]
fn nkn_uses_json_frame_mode_for_explicit_and_detected_protocol() {
    assert_eq!(protocol_frame_mode("nkn", false), Some(TcpFrameMode::Nkn));
    assert_eq!(
        protocol_frame_mode("nkn-custom", false),
        Some(TcpFrameMode::Nkn)
    );

    let router = nettrap_proxy::ProtocolRouter::with_default_tastes(None, None);
    let request = br#"{"jsonrpc":"2.0","method":"getnodestate","id":1}"#;
    assert_eq!(
        tcp_frame_mode("tcp", request, 30001, &router, false, false),
        TcpFrameMode::Nkn
    );
}

#[test]
fn nkn_json_frame_waits_for_complete_json_rpc() {
    let mut buffer = br#"{"jsonrpc":"2.0","method":"getnodestate""#.to_vec();

    assert_eq!(
        next_tcp_frame_for_mode(&mut buffer, TcpFrameMode::Nkn),
        TcpFrameResult::Incomplete
    );
    buffer.extend_from_slice(br#","id":1}"#);

    let frame = expect_complete(next_tcp_frame_for_mode(&mut buffer, TcpFrameMode::Nkn));
    assert_eq!(
        frame,
        br#"{"jsonrpc":"2.0","method":"getnodestate","id":1}"#
    );
    assert!(buffer.is_empty());
}

#[test]
fn nkn_json_frame_rejects_oversized_incomplete_payload() {
    let mut buffer = vec![b'{'; MAX_NKN_FRAME_SIZE + 1];

    assert_eq!(
        next_tcp_frame_for_mode(&mut buffer, TcpFrameMode::Nkn),
        TcpFrameResult::TooLarge { response: None }
    );
    assert!(buffer.is_empty());
}

#[test]
fn tcp_one_shot_protocol_names_require_exact_or_separator_match() {
    assert_eq!(
        explicit_tcp_one_shot_protocol("daytime-custom"),
        Some("daytime")
    );
    assert_eq!(explicit_tcp_one_shot_protocol("time_37"), Some("time"));
    assert_eq!(explicit_tcp_one_shot_protocol("timeout"), None);
    assert!(!build_tcp_one_shot_response("quotd").is_empty());
}

#[test]
fn protocol_name_matching_rejects_bare_prefixes() {
    assert!(listener_name_matches_protocol("smtp_backup", "smtp"));
    assert!(listener_name_matches_protocol("raw-custom", "raw"));

    assert!(!listener_name_matches_protocol("smtpbackup", "smtp"));
    assert!(!listener_name_matches_protocol("rawhide", "raw"));
    assert!(!listener_name_matches_protocol("timeout", "time"));

    assert_eq!(protocol_frame_mode("smtpbackup", false), None);
    assert_eq!(protocol_frame_mode("rawhide", false), None);
    assert_eq!(protocol_frame_mode("timeout", false), None);
}

#[test]
fn ssh_first_response_omits_duplicate_banner_when_already_sent() {
    let handler = nettrap_proto_ssh::SshHandler::new();

    let response = build_ssh_first_response(&handler, true);
    assert!(!response.is_empty());
    assert!(!response.starts_with(b"SSH-"));

    let response_with_banner = build_ssh_first_response(&handler, false);
    assert!(response_with_banner.starts_with(b"SSH-"));
}

#[test]
fn ftp_pasv_host_uses_control_local_ipv4() {
    let handler = nettrap_proto_ftp::FtpHandler::new();
    let destination = SessionDestination::new_unchecked("192.0.2.10", 21);
    let local_addr: std::net::SocketAddr = "192.0.2.20:2121".parse().expect("local addr");

    assert_eq!(
        ftp_passive_response_host(&handler, &destination, Some(local_addr)),
        "192,0,2,20"
    );
}

#[test]
fn ftp_pasv_host_falls_back_to_loopback_for_redirect_destination() {
    let handler = nettrap_proto_ftp::FtpHandler::new();
    let destination = SessionDestination::new_unchecked("192.0.2.10", 21);

    assert_eq!(
        ftp_passive_response_host(&handler, &destination, None),
        "127,0,0,1"
    );
}

#[test]
fn ftp_pasv_host_prefers_configured_address() {
    let handler = nettrap_proto_ftp::FtpHandler::new()
        .with_pasv_address("10.1.2.3")
        .expect("valid PASV address");
    let destination = SessionDestination::new_unchecked("192.0.2.10", 21);
    let local_addr: std::net::SocketAddr = "192.0.2.20:2121".parse().expect("local addr");

    assert_eq!(
        ftp_passive_response_host(&handler, &destination, Some(local_addr)),
        "10,1,2,3"
    );
}

#[tokio::test]
async fn ftp_prefixed_pasv_does_not_open_passive_socket() {
    let handler = nettrap_proto_ftp::FtpHandler::new()
        .with_pasv_ports(0, 0)
        .expect("zero PASV range should reset");
    let mut state = FtpPassiveState::default();
    let peer: std::net::SocketAddr = "127.0.0.1:40000".parse().expect("peer addr");
    let destination = SessionDestination::new_unchecked("127.0.0.1", 21);
    let control_local: std::net::SocketAddr = "127.0.0.1:2121".parse().expect("local addr");

    let response = prepare_ftp_command(
        &handler,
        &mut state,
        "PASVXYZ",
        &peer,
        &destination,
        Some(control_local),
    )
    .await;

    match response {
        FtpCommandAction::Response(response) => {
            assert!(!String::from_utf8_lossy(&response).starts_with("227 "));
        }
        FtpCommandAction::Transfer { .. } => panic!("prefixed PASV must not open data socket"),
    }
    assert!(state.listener.is_none());
    assert!(state.permit.is_none());
}

#[tokio::test]
async fn ftp_unicode_whitespace_padded_command_is_rejected() {
    let handler = nettrap_proto_ftp::FtpHandler::new();
    let mut state = FtpPassiveState::default();
    let peer: std::net::SocketAddr = "127.0.0.1:40000".parse().expect("peer addr");
    let destination = SessionDestination::new_unchecked("127.0.0.1", 21);

    let response = handle_ftp_command(
        &handler,
        &mut state,
        "QUIT\u{00a0}\r\n",
        &peer,
        &destination,
        None,
    )
    .await;

    assert!(response.starts_with(b"502 "));
    assert!(state.listener.is_none());
    assert!(state.permit.is_none());
}

#[tokio::test]
async fn ftp_abor_and_quit_clear_passive_state() {
    let handler = nettrap_proto_ftp::FtpHandler::new()
        .with_pasv_ports(0, 0)
        .expect("zero PASV range should reset");
    let mut state = FtpPassiveState::default();
    let peer: std::net::SocketAddr = "127.0.0.1:40000".parse().expect("peer addr");
    let destination = SessionDestination::new_unchecked("127.0.0.1", 21);
    let control_local: std::net::SocketAddr = "127.0.0.1:2121".parse().expect("local addr");

    let response = open_ftp_passive_data_socket(
        &handler,
        &mut state,
        &peer,
        &destination,
        Some(control_local),
        false,
    )
    .await;
    assert!(response.starts_with(b"227 "));
    assert!(state.listener.is_some());
    assert!(state.permit.is_some());

    let response = prepare_ftp_command(
        &handler,
        &mut state,
        "ABOR",
        &peer,
        &destination,
        Some(control_local),
    )
    .await;
    assert!(matches!(response, FtpCommandAction::Response(_)));
    assert!(state.listener.is_none());
    assert!(state.permit.is_none());

    let response = open_ftp_passive_data_socket(
        &handler,
        &mut state,
        &peer,
        &destination,
        Some(control_local),
        false,
    )
    .await;
    assert!(response.starts_with(b"227 "));

    let response = prepare_ftp_command(
        &handler,
        &mut state,
        "QUIT",
        &peer,
        &destination,
        Some(control_local),
    )
    .await;
    assert!(matches!(response, FtpCommandAction::Response(_)));
    assert!(state.listener.is_none());
    assert!(state.permit.is_none());
}

#[tokio::test]
async fn ftp_passive_transfer_uses_data_socket() {
    let handler = nettrap_proto_ftp::FtpHandler::new()
        .with_pasv_ports(0, 0)
        .expect("zero PASV range should reset");
    let mut state = FtpPassiveState::default();
    let peer: std::net::SocketAddr = "127.0.0.1:40000".parse().expect("peer addr");
    let destination = SessionDestination::new_unchecked("127.0.0.1", 21);
    let control_local: std::net::SocketAddr = "127.0.0.1:2121".parse().expect("local addr");

    let pasv_response = open_ftp_passive_data_socket(
        &handler,
        &mut state,
        &peer,
        &destination,
        Some(control_local),
        false,
    )
    .await;
    assert!(pasv_response.starts_with(b"227 "));
    let port = state
        .listener
        .as_ref()
        .expect("passive listener")
        .local_addr()
        .expect("local addr")
        .port();
    assert!(state.permit.is_some());

    let data_reader = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect passive data socket");
        let mut data = Vec::new();
        stream
            .read_to_end(&mut data)
            .await
            .expect("read passive data");
        data
    });

    let transfer = match prepare_ftp_command(
        &handler,
        &mut state,
        "NLST",
        &peer,
        &destination,
        Some(control_local),
    )
    .await
    {
        FtpCommandAction::Transfer {
            listener,
            permit,
            transfer,
        } => {
            let start_response = transfer.start_response.to_bytes();
            assert!(String::from_utf8_lossy(&start_response).starts_with("150 "));
            (listener, permit, transfer)
        }
        FtpCommandAction::Response(response) => {
            panic!(
                "expected transfer action, got {}",
                String::from_utf8_lossy(&response)
            );
        }
    };
    let control_response = finish_ftp_passive_transfer(transfer.0, transfer.1, transfer.2).await;
    let data = data_reader.await.expect("data task");

    assert!(String::from_utf8_lossy(&data).contains("index.html"));
    let control_text = String::from_utf8_lossy(&control_response);
    assert!(control_text.contains("226 Directory send OK."));
    assert!(state.listener.is_none());
    assert!(state.permit.is_none());
}

#[tokio::test]
async fn ftp_command_rejects_invalid_utf8_in_ordered_path() {
    let ctx = Arc::new(
        ListenerContext::builder()
            .name("ftp")
            .port(21)
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
    let peer: std::net::SocketAddr = "127.0.0.1:53005".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 21);
    let command_context = FtpCommandContext {
        peer: &peer,
        destination: &destination,
        control_local_addr: None,
    };
    let mut state = FtpPassiveState::default();
    let handler = nettrap_proto_ftp::FtpHandler::new();

    let response = match prepare_ordered_ftp_action(
        &ctx,
        None,
        &handler,
        &mut state,
        b"\xff\xfe\xfd",
        command_context,
    )
    .await
    {
        FtpCommandAction::Response(response) => response,
        FtpCommandAction::Transfer { .. } => {
            panic!("invalid UTF-8 should not start a transfer")
        }
    };

    assert!(response.starts_with(b"500 "));
}

#[tokio::test]
async fn ftp_command_rejects_bare_lf_in_ordered_path() {
    let ctx = Arc::new(
        ListenerContext::builder()
            .name("ftp")
            .port(21)
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
    let peer: std::net::SocketAddr = "127.0.0.1:53005".parse().expect("peer");
    let destination = SessionDestination::new_unchecked("10.0.0.5", 21);
    let command_context = FtpCommandContext {
        peer: &peer,
        destination: &destination,
        control_local_addr: None,
    };
    let mut state = FtpPassiveState::default();
    let handler = nettrap_proto_ftp::FtpHandler::new();

    let response = match prepare_ordered_ftp_action(
        &ctx,
        None,
        &handler,
        &mut state,
        b"QUIT\n",
        command_context,
    )
    .await
    {
        FtpCommandAction::Response(response) => response,
        FtpCommandAction::Transfer { .. } => {
            panic!("malformed FTP command should not start a transfer")
        }
    };

    assert!(response.starts_with(b"502 "));
}
