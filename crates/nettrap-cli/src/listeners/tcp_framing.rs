//! TCP frame extraction and protocol framing primitives.

use nettrap_protocols::handlers::*;
use serde::de::IgnoredAny;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::listener_context::ListenerContext;
use crate::session::SessionDestination;

mod http;
#[path = "tcp_io.rs"]
mod tcp_io;

pub(crate) use http::*;
pub(crate) use tcp_io::*;

pub(crate) const MAX_HTTP_HEADER_SIZE: usize = 64 * 1024;
pub(crate) const MAX_HTTP_REQUEST_SIZE: usize = 10 * 1024 * 1024;
pub(crate) const MAX_LINE_FRAME_SIZE: usize = 64 * 1024;
pub(crate) const MAX_SSH_PACKET_SIZE: usize = 64 * 1024;
pub(crate) const MAX_SOCKS4_FRAME_SIZE: usize = 8 * 1024;
pub(crate) const MAX_SMTP_DATA_SIZE: usize = 50 * 1024 * 1024;
pub(crate) const MAX_MYSQL_FRAME_SIZE: usize = 16 * 1024 * 1024;
pub(crate) const MAX_POSTGRES_FRAME_SIZE: usize = 16 * 1024 * 1024;
pub(crate) const MAX_MQTT_FRAME_SIZE: usize = 1024 * 1024;
pub(crate) const MAX_REDIS_FRAME_SIZE: usize = 1024 * 1024;
pub(crate) const MAX_REDIS_ARRAY_COUNT: usize = 1024;
pub(crate) const MAX_REDIS_BULK_SIZE: usize = 64 * 1024;
pub(crate) const MAX_MEMCACHED_LINE_SIZE: usize = 64 * 1024;
pub(crate) const MAX_MEMCACHED_FRAME_SIZE: usize = 1024 * 1024;
pub(crate) const MAX_NKN_FRAME_SIZE: usize = 4096;
pub(crate) const MAX_TLS_RECORD_SIZE: usize = 64 * 1024;
pub(crate) const MAX_LDAP_BER_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;
pub(crate) const MAX_LDAP_FRAME_SIZE: usize = MAX_LDAP_BER_PAYLOAD_SIZE + 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpFrameMode {
    DnsTcp,
    Http,
    Line,
    SmtpData,
    SshBanner,
    SshPayload,
    Mysql,
    Postgres,
    Socks,
    Smb,
    Rdp,
    Ldap,
    Mqtt,
    Tls,
    Redis,
    Memcached,
    Nkn,
    Immediate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TcpFrameResult {
    Complete(Vec<u8>),
    Incomplete,
    Invalid { response: Option<Vec<u8>> },
    TooLarge { response: Option<Vec<u8>> },
}

pub(crate) fn optional_frame(frame: Option<Vec<u8>>) -> TcpFrameResult {
    frame
        .map(TcpFrameResult::Complete)
        .unwrap_or(TcpFrameResult::Incomplete)
}

pub(crate) fn next_tcp_frame_with_mode(
    buffer: &mut Vec<u8>,
    listener_name: &str,
    destination_port: u16,
    router: &nettrap_proxy::ProtocolRouter,
    smtp_data_mode: bool,
    ssh_first_packet: bool,
) -> (TcpFrameMode, TcpFrameResult) {
    let mode = tcp_frame_mode(
        listener_name,
        buffer,
        destination_port,
        router,
        smtp_data_mode,
        ssh_first_packet,
    );
    let frame = next_tcp_frame_for_mode(buffer, mode);
    (mode, frame)
}

pub(crate) fn tcp_dispatch_name_for_frame(listener_name: &str, frame_mode: TcpFrameMode) -> &str {
    if frame_mode == TcpFrameMode::Tls {
        "tls"
    } else {
        listener_name
    }
}

pub(crate) fn next_tcp_frame_for_mode(buffer: &mut Vec<u8>, mode: TcpFrameMode) -> TcpFrameResult {
    match mode {
        TcpFrameMode::DnsTcp => optional_frame(extract_length_prefixed_frame(buffer)),
        TcpFrameMode::Http => extract_http_request(buffer),
        TcpFrameMode::Line | TcpFrameMode::SshBanner => extract_line_frame(buffer),
        TcpFrameMode::SmtpData => extract_smtp_data_frame(buffer),
        TcpFrameMode::SshPayload => extract_ssh_payload_frame(buffer),
        TcpFrameMode::Mysql => extract_mysql_frame(buffer),
        TcpFrameMode::Postgres => extract_postgres_frame(buffer),
        TcpFrameMode::Socks => extract_socks_frame(buffer),
        TcpFrameMode::Smb => optional_frame(extract_smb_frame(buffer)),
        TcpFrameMode::Rdp => extract_rdp_frame(buffer),
        TcpFrameMode::Ldap => extract_ldap_frame(buffer),
        TcpFrameMode::Mqtt => extract_mqtt_frame(buffer),
        TcpFrameMode::Tls => extract_tls_frame(buffer),
        TcpFrameMode::Redis => extract_redis_frame(buffer),
        TcpFrameMode::Memcached => extract_memcached_frame(buffer),
        TcpFrameMode::Nkn => extract_nkn_frame(buffer),
        TcpFrameMode::Immediate => optional_frame(extract_immediate_frame(buffer)),
    }
}

pub(crate) fn tcp_frame_mode(
    listener_name: &str,
    buffer: &[u8],
    destination_port: u16,
    router: &nettrap_proxy::ProtocolRouter,
    smtp_data_mode: bool,
    ssh_first_packet: bool,
) -> TcpFrameMode {
    if smtp_data_mode {
        return TcpFrameMode::SmtpData;
    }

    if has_tls_record_prefix(buffer) || is_tls_client_hello(buffer) {
        return TcpFrameMode::Tls;
    }

    if let Some(mode) = listener_frame_mode(listener_name, ssh_first_packet) {
        return mode;
    }

    if let Some(mode) = port_frame_mode(destination_port, buffer, router, ssh_first_packet) {
        return mode;
    }

    if let Some((detected, _)) = router.route_tcp(buffer, destination_port) {
        return protocol_frame_mode(detected.as_str(), ssh_first_packet)
            .unwrap_or(TcpFrameMode::Immediate);
    }

    TcpFrameMode::Immediate
}

pub(crate) fn listener_frame_mode(
    listener_name: &str,
    ssh_first_packet: bool,
) -> Option<TcpFrameMode> {
    let listener = listener_name.to_lowercase();

    if listener == "tcp" || listener == "auto" || listener == "autodetect" {
        return None;
    }

    protocol_frame_mode(&listener, ssh_first_packet)
}

pub(crate) fn listener_name_matches_protocol(listener_name: &str, protocol: &str) -> bool {
    // Trim only ASCII space/tab, then reject any residual control or non-space
    // whitespace (e.g. a NBSP `\u{00a0}`) so a padded listener name can't sneak
    // past protocol matching. `canonical_protocol_alias` lowercases and maps
    // aliases such as `qotd` -> `quotd`.
    if listener_name.trim_matches([' ', '\t']) != listener_name
        || listener_name.is_empty()
        || listener_name
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return false;
    }
    let listener = canonical_protocol_alias(listener_name);
    listener == protocol
        || listener
            .strip_prefix(protocol)
            .and_then(|suffix| suffix.as_bytes().first().copied())
            .is_some_and(|byte| matches!(byte, b'-' | b'_'))
}

/// Map well-known protocol-name aliases to the canonical identifier used
/// throughout the dispatcher. The QOTD service (RFC 865) is advertised in the
/// README and config as `qotd` (the standard abbreviation), but the internal
/// handler identifier is `quotd`; without this alias a listener named `qotd`
/// never matched the one-shot quote path and silently sent nothing.
pub(crate) fn canonical_protocol_alias(listener_name: &str) -> String {
    let lower = listener_name.to_lowercase();
    match lower.as_str() {
        "qotd" => "quotd".to_string(),
        other if other.starts_with("qotd-") || other.starts_with("qotd_") => {
            format!("quotd{}", &other["qotd".len()..])
        }
        _ => lower,
    }
}

pub(crate) fn explicit_tcp_one_shot_protocol(listener_name: &str) -> Option<&'static str> {
    ["daytime", "time", "chargen", "quotd"]
        .into_iter()
        .find(|protocol| listener_name_matches_protocol(listener_name, protocol))
}

pub(crate) fn build_tcp_one_shot_response(protocol: &str) -> Vec<u8> {
    match protocol {
        "daytime" => nettrap_proto_daytime::DaytimeHandler::new()
            .handle_at(crate::faketime::fake_now())
            .into_bytes(),
        "time" => nettrap_proto_time::TimeHandler::new()
            .handle_at(crate::faketime::fake_now())
            .to_vec(),
        "chargen" => {
            let handler = nettrap_proto_chargen::ChargenHandler::new();
            handler.handle(6)
        }
        "quotd" => nettrap_proto_quotd::QuotdHandler::new()
            .handle()
            .into_bytes(),
        _ => Vec::new(),
    }
}

pub(crate) async fn handle_tcp_one_shot_connection(
    ctx: &Arc<ListenerContext>,
    stream: &mut tokio::net::TcpStream,
    peer: &SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
) -> crate::Result<bool> {
    let Some(protocol) = explicit_tcp_one_shot_protocol(ctx.name()) else {
        return Ok(false);
    };

    let response = build_tcp_one_shot_response(protocol);
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: &format!("{}_request", protocol),
            detail: "connect",
            data_len: 0,
            protocol,
        },
    )
    .await;

    if !response.is_empty() {
        ctx.apply_response_delay().await;
        write_tcp_with_timeout(ctx, stream, &response, peer, "TCP").await?;
        ctx.write_pcap_response_for_destination(&response, peer, destination);
    }
    ctx.update_session_bytes(peer, "TCP", destination, 0, response.len() as u64);
    Ok(true)
}

pub(crate) fn protocol_frame_mode(protocol: &str, ssh_first_packet: bool) -> Option<TcpFrameMode> {
    if listener_name_matches_protocol(protocol, "dns") {
        return Some(TcpFrameMode::DnsTcp);
    }

    if listener_name_matches_protocol(protocol, "tls")
        || listener_name_matches_protocol(protocol, "ssl")
    {
        return Some(TcpFrameMode::Tls);
    }

    if listener_name_matches_protocol(protocol, "http")
        || listener_name_matches_protocol(protocol, "https")
    {
        return Some(TcpFrameMode::Http);
    }

    if listener_name_matches_protocol(protocol, "upnp") {
        return Some(TcpFrameMode::Http);
    }

    if [
        "smtp",
        "smtps",
        "ftp",
        "ftps",
        "pop3",
        "pop3s",
        "imap",
        "imaps",
        "irc",
        "ircs",
        "telnet",
        "telnets",
        "finger",
        "ident",
        "syslogrecv",
    ]
    .into_iter()
    .any(|candidate| listener_name_matches_protocol(protocol, candidate))
    {
        return Some(TcpFrameMode::Line);
    }

    if [
        "daytime", "time", "chargen", "quotd", "dummy", "raw", "echo",
    ]
    .into_iter()
    .any(|candidate| listener_name_matches_protocol(protocol, candidate))
    {
        return Some(TcpFrameMode::Immediate);
    }

    if listener_name_matches_protocol(protocol, "ssh") {
        return Some(if ssh_first_packet {
            TcpFrameMode::SshBanner
        } else {
            TcpFrameMode::SshPayload
        });
    }

    if listener_name_matches_protocol(protocol, "mysql") {
        return Some(TcpFrameMode::Mysql);
    }
    if listener_name_matches_protocol(protocol, "postgres") {
        return Some(TcpFrameMode::Postgres);
    }
    if listener_name_matches_protocol(protocol, "socks") {
        return Some(TcpFrameMode::Socks);
    }
    if listener_name_matches_protocol(protocol, "smb") {
        return Some(TcpFrameMode::Smb);
    }
    if listener_name_matches_protocol(protocol, "rdp") {
        return Some(TcpFrameMode::Rdp);
    }
    if listener_name_matches_protocol(protocol, "ldap") {
        return Some(TcpFrameMode::Ldap);
    }
    if listener_name_matches_protocol(protocol, "ldaps") {
        return Some(TcpFrameMode::Ldap);
    }
    if listener_name_matches_protocol(protocol, "redis") {
        return Some(TcpFrameMode::Redis);
    }
    if listener_name_matches_protocol(protocol, "memcached") {
        return Some(TcpFrameMode::Memcached);
    }
    if listener_name_matches_protocol(protocol, "mqtt") {
        return Some(TcpFrameMode::Mqtt);
    }
    if listener_name_matches_protocol(protocol, "nkn") {
        return Some(TcpFrameMode::Nkn);
    }

    None
}

pub(crate) fn port_frame_mode(
    destination_port: u16,
    buffer: &[u8],
    router: &nettrap_proxy::ProtocolRouter,
    ssh_first_packet: bool,
) -> Option<TcpFrameMode> {
    match destination_port {
        53 => Some(TcpFrameMode::DnsTcp),
        _ if is_dns_over_tcp_frame(buffer, destination_port, router) => Some(TcpFrameMode::DnsTcp),
        853 | 636 | 990 | 992 | 993 | 994 | 6697 => Some(TcpFrameMode::Tls),
        443 | 8443 | 8883 | 9443 if has_tls_record_prefix(buffer) => Some(TcpFrameMode::Tls),
        80 | 443 | 8000 | 8080 | 8443 | 8888 => Some(TcpFrameMode::Http),
        25 | 465 | 587 | 2525 => Some(TcpFrameMode::Line),
        21 => Some(TcpFrameMode::Line),
        110 | 995 => Some(TcpFrameMode::Line),
        143 => Some(TcpFrameMode::Line),
        194 | 6667 => Some(TcpFrameMode::Line),
        23 | 79 | 113 | 514 | 601 => Some(TcpFrameMode::Line),
        13 | 17 | 19 | 37 => Some(TcpFrameMode::Immediate),
        22 => Some(if ssh_first_packet {
            TcpFrameMode::SshBanner
        } else {
            TcpFrameMode::SshPayload
        }),
        3306 => Some(TcpFrameMode::Mysql),
        5432 => Some(TcpFrameMode::Postgres),
        1080 => Some(TcpFrameMode::Socks),
        139 | 445 => Some(TcpFrameMode::Smb),
        3389 => Some(TcpFrameMode::Rdp),
        389 => Some(TcpFrameMode::Ldap),
        6379 => Some(TcpFrameMode::Redis),
        11211 => Some(TcpFrameMode::Memcached),
        1883 => Some(TcpFrameMode::Mqtt),
        _ => None,
    }
}

fn is_dns_over_tcp_frame(
    buffer: &[u8],
    destination_port: u16,
    router: &nettrap_proxy::ProtocolRouter,
) -> bool {
    let Some((payload, complete)) = split_length_prefixed_payload(buffer) else {
        return false;
    };

    if complete {
        return router
            .route_tcp(payload, destination_port)
            .as_ref()
            .is_some_and(|(name, _)| name == "dns");
    }

    looks_like_dns_header(payload)
}

pub(crate) fn extract_length_prefixed_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buffer.len() < 2 {
        return None;
    }

    let declared_len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
    let total_len = 2 + declared_len;
    if buffer.len() < total_len {
        return None;
    }

    Some(buffer.drain(..total_len).collect())
}

fn split_length_prefixed_payload(buffer: &[u8]) -> Option<(&[u8], bool)> {
    if buffer.len() < 2 {
        return None;
    }

    let declared_len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
    let total_len = 2usize.checked_add(declared_len)?;
    let complete = buffer.len() >= total_len;
    let payload_end = if complete { total_len } else { buffer.len() };
    Some((&buffer[2..payload_end], complete))
}

pub(crate) fn has_tls_record_prefix(buffer: &[u8]) -> bool {
    buffer.len() >= 2 && buffer[0] == 0x16 && buffer[1] == 0x03
}

fn looks_like_dns_header(data: &[u8]) -> bool {
    if data.len() < 13 {
        return false;
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_query = (flags & 0x8000) == 0;
    let opcode = (flags >> 11) & 0x0f;
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let nscount = u16::from_be_bytes([data[8], data[9]]);
    let first_label_len = data[12];

    is_query
        && opcode <= 2
        && qdcount == 1
        && ancount == 0
        && nscount == 0
        && (1..=63).contains(&first_label_len)
}

pub(crate) fn has_supported_tls_record_header(buffer: &[u8]) -> bool {
    has_tls_record_prefix(buffer) && buffer.len() >= 3 && (0x01..=0x04).contains(&buffer[2])
}

pub(crate) fn is_tls_client_hello(buffer: &[u8]) -> bool {
    buffer.len() >= 6
        && has_supported_tls_record_header(buffer)
        && u16::from_be_bytes([buffer[3], buffer[4]]) as usize >= 4
        && buffer[5] == 0x01
}

pub(crate) fn is_implicit_tls_port(port: u16) -> bool {
    matches!(
        port,
        443 | 465 | 636 | 853 | 990 | 992 | 993 | 994 | 995 | 6697 | 8443 | 8883 | 9443
    )
}

/// True if `frame` (a complete MySQL packet incl. its 4-byte header) is a
/// client SSLRequest: seq 1, CLIENT_SSL set, and short enough to be the
/// bare capabilities packet rather than a full HandshakeResponse (which
/// appends username/auth and is therefore longer).
pub(crate) fn is_mysql_ssl_request(frame: &[u8]) -> bool {
    const CLIENT_SSL: u32 = 0x0000_0800;
    if frame.len() < 8 {
        return false;
    }
    if frame[3] != 1 {
        return false;
    }
    let declared = frame[0] as usize | ((frame[1] as usize) << 8) | ((frame[2] as usize) << 16);
    if declared != frame.len() - 4 {
        return false;
    }
    // SSLRequest is either the bare 4-byte capability block or the full
    // 32-byte 4.1 form. Anything else is malformed and should not trigger
    // a TLS upgrade.
    if !matches!(declared, 4 | 32) {
        return false;
    }
    let cap_flags = u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]);
    if cap_flags & CLIENT_SSL == 0 {
        return false;
    }

    declared == 4 || frame[13..36].iter().all(|byte| *byte == 0)
}

pub(crate) fn extract_tls_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    if buffer.len() < 5 {
        return TcpFrameResult::Incomplete;
    }
    if !has_tls_record_prefix(buffer) {
        return TcpFrameResult::Invalid { response: None };
    }
    if !has_supported_tls_record_header(buffer) {
        buffer.clear();
        return TcpFrameResult::Invalid {
            response: Some(build_tls_alert_decode_error()),
        };
    }

    let record_len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
    let total_len = 5 + record_len;
    if record_len < 4 {
        buffer.clear();
        return TcpFrameResult::Invalid {
            response: Some(build_tls_alert_decode_error()),
        };
    }
    if total_len > MAX_TLS_RECORD_SIZE {
        buffer.clear();
        return TcpFrameResult::TooLarge {
            response: Some(build_tls_alert_decode_error()),
        };
    }
    if buffer.len() < total_len {
        return TcpFrameResult::Incomplete;
    }

    TcpFrameResult::Complete(buffer.drain(..total_len).collect())
}

pub(crate) fn extract_line_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    extract_limited_line_frame(buffer, MAX_LINE_FRAME_SIZE)
}

pub(crate) fn extract_limited_line_frame(buffer: &mut Vec<u8>, max_len: usize) -> TcpFrameResult {
    if let Some(line_end) = buffer.iter().position(|&byte| byte == b'\n') {
        let frame_len = line_end + 1;
        if frame_len > max_len {
            buffer.clear();
            return TcpFrameResult::TooLarge { response: None };
        }
        return TcpFrameResult::Complete(buffer.drain(..frame_len).collect());
    }

    if buffer.len() > max_len {
        buffer.clear();
        return TcpFrameResult::TooLarge { response: None };
    }

    TcpFrameResult::Incomplete
}

pub(crate) fn extract_ssh_payload_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    if buffer.len() < 5 {
        return TcpFrameResult::Incomplete;
    }

    let packet_len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
    if packet_len < 5 {
        buffer.clear();
        return TcpFrameResult::Invalid { response: None };
    }

    let Some(total_len) = 4usize.checked_add(packet_len) else {
        buffer.clear();
        return TcpFrameResult::TooLarge { response: None };
    };
    if total_len > MAX_SSH_PACKET_SIZE {
        buffer.clear();
        return TcpFrameResult::TooLarge { response: None };
    }
    if buffer.len() < total_len {
        return TcpFrameResult::Incomplete;
    }

    TcpFrameResult::Complete(buffer.drain(..total_len).collect())
}

pub(crate) fn extract_smtp_data_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    extract_smtp_data_frame_with_limit(buffer, MAX_SMTP_DATA_SIZE)
}

fn extract_smtp_data_frame_with_limit(buffer: &mut Vec<u8>, max_len: usize) -> TcpFrameResult {
    if buffer.starts_with(b".\r\n") {
        return TcpFrameResult::Complete(buffer.drain(..3).collect());
    }

    if let Some(offset) = find_subslice(buffer, b"\r\n.\r\n") {
        let frame_len = offset + 5;
        if frame_len > max_len {
            buffer.clear();
            return TcpFrameResult::TooLarge {
                response: Some(b"552 Message too large\r\n".to_vec()),
            };
        }
        return TcpFrameResult::Complete(buffer.drain(..frame_len).collect());
    }

    if buffer.len() > max_len {
        buffer.clear();
        return TcpFrameResult::TooLarge {
            response: Some(b"552 Message too large\r\n".to_vec()),
        };
    }

    TcpFrameResult::Incomplete
}

pub(crate) fn extract_mqtt_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    if buffer.len() < 2 {
        return TcpFrameResult::Incomplete;
    }

    let packet_type = (buffer[0] >> 4) & 0x0F;
    if !(1..=14).contains(&packet_type) {
        buffer.clear();
        return TcpFrameResult::Invalid { response: None };
    }

    let mut multiplier = 1usize;
    let mut remaining_len = 0usize;

    for i in 1..=4 {
        if i >= buffer.len() {
            return TcpFrameResult::Incomplete;
        }

        let byte = buffer[i];
        let Some(partial_len) = ((byte & 0x7F) as usize).checked_mul(multiplier) else {
            buffer.clear();
            return TcpFrameResult::Invalid { response: None };
        };
        let Some(next_remaining_len) = remaining_len.checked_add(partial_len) else {
            buffer.clear();
            return TcpFrameResult::TooLarge { response: None };
        };
        remaining_len = next_remaining_len;
        if remaining_len > MAX_MQTT_FRAME_SIZE {
            buffer.clear();
            return TcpFrameResult::TooLarge { response: None };
        }
        if byte & 0x80 == 0 {
            if mqtt_remaining_length_encoded_len(remaining_len) != i {
                buffer.clear();
                return TcpFrameResult::Invalid { response: None };
            }
            let header_len = i + 1;
            if !mqtt_fixed_header_is_valid(buffer[0], packet_type, remaining_len) {
                buffer.clear();
                return TcpFrameResult::Invalid { response: None };
            }
            let Some(total_len) = header_len.checked_add(remaining_len) else {
                buffer.clear();
                return TcpFrameResult::TooLarge { response: None };
            };
            if total_len > MAX_MQTT_FRAME_SIZE {
                buffer.clear();
                return TcpFrameResult::TooLarge { response: None };
            }
            if buffer.len() < total_len {
                return TcpFrameResult::Incomplete;
            }
            return TcpFrameResult::Complete(buffer.drain(..total_len).collect());
        }
        let Some(next_multiplier) = multiplier.checked_mul(128) else {
            buffer.clear();
            return TcpFrameResult::Invalid { response: None };
        };
        multiplier = next_multiplier;
    }

    buffer.clear();
    TcpFrameResult::Invalid { response: None }
}

fn mqtt_fixed_header_is_valid(first: u8, packet_type: u8, remaining_len: usize) -> bool {
    let flags = first & 0x0f;
    match packet_type {
        1 => flags == 0,
        2 => false,
        3 => ((flags >> 1) & 0x03) != 0x03,
        4 | 5 | 7 | 9 | 11 => flags == 0,
        6 | 8 | 10 => flags == 0x02,
        12 => flags == 0 && remaining_len == 0,
        13 => false,
        14 => flags == 0 && remaining_len == 0,
        _ => false,
    }
}

pub(crate) fn mqtt_remaining_length_encoded_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 128 {
        value /= 128;
        len += 1;
    }
    len
}

pub(crate) fn extract_mysql_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    if buffer.len() < 4 {
        return TcpFrameResult::Incomplete;
    }

    let payload_len =
        buffer[0] as usize | ((buffer[1] as usize) << 8) | ((buffer[2] as usize) << 16);
    let Some(total_len) = 4usize.checked_add(payload_len) else {
        buffer.clear();
        return TcpFrameResult::TooLarge { response: None };
    };
    if total_len > MAX_MYSQL_FRAME_SIZE {
        // Attacker-controlled length field: drop oversized declared frames so
        // the shared connection buffer cannot be grown without bound. Matches
        // the cap every other length-prefixed framer applies.
        buffer.clear();
        return TcpFrameResult::TooLarge { response: None };
    }
    if buffer.len() < total_len {
        return TcpFrameResult::Incomplete;
    }

    TcpFrameResult::Complete(buffer.drain(..total_len).collect())
}

pub(crate) fn extract_postgres_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    if buffer.is_empty() {
        return TcpFrameResult::Incomplete;
    }

    let total_len = if is_postgres_typed_message(buffer[0]) {
        if buffer.len() < 5 {
            return TcpFrameResult::Incomplete;
        }
        let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
        if len < 4 {
            buffer.clear();
            return TcpFrameResult::Invalid { response: None };
        }
        match 1usize.checked_add(len) {
            Some(total_len) if total_len <= MAX_POSTGRES_FRAME_SIZE => total_len,
            Some(_) => {
                buffer.clear();
                return TcpFrameResult::TooLarge { response: None };
            }
            None => {
                buffer.clear();
                return TcpFrameResult::TooLarge { response: None };
            }
        }
    } else {
        if buffer.len() < 4 {
            return TcpFrameResult::Incomplete;
        }
        let len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        if len < 4 {
            return optional_frame(extract_immediate_frame(buffer));
        }
        if len > MAX_POSTGRES_FRAME_SIZE {
            buffer.clear();
            return TcpFrameResult::TooLarge { response: None };
        }
        len
    };

    if buffer.len() < total_len {
        return TcpFrameResult::Incomplete;
    }

    TcpFrameResult::Complete(buffer.drain(..total_len).collect())
}

pub(crate) fn is_postgres_typed_message(byte: u8) -> bool {
    matches!(
        byte,
        b'Q' | b'X' | b'P' | b'B' | b'D' | b'E' | b'C' | b'H' | b'S' | b'F'
    )
}

pub(crate) fn extract_socks_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    match buffer.first().copied() {
        Some(0x04) => extract_socks4_frame(buffer),
        Some(0x05) => {
            if buffer.len() >= 2 {
                let greeting_len = 2 + buffer[1] as usize;
                if buffer.len() == greeting_len {
                    return optional_frame(extract_socks5_frame(buffer));
                }
            }
            if buffer.len() >= 3 && buffer[2] != 0x00 {
                buffer.clear();
                TcpFrameResult::Invalid { response: None }
            } else {
                optional_frame(extract_socks5_frame(buffer))
            }
        }
        Some(_) => optional_frame(extract_immediate_frame(buffer)),
        None => TcpFrameResult::Incomplete,
    }
}

pub(crate) fn extract_socks4_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    if buffer.len() > MAX_SOCKS4_FRAME_SIZE {
        buffer.clear();
        return TcpFrameResult::TooLarge { response: None };
    }

    if buffer.len() < 9 {
        return TcpFrameResult::Incomplete;
    }

    let Some(user_end) = buffer[8..].iter().position(|&b| b == 0) else {
        return TcpFrameResult::Incomplete;
    };
    let mut total_len = 8 + user_end + 1;
    let is_socks4a = buffer[4] == 0 && buffer[5] == 0 && buffer[6] == 0 && buffer[7] != 0;

    if is_socks4a {
        let host_start = total_len;
        let Some(host_end) = buffer[host_start..].iter().position(|&b| b == 0) else {
            return TcpFrameResult::Incomplete;
        };
        total_len = host_start + host_end + 1;
    }

    TcpFrameResult::Complete(buffer.drain(..total_len).collect())
}

pub(crate) fn extract_socks5_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buffer.len() < 2 {
        return None;
    }

    let nmethods = buffer[1] as usize;
    let greeting_len = 2usize.checked_add(nmethods)?;
    if nmethods == 0 {
        return Some(buffer.drain(..greeting_len).collect());
    }
    if nmethods > 0 {
        if buffer.len() < greeting_len {
            return None;
        }

        if buffer.len() == greeting_len {
            return Some(buffer.drain(..greeting_len).collect());
        }
    }

    if buffer.len() < 4 {
        return None;
    }

    if buffer[2] != 0x00 {
        return extract_immediate_frame(buffer);
    }

    let total_len = match buffer[3] {
        0x01 => 10,
        0x03 => {
            if buffer.len() < 5 {
                return None;
            }
            7usize.checked_add(buffer[4] as usize)?
        }
        0x04 => 22,
        _ => return extract_immediate_frame(buffer),
    };

    if buffer.len() < total_len {
        return None;
    }

    Some(buffer.drain(..total_len).collect())
}

pub(crate) fn extract_smb_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buffer.len() < 4 {
        return None;
    }

    if buffer[0] != 0x00 {
        return extract_immediate_frame(buffer);
    }

    if buffer[1] & 0xfe != 0 {
        return extract_immediate_frame(buffer);
    }

    let payload_len =
        (((buffer[1] as usize) & 0x01) << 16) | ((buffer[2] as usize) << 8) | buffer[3] as usize;
    let total_len = 4usize.checked_add(payload_len)?;
    if buffer.len() < total_len {
        return None;
    }

    Some(buffer.drain(..total_len).collect())
}

pub(crate) fn extract_rdp_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    if buffer.len() < 4 {
        return TcpFrameResult::Incomplete;
    }

    if buffer[0] != 0x03 {
        return TcpFrameResult::Invalid { response: None };
    }
    if buffer[1] != 0x00 {
        buffer.clear();
        return TcpFrameResult::Invalid { response: None };
    }

    let total_len = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
    if total_len < 7 {
        buffer.clear();
        return TcpFrameResult::Invalid { response: None };
    }
    if buffer.len() < total_len {
        return TcpFrameResult::Incomplete;
    }

    TcpFrameResult::Complete(buffer.drain(..total_len).collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LdapBerLength {
    Complete(usize),
    Incomplete,
    Invalid,
    TooLarge,
    NotLdap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BerLengthField {
    Complete {
        payload_len: usize,
        len_bytes: usize,
    },
    Incomplete,
    Invalid,
}

pub(crate) fn extract_ldap_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    if buffer.len() < 2 {
        return TcpFrameResult::Incomplete;
    }

    let total_len = match ldap_total_len(buffer) {
        LdapBerLength::Complete(total_len) => total_len,
        LdapBerLength::Incomplete => {
            if buffer.len() > MAX_LDAP_FRAME_SIZE {
                buffer.clear();
                return TcpFrameResult::TooLarge { response: None };
            }
            return TcpFrameResult::Incomplete;
        }
        LdapBerLength::Invalid => {
            buffer.clear();
            return TcpFrameResult::Invalid { response: None };
        }
        LdapBerLength::TooLarge => {
            buffer.clear();
            return TcpFrameResult::TooLarge { response: None };
        }
        LdapBerLength::NotLdap => return optional_frame(extract_immediate_frame(buffer)),
    };

    if total_len > MAX_LDAP_FRAME_SIZE {
        buffer.clear();
        return TcpFrameResult::TooLarge { response: None };
    }
    if buffer.len() < total_len {
        if buffer.len() > MAX_LDAP_FRAME_SIZE {
            buffer.clear();
            return TcpFrameResult::TooLarge { response: None };
        }
        return TcpFrameResult::Incomplete;
    }

    TcpFrameResult::Complete(buffer.drain(..total_len).collect())
}

pub(crate) fn ldap_total_len(buffer: &[u8]) -> LdapBerLength {
    if buffer.first().copied() != Some(0x30) {
        return LdapBerLength::NotLdap;
    }

    let (payload_len, len_bytes) = match parse_ber_length(&buffer[1..]) {
        BerLengthField::Complete {
            payload_len,
            len_bytes,
        } => (payload_len, len_bytes),
        BerLengthField::Incomplete => return LdapBerLength::Incomplete,
        BerLengthField::Invalid => return LdapBerLength::Invalid,
    };
    if payload_len > MAX_LDAP_BER_PAYLOAD_SIZE {
        return LdapBerLength::TooLarge;
    }

    match 1usize
        .checked_add(len_bytes)
        .and_then(|prefix_len| prefix_len.checked_add(payload_len))
    {
        Some(total_len) => LdapBerLength::Complete(total_len),
        None => LdapBerLength::TooLarge,
    }
}

pub(crate) fn parse_ber_length(data: &[u8]) -> BerLengthField {
    let Some(first) = data.first().copied() else {
        return BerLengthField::Incomplete;
    };
    if first & 0x80 == 0 {
        return BerLengthField::Complete {
            payload_len: first as usize,
            len_bytes: 1,
        };
    }

    let num_bytes = (first & 0x7F) as usize;
    if num_bytes == 0 || num_bytes > 4 {
        return BerLengthField::Invalid;
    }
    if data.len() < 1 + num_bytes {
        return BerLengthField::Incomplete;
    }
    if num_bytes == 1 {
        if data[1] < 128 {
            return BerLengthField::Invalid;
        }
    } else if data[1] == 0 {
        return BerLengthField::Invalid;
    }

    let mut len = 0usize;
    for byte in &data[1..=num_bytes] {
        len = (len << 8) | (*byte as usize);
    }
    BerLengthField::Complete {
        payload_len: len,
        len_bytes: 1 + num_bytes,
    }
}

pub(crate) fn extract_redis_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    if buffer.is_empty() {
        return TcpFrameResult::Incomplete;
    }

    if buffer.len() > MAX_REDIS_FRAME_SIZE {
        buffer.clear();
        return TcpFrameResult::TooLarge { response: None };
    }

    if buffer[0] == b'*' {
        extract_redis_resp_array_frame(buffer)
    } else {
        extract_limited_line_frame(buffer, MAX_LINE_FRAME_SIZE)
    }
}

pub(crate) fn extract_redis_resp_array_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    let Some(header_end) = find_crlf_from(buffer, 0) else {
        return TcpFrameResult::Incomplete;
    };

    let Ok(count_text) = std::str::from_utf8(&buffer[1..header_end]) else {
        buffer.clear();
        return TcpFrameResult::Invalid { response: None };
    };
    let Some(count) = parse_resp_array_count(count_text) else {
        buffer.clear();
        return TcpFrameResult::Invalid { response: None };
    };
    if count == 0 {
        buffer.clear();
        return TcpFrameResult::Invalid { response: None };
    }
    if count > MAX_REDIS_ARRAY_COUNT {
        buffer.clear();
        return TcpFrameResult::TooLarge { response: None };
    }

    let mut pos = header_end + 2;
    for _ in 0..count {
        if pos >= buffer.len() {
            return TcpFrameResult::Incomplete;
        }
        if buffer[pos] != b'$' {
            buffer.clear();
            return TcpFrameResult::Invalid { response: None };
        }

        let Some(bulk_header_end) = find_crlf_from(buffer, pos) else {
            return TcpFrameResult::Incomplete;
        };
        let Ok(bulk_len_text) = std::str::from_utf8(&buffer[pos + 1..bulk_header_end]) else {
            buffer.clear();
            return TcpFrameResult::Invalid { response: None };
        };
        let Some(bulk_len) = parse_resp_bulk_len(bulk_len_text) else {
            buffer.clear();
            return TcpFrameResult::Invalid { response: None };
        };

        pos = bulk_header_end + 2;
        let Some(bulk_len) = bulk_len else {
            buffer.clear();
            return TcpFrameResult::Invalid { response: None };
        };
        if bulk_len > MAX_REDIS_BULK_SIZE {
            buffer.clear();
            return TcpFrameResult::TooLarge { response: None };
        }
        let Some(data_end) = pos.checked_add(bulk_len) else {
            buffer.clear();
            return TcpFrameResult::TooLarge { response: None };
        };
        let Some(frame_pos) = data_end.checked_add(2) else {
            buffer.clear();
            return TcpFrameResult::TooLarge { response: None };
        };
        if frame_pos > MAX_REDIS_FRAME_SIZE {
            buffer.clear();
            return TcpFrameResult::TooLarge { response: None };
        }
        if buffer.len() < frame_pos {
            return TcpFrameResult::Incomplete;
        }
        if &buffer[data_end..frame_pos] != b"\r\n" {
            buffer.clear();
            return TcpFrameResult::Invalid { response: None };
        }
        pos = frame_pos;
    }

    TcpFrameResult::Complete(buffer.drain(..pos).collect())
}

pub(crate) fn parse_resp_array_count(text: &str) -> Option<usize> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

pub(crate) fn parse_resp_bulk_len(text: &str) -> Option<Option<usize>> {
    if text == "-1" {
        return Some(None);
    }
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok().map(Some)
}

pub(crate) fn extract_memcached_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    if buffer.is_empty() {
        return TcpFrameResult::Incomplete;
    }

    if buffer[0] == 0x80 {
        return extract_memcached_binary_frame(buffer);
    }

    let Some(line_end) = buffer.iter().position(|&byte| byte == b'\n') else {
        if buffer.len() > MAX_MEMCACHED_LINE_SIZE {
            buffer.clear();
            return TcpFrameResult::TooLarge { response: None };
        }
        return TcpFrameResult::Incomplete;
    };
    if line_end == 0 || buffer.get(line_end - 1).copied() != Some(b'\r') {
        buffer.clear();
        return TcpFrameResult::Invalid {
            response: Some(b"ERROR\r\n".to_vec()),
        };
    }

    let header_len = line_end + 1;
    if header_len > MAX_MEMCACHED_LINE_SIZE {
        buffer.clear();
        return TcpFrameResult::TooLarge { response: None };
    }

    let header = &buffer[..line_end];
    let header = header.strip_suffix(b"\r").unwrap_or(header);
    let Ok(header_text) = std::str::from_utf8(header) else {
        buffer.clear();
        return TcpFrameResult::Invalid { response: None };
    };

    match memcached_storage_body_len(header_text) {
        Ok(Some(body_len)) => {
            let Some(body_end) = header_len.checked_add(body_len) else {
                buffer.clear();
                return TcpFrameResult::TooLarge { response: None };
            };
            let Some(total_len) = body_end.checked_add(2) else {
                buffer.clear();
                return TcpFrameResult::TooLarge { response: None };
            };
            if total_len > MAX_MEMCACHED_FRAME_SIZE {
                buffer.clear();
                return TcpFrameResult::TooLarge { response: None };
            }
            if buffer.len() < total_len {
                return TcpFrameResult::Incomplete;
            }
            if &buffer[body_end..total_len] != b"\r\n" {
                buffer.clear();
                return TcpFrameResult::Invalid { response: None };
            }
            return TcpFrameResult::Complete(buffer.drain(..total_len).collect());
        }
        Ok(None) => {}
        Err(()) => {
            buffer.clear();
            return TcpFrameResult::Invalid {
                response: Some(b"ERROR\r\n".to_vec()),
            };
        }
    }

    TcpFrameResult::Complete(buffer.drain(..header_len).collect())
}

pub(crate) fn extract_memcached_binary_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    if buffer.len() < 24 {
        return TcpFrameResult::Incomplete;
    }

    let body_len = u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]) as usize;
    let Some(total_len) = 24usize.checked_add(body_len) else {
        buffer.clear();
        return TcpFrameResult::TooLarge { response: None };
    };
    if total_len > MAX_MEMCACHED_FRAME_SIZE {
        buffer.clear();
        return TcpFrameResult::TooLarge { response: None };
    }
    if buffer.len() < total_len {
        return TcpFrameResult::Incomplete;
    }

    TcpFrameResult::Complete(buffer.drain(..total_len).collect())
}

pub(crate) fn memcached_storage_body_len(header: &str) -> Result<Option<usize>, ()> {
    if header.chars().any(|ch| ch.is_whitespace() && ch != ' ') {
        return Err(());
    }
    let parts: Vec<&str> = header.split(' ').collect();
    if parts.iter().skip(1).any(|part| part.is_empty()) {
        return Err(());
    }
    let mut parts = parts.into_iter();
    let Some(command) = parts.next() else {
        return Ok(None);
    };
    let command = command.to_ascii_lowercase();
    if !matches!(
        command.as_str(),
        "set" | "add" | "replace" | "append" | "prepend" | "cas"
    ) {
        return Ok(None);
    }

    let Some(bytes) = parts.nth(3) else {
        return Err(());
    };
    parse_memcached_unsigned_decimal(bytes).map(Some).ok_or(())
}

pub(crate) fn parse_memcached_unsigned_decimal<T: std::str::FromStr>(value: &str) -> Option<T> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

pub(crate) fn find_crlf_from(haystack: &[u8], start: usize) -> Option<usize> {
    haystack
        .get(start..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
}

pub(crate) fn extract_immediate_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buffer.is_empty() {
        None
    } else {
        Some(std::mem::take(buffer))
    }
}

pub(crate) fn extract_nkn_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    if buffer.is_empty() {
        return TcpFrameResult::Incomplete;
    }
    if buffer.len() > MAX_NKN_FRAME_SIZE {
        buffer.clear();
        return TcpFrameResult::TooLarge { response: None };
    }

    let json_start = buffer
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(buffer.len());
    if json_start == buffer.len() {
        return TcpFrameResult::Incomplete;
    }

    if !matches!(buffer[json_start], b'{' | b'[') {
        return TcpFrameResult::Complete(std::mem::take(buffer));
    }

    let mut stream =
        serde_json::Deserializer::from_slice(&buffer[json_start..]).into_iter::<IgnoredAny>();
    match stream.next() {
        Some(Ok(_)) => {
            let mut frame_len = json_start + stream.byte_offset();
            while buffer
                .get(frame_len)
                .is_some_and(|byte| byte.is_ascii_whitespace())
            {
                frame_len += 1;
            }
            if frame_len != buffer.len() {
                buffer.clear();
                return TcpFrameResult::Invalid { response: None };
            }
            TcpFrameResult::Complete(buffer.drain(..frame_len).collect())
        }
        Some(Err(err)) if err.is_eof() => TcpFrameResult::Incomplete,
        Some(Err(_)) => {
            buffer.clear();
            TcpFrameResult::Invalid { response: None }
        }
        None => TcpFrameResult::Incomplete,
    }
}

pub(crate) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub(crate) fn build_tls_alert_decode_error() -> Vec<u8> {
    vec![21, 0x03, 0x03, 0x00, 0x02, 0x02, 50]
}

#[cfg(test)]
#[path = "tcp_framing_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "framing_alias_tests.rs"]
mod framing_alias_tests;
