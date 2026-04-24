//! TCP connection handler functions.
//!
//! Contains the main TCP connection handling logic for protocols.

use nettrap_proto_irc::IrcHandlerTrait;
use nettrap_proto_pop3::Pop3HandlerTrait;
use nettrap_protocols::handlers::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;

use crate::listener_context::ListenerContext;
use crate::session::SessionDestination;
use crate::utils::{
    build_http_response_with_fakefile, dump_http_post, extract_http_body, extract_http_host,
    extract_http_method, extract_http_path, extract_http_target, log_event,
};

const MAX_HTTP_HEADER_SIZE: usize = 64 * 1024;
const MAX_HTTP_REQUEST_SIZE: usize = 10 * 1024 * 1024;
const MAX_LINE_FRAME_SIZE: usize = 64 * 1024;
const MAX_SOCKS4_FRAME_SIZE: usize = 8 * 1024;
const MAX_SMTP_DATA_SIZE: usize = 50 * 1024 * 1024;
const MAX_MQTT_FRAME_SIZE: usize = 1024 * 1024;
const MAX_REDIS_FRAME_SIZE: usize = 1024 * 1024;
const MAX_REDIS_ARRAY_COUNT: usize = 1024;
const MAX_MEMCACHED_LINE_SIZE: usize = 64 * 1024;
const MAX_MEMCACHED_FRAME_SIZE: usize = 1024 * 1024;
const MAX_TLS_RECORD_SIZE: usize = 64 * 1024;
const MAX_LDAP_BER_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;
const MAX_LDAP_FRAME_SIZE: usize = MAX_LDAP_BER_PAYLOAD_SIZE + 6;
const FTP_PASSIVE_ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
const MAX_FTP_PASSIVE_TRANSFERS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpFrameMode {
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
    Immediate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TcpFrameResult {
    Complete(Vec<u8>),
    Incomplete,
    Invalid { response: Option<Vec<u8>> },
    TooLarge { response: Option<Vec<u8>> },
}

#[derive(Default)]
struct FtpPassiveState {
    listener: Option<tokio::net::TcpListener>,
}

enum FtpCommandAction {
    Response(Vec<u8>),
    Transfer {
        listener: tokio::net::TcpListener,
        transfer: nettrap_proto_ftp::FtpDataTransfer,
    },
}

#[derive(Clone, Copy)]
struct FtpCommandContext<'a> {
    peer: &'a SocketAddr,
    destination: &'a SessionDestination,
    control_local_addr: Option<SocketAddr>,
}

fn optional_frame(frame: Option<Vec<u8>>) -> TcpFrameResult {
    frame
        .map(TcpFrameResult::Complete)
        .unwrap_or(TcpFrameResult::Incomplete)
}

fn next_tcp_frame(
    buffer: &mut Vec<u8>,
    listener_name: &str,
    destination_port: u16,
    router: &nettrap_proxy::ProtocolRouter,
    smtp_data_mode: bool,
    ssh_first_packet: bool,
) -> TcpFrameResult {
    let mode = tcp_frame_mode(
        listener_name,
        buffer,
        destination_port,
        router,
        smtp_data_mode,
        ssh_first_packet,
    );

    match mode {
        TcpFrameMode::DnsTcp => optional_frame(extract_length_prefixed_frame(buffer)),
        TcpFrameMode::Http => extract_http_request(buffer),
        TcpFrameMode::Line | TcpFrameMode::SshBanner => extract_line_frame(buffer),
        TcpFrameMode::SmtpData => extract_smtp_data_frame(buffer),
        TcpFrameMode::SshPayload => optional_frame(extract_ssh_payload_frame(buffer)),
        TcpFrameMode::Mysql => optional_frame(extract_mysql_frame(buffer)),
        TcpFrameMode::Postgres => optional_frame(extract_postgres_frame(buffer)),
        TcpFrameMode::Socks => extract_socks_frame(buffer),
        TcpFrameMode::Smb => optional_frame(extract_smb_frame(buffer)),
        TcpFrameMode::Rdp => optional_frame(extract_rdp_frame(buffer)),
        TcpFrameMode::Ldap => extract_ldap_frame(buffer),
        TcpFrameMode::Mqtt => extract_mqtt_frame(buffer),
        TcpFrameMode::Tls => extract_tls_frame(buffer),
        TcpFrameMode::Redis => extract_redis_frame(buffer),
        TcpFrameMode::Memcached => extract_memcached_frame(buffer),
        TcpFrameMode::Immediate => optional_frame(extract_immediate_frame(buffer)),
    }
}

fn tcp_frame_mode(
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

    if let Some(mode) = listener_frame_mode(listener_name, ssh_first_packet) {
        return mode;
    }

    if has_tls_record_prefix(buffer) || is_tls_client_hello(buffer) {
        return TcpFrameMode::Tls;
    }

    if let Some(mode) = port_frame_mode(destination_port, buffer, ssh_first_packet) {
        return mode;
    }

    if let Some((detected, _)) = router.route_tcp(buffer, destination_port) {
        return protocol_frame_mode(detected.as_str(), ssh_first_packet)
            .unwrap_or(TcpFrameMode::Immediate);
    }

    TcpFrameMode::Immediate
}

fn listener_frame_mode(listener_name: &str, ssh_first_packet: bool) -> Option<TcpFrameMode> {
    let listener = listener_name.to_ascii_lowercase();

    if listener == "tcp" || listener == "auto" || listener == "autodetect" {
        return None;
    }

    protocol_frame_mode(&listener, ssh_first_packet)
}

fn protocol_frame_mode(protocol: &str, ssh_first_packet: bool) -> Option<TcpFrameMode> {
    if protocol == "dns" || protocol.starts_with("dns") {
        return Some(TcpFrameMode::DnsTcp);
    }

    if protocol == "tls" || protocol.starts_with("tls") {
        return Some(TcpFrameMode::Tls);
    }

    if protocol == "http" || protocol.starts_with("http") || protocol == "https" {
        return Some(TcpFrameMode::Http);
    }

    if protocol == "upnp" || protocol.starts_with("upnp") {
        return Some(TcpFrameMode::Http);
    }

    if matches!(
        protocol,
        "smtp" | "ftp" | "pop3" | "irc" | "telnet" | "finger" | "ident" | "syslogrecv"
    ) || protocol.starts_with("smtp")
        || protocol.starts_with("ftp")
        || protocol.starts_with("pop3")
        || protocol.starts_with("irc")
        || protocol.starts_with("telnet")
        || protocol.starts_with("finger")
        || protocol.starts_with("ident")
        || protocol.starts_with("syslogrecv")
    {
        return Some(TcpFrameMode::Line);
    }

    if matches!(
        protocol,
        "daytime" | "time" | "chargen" | "quotd" | "dummy" | "raw" | "echo"
    ) || protocol.starts_with("daytime")
        || protocol.starts_with("time")
        || protocol.starts_with("chargen")
        || protocol.starts_with("quotd")
        || protocol.starts_with("dummy")
        || protocol.starts_with("raw")
        || protocol.starts_with("echo")
    {
        return Some(TcpFrameMode::Immediate);
    }

    if protocol == "ssh" || protocol.starts_with("ssh") {
        return Some(if ssh_first_packet {
            TcpFrameMode::SshBanner
        } else {
            TcpFrameMode::SshPayload
        });
    }

    if protocol == "mysql" || protocol.starts_with("mysql") {
        return Some(TcpFrameMode::Mysql);
    }
    if protocol == "postgres" || protocol.starts_with("postgres") {
        return Some(TcpFrameMode::Postgres);
    }
    if protocol == "socks" || protocol.starts_with("socks") {
        return Some(TcpFrameMode::Socks);
    }
    if protocol == "smb" || protocol.starts_with("smb") {
        return Some(TcpFrameMode::Smb);
    }
    if protocol == "rdp" || protocol.starts_with("rdp") {
        return Some(TcpFrameMode::Rdp);
    }
    if protocol == "ldap" || protocol.starts_with("ldap") {
        return Some(TcpFrameMode::Ldap);
    }
    if protocol == "redis" || protocol.starts_with("redis") {
        return Some(TcpFrameMode::Redis);
    }
    if protocol == "memcached" || protocol.starts_with("memcached") {
        return Some(TcpFrameMode::Memcached);
    }
    if protocol == "mqtt" || protocol.starts_with("mqtt") {
        return Some(TcpFrameMode::Mqtt);
    }

    None
}

fn port_frame_mode(
    destination_port: u16,
    buffer: &[u8],
    ssh_first_packet: bool,
) -> Option<TcpFrameMode> {
    match destination_port {
        53 => Some(TcpFrameMode::DnsTcp),
        443 | 8443 | 8883 | 9443 if has_tls_record_prefix(buffer) => Some(TcpFrameMode::Tls),
        80 | 443 | 8000 | 8080 | 8443 | 8888 => Some(TcpFrameMode::Http),
        25 | 465 | 587 | 2525 => Some(TcpFrameMode::Line),
        21 => Some(TcpFrameMode::Line),
        110 | 995 => Some(TcpFrameMode::Line),
        194 | 6667 | 6697 => Some(TcpFrameMode::Line),
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
        389 | 636 => Some(TcpFrameMode::Ldap),
        6379 => Some(TcpFrameMode::Redis),
        11211 => Some(TcpFrameMode::Memcached),
        1883 => Some(TcpFrameMode::Mqtt),
        _ => None,
    }
}

fn extract_length_prefixed_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
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

fn has_tls_record_prefix(buffer: &[u8]) -> bool {
    buffer.len() >= 2 && buffer[0] == 0x16 && buffer[1] == 0x03
}

fn is_tls_client_hello(buffer: &[u8]) -> bool {
    buffer.len() >= 6 && buffer[0] == 0x16 && buffer[1] == 0x03 && buffer[5] == 0x01
}

fn extract_tls_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    if buffer.len() < 5 {
        return TcpFrameResult::Incomplete;
    }
    if !has_tls_record_prefix(buffer) {
        return TcpFrameResult::Invalid { response: None };
    }

    let record_len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
    let total_len = 5 + record_len;
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

fn extract_line_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    extract_limited_line_frame(buffer, MAX_LINE_FRAME_SIZE)
}

fn extract_limited_line_frame(buffer: &mut Vec<u8>, max_len: usize) -> TcpFrameResult {
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

fn extract_ssh_payload_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buffer.len() < 5 {
        None
    } else {
        Some(std::mem::take(buffer))
    }
}

fn extract_smtp_data_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    if let Some(offset) = find_subslice(buffer, b"\r\n.\r\n") {
        return TcpFrameResult::Complete(buffer.drain(..offset + 5).collect());
    }

    if let Some(offset) = find_subslice(buffer, b"\n.\n") {
        return TcpFrameResult::Complete(buffer.drain(..offset + 3).collect());
    }

    if buffer.len() > MAX_SMTP_DATA_SIZE {
        buffer.clear();
        return TcpFrameResult::TooLarge {
            response: Some(b"552 Message too large\r\n".to_vec()),
        };
    }

    TcpFrameResult::Incomplete
}

fn extract_http_request(buffer: &mut Vec<u8>) -> TcpFrameResult {
    let Some(header_end) = find_subslice(buffer, b"\r\n\r\n") else {
        if buffer.len() > MAX_HTTP_HEADER_SIZE {
            buffer.clear();
            return TcpFrameResult::TooLarge {
                response: Some(http_error_response(431, "Request Header Fields Too Large")),
            };
        }
        return TcpFrameResult::Incomplete;
    };

    let headers_end = header_end + 4;
    let headers = &buffer[..headers_end];

    if headers_end > MAX_HTTP_HEADER_SIZE {
        buffer.clear();
        return TcpFrameResult::TooLarge {
            response: Some(http_error_response(431, "Request Header Fields Too Large")),
        };
    }

    match http_body_framing(headers) {
        Ok(framing) => extract_http_request_with_framing(buffer, headers_end, framing),
        Err(HttpFrameError::Invalid) => {
            buffer.clear();
            TcpFrameResult::Invalid {
                response: Some(http_error_response(400, "Bad Request")),
            }
        }
        Err(HttpFrameError::TooLarge) => {
            buffer.clear();
            TcpFrameResult::TooLarge {
                response: Some(http_error_response(413, "Payload Too Large")),
            }
        }
    }
}

fn extract_http_request_with_framing(
    buffer: &mut Vec<u8>,
    headers_end: usize,
    framing: HttpBodyFraming,
) -> TcpFrameResult {
    match framing {
        HttpBodyFraming::Chunked => match extract_chunked_http_body_len(buffer, headers_end) {
            Ok(Some(total_len)) => TcpFrameResult::Complete(buffer.drain(..total_len).collect()),
            Ok(None) => TcpFrameResult::Incomplete,
            Err(HttpFrameError::Invalid) => {
                buffer.clear();
                TcpFrameResult::Invalid {
                    response: Some(http_error_response(400, "Bad Request")),
                }
            }
            Err(HttpFrameError::TooLarge) => {
                buffer.clear();
                TcpFrameResult::TooLarge {
                    response: Some(http_error_response(413, "Payload Too Large")),
                }
            }
        },
        HttpBodyFraming::ContentLength(content_length) => {
            let Some(total_len) = headers_end.checked_add(content_length) else {
                buffer.clear();
                return TcpFrameResult::TooLarge {
                    response: Some(http_error_response(413, "Payload Too Large")),
                };
            };
            if total_len > MAX_HTTP_REQUEST_SIZE {
                buffer.clear();
                return TcpFrameResult::TooLarge {
                    response: Some(http_error_response(413, "Payload Too Large")),
                };
            }
            if buffer.len() < total_len {
                return TcpFrameResult::Incomplete;
            }
            TcpFrameResult::Complete(buffer.drain(..total_len).collect())
        }
        HttpBodyFraming::HeadersOnly => {
            TcpFrameResult::Complete(buffer.drain(..headers_end).collect())
        }
    }
}

fn extract_chunked_http_body_len(
    buffer: &[u8],
    mut pos: usize,
) -> std::result::Result<Option<usize>, HttpFrameError> {
    loop {
        let Some(line_offset) = find_subslice(&buffer[pos..], b"\r\n") else {
            return if buffer.len() > MAX_HTTP_REQUEST_SIZE {
                Err(HttpFrameError::TooLarge)
            } else {
                Ok(None)
            };
        };
        let line_end = pos + line_offset;
        let chunk_header =
            std::str::from_utf8(&buffer[pos..line_end]).map_err(|_| HttpFrameError::Invalid)?;
        let chunk_size = usize::from_str_radix(
            chunk_header
                .split(';')
                .next()
                .ok_or(HttpFrameError::Invalid)?
                .trim(),
            16,
        )
        .map_err(|_| HttpFrameError::Invalid)?;
        pos = line_end + 2;

        if chunk_size == 0 {
            let trailers = &buffer[pos..];
            if trailers.starts_with(b"\r\n") {
                return Ok(Some(pos + 2));
            }

            let Some(trailer_end) = find_subslice(trailers, b"\r\n\r\n") else {
                return if buffer.len() > MAX_HTTP_REQUEST_SIZE {
                    Err(HttpFrameError::TooLarge)
                } else {
                    Ok(None)
                };
            };
            let total_len = pos + trailer_end + 4;
            return if total_len > MAX_HTTP_REQUEST_SIZE {
                Err(HttpFrameError::TooLarge)
            } else {
                Ok(Some(total_len))
            };
        }

        let data_end = pos
            .checked_add(chunk_size)
            .ok_or(HttpFrameError::TooLarge)?;
        let frame_end = data_end.checked_add(2).ok_or(HttpFrameError::TooLarge)?;
        if frame_end > MAX_HTTP_REQUEST_SIZE {
            return Err(HttpFrameError::TooLarge);
        }
        if buffer.len() < frame_end {
            return Ok(None);
        }

        if &buffer[data_end..data_end + 2] != b"\r\n" {
            return Err(HttpFrameError::Invalid);
        }

        pos = frame_end;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpBodyFraming {
    HeadersOnly,
    ContentLength(usize),
    Chunked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpFrameError {
    Invalid,
    TooLarge,
}

fn http_body_framing(headers: &[u8]) -> std::result::Result<HttpBodyFraming, HttpFrameError> {
    let Ok(headers) = std::str::from_utf8(headers) else {
        return Err(HttpFrameError::Invalid);
    };

    let mut transfer_encoding = None;
    let mut content_length = None;

    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };

        if name.trim().eq_ignore_ascii_case("Transfer-Encoding") {
            transfer_encoding = Some(value.trim());
        } else if name.trim().eq_ignore_ascii_case("Content-Length") {
            content_length = Some(value.trim());
        }
    }

    if let Some(encoding) = transfer_encoding {
        if encoding
            .split(',')
            .any(|value| value.trim().eq_ignore_ascii_case("chunked"))
        {
            return Ok(HttpBodyFraming::Chunked);
        }
        return Err(HttpFrameError::Invalid);
    }

    if let Some(length) = content_length {
        let length = length.parse().map_err(|_| HttpFrameError::Invalid)?;
        if length > MAX_HTTP_REQUEST_SIZE {
            return Err(HttpFrameError::TooLarge);
        }
        return Ok(HttpBodyFraming::ContentLength(length));
    }

    Ok(HttpBodyFraming::HeadersOnly)
}

fn http_error_response(status_code: u16, reason: &str) -> Vec<u8> {
    let body = format!("{status_code} {reason}\r\n");
    format!(
        "HTTP/1.1 {status_code} {reason}\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn extract_mqtt_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
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
        remaining_len += ((byte & 0x7F) as usize) * multiplier;
        if remaining_len > MAX_MQTT_FRAME_SIZE {
            buffer.clear();
            return TcpFrameResult::TooLarge { response: None };
        }
        if byte & 0x80 == 0 {
            let header_len = i + 1;
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
        multiplier *= 128;
    }

    buffer.clear();
    TcpFrameResult::Invalid { response: None }
}

fn extract_mysql_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buffer.len() < 4 {
        return None;
    }

    let payload_len =
        buffer[0] as usize | ((buffer[1] as usize) << 8) | ((buffer[2] as usize) << 16);
    let total_len = 4usize.checked_add(payload_len)?;
    if buffer.len() < total_len {
        return None;
    }

    Some(buffer.drain(..total_len).collect())
}

fn extract_postgres_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    const MAX_POSTGRES_FRAME_SIZE: usize = 16 * 1024 * 1024;

    if buffer.is_empty() {
        return None;
    }

    let total_len = if is_postgres_typed_message(buffer[0]) {
        if buffer.len() < 5 {
            return None;
        }
        let len = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as usize;
        if !(4..=MAX_POSTGRES_FRAME_SIZE).contains(&len) {
            return extract_immediate_frame(buffer);
        }
        1usize.checked_add(len)?
    } else {
        if buffer.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
        if !(4..=MAX_POSTGRES_FRAME_SIZE).contains(&len) {
            return extract_immediate_frame(buffer);
        }
        len
    };

    if buffer.len() < total_len {
        return None;
    }

    Some(buffer.drain(..total_len).collect())
}

fn is_postgres_typed_message(byte: u8) -> bool {
    matches!(
        byte,
        b'Q' | b'X' | b'P' | b'B' | b'D' | b'E' | b'C' | b'H' | b'S' | b'F'
    )
}

fn extract_socks_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    match buffer.first().copied() {
        Some(0x04) => extract_socks4_frame(buffer),
        Some(0x05) => optional_frame(extract_socks5_frame(buffer)),
        Some(_) => optional_frame(extract_immediate_frame(buffer)),
        None => TcpFrameResult::Incomplete,
    }
}

fn extract_socks4_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
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

fn extract_socks5_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buffer.len() < 2 {
        return None;
    }

    let nmethods = buffer[1] as usize;
    let greeting_len = 2usize.checked_add(nmethods)?;
    if nmethods > 0 {
        if buffer.len() < greeting_len {
            return None;
        }

        if buffer.len() == greeting_len
            || (buffer.len() > greeting_len && buffer[greeting_len] == 0x05)
        {
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

fn extract_smb_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buffer.len() < 4 {
        return None;
    }

    if buffer[0] != 0x00 {
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

fn extract_rdp_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buffer.len() < 4 {
        return None;
    }

    if buffer[0] != 0x03 {
        return extract_immediate_frame(buffer);
    }

    let total_len = u16::from_be_bytes([buffer[2], buffer[3]]) as usize;
    if total_len < 4 {
        return extract_immediate_frame(buffer);
    }
    if buffer.len() < total_len {
        return None;
    }

    Some(buffer.drain(..total_len).collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LdapBerLength {
    Complete(usize),
    Incomplete,
    Invalid,
    TooLarge,
    NotLdap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BerLengthField {
    Complete {
        payload_len: usize,
        len_bytes: usize,
    },
    Incomplete,
    Invalid,
}

fn extract_ldap_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
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

fn ldap_total_len(buffer: &[u8]) -> LdapBerLength {
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

fn parse_ber_length(data: &[u8]) -> BerLengthField {
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

    let mut len = 0usize;
    for byte in &data[1..=num_bytes] {
        len = (len << 8) | (*byte as usize);
    }
    BerLengthField::Complete {
        payload_len: len,
        len_bytes: 1 + num_bytes,
    }
}

fn extract_redis_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
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

fn extract_redis_resp_array_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
    let Some(header_end) = find_crlf_from(buffer, 0) else {
        return TcpFrameResult::Incomplete;
    };

    let Ok(count_text) = std::str::from_utf8(&buffer[1..header_end]) else {
        buffer.clear();
        return TcpFrameResult::Invalid { response: None };
    };
    let Ok(count) = count_text.parse::<usize>() else {
        buffer.clear();
        return TcpFrameResult::Invalid { response: None };
    };
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
        let Ok(bulk_len) = bulk_len_text.parse::<isize>() else {
            buffer.clear();
            return TcpFrameResult::Invalid { response: None };
        };

        pos = bulk_header_end + 2;
        if bulk_len == -1 {
            continue;
        }
        if bulk_len < -1 {
            buffer.clear();
            return TcpFrameResult::Invalid { response: None };
        }

        let bulk_len = bulk_len as usize;
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

fn extract_memcached_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
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

    if let Some(body_len) = memcached_storage_body_len(header_text) {
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

    TcpFrameResult::Complete(buffer.drain(..header_len).collect())
}

fn extract_memcached_binary_frame(buffer: &mut Vec<u8>) -> TcpFrameResult {
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

fn memcached_storage_body_len(header: &str) -> Option<usize> {
    let mut parts = header.split_whitespace();
    let command = parts.next()?.to_ascii_lowercase();
    if !matches!(
        command.as_str(),
        "set" | "add" | "replace" | "append" | "prepend" | "cas"
    ) {
        return None;
    }

    let bytes = header.split_whitespace().nth(4)?;
    bytes.parse().ok()
}

fn find_crlf_from(haystack: &[u8], start: usize) -> Option<usize> {
    haystack
        .get(start..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
}

fn extract_immediate_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buffer.is_empty() {
        None
    } else {
        Some(std::mem::take(buffer))
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Handle a TCP connection after accept.
#[allow(clippy::too_many_arguments)]
pub async fn handle_tcp_connection(
    ctx: Arc<ListenerContext>,
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    destination: SessionDestination,
    output_path: Option<&std::path::Path>,
) -> crate::Result<()> {
    let control_local_addr = stream.local_addr().ok();

    // Rate-limited connection logging - deduplicate connect events
    let dedup_key = format!("{}:{}", ctx.name(), peer.ip());
    if ctx.connection_dedup.should_log(&dedup_key) {
        log_event(output_path, ctx.name(), &peer, "connect", "").await;
    }
    ctx.fire_execute_cmd_for_session(&peer, "TCP", &destination);

    // Use protocol_handlers for handler initialization
    let smtp_handler = crate::protocol_handlers::init_smtp_handler(&ctx);
    let ftp_handler = crate::protocol_handlers::init_ftp_handler(&ctx);
    let pop3_handler = crate::protocol_handlers::init_pop3_handler(&ctx);
    let irc_handler = crate::protocol_handlers::init_irc_handler(&ctx);

    let telnet_handler = nettrap_proto_telnet::TelnetHandler::new();
    let smb_handler = nettrap_proto_smb::SmbHandler::new();
    let rdp_handler = nettrap_proto_rdp::RdpHandler::new();
    let redis_handler = nettrap_proto_redis::RedisHandler::new();
    let mysql_handler = nettrap_proto_mysql::MysqlHandler::new();
    let ldap_handler = nettrap_proto_ldap::LdapHandler::new();
    let socks_handler = nettrap_proto_socks::SocksHandler::new();
    let memcached_handler = nettrap_proto_memcached::MemcachedHandler::new();
    let postgres_handler = nettrap_proto_postgres::PostgresHandler::new();

    let webroot_server = ctx.webroot().map(crate::webroot::WebrootServer::new);

    let mut smtp_data_mode = false;
    let mut smtp_data_buf: Vec<u8> = Vec::new();
    let mut smtp_auth_state = nettrap_proto_smtp::SmtpAuthState::None;
    let mut irc_nick = "unknown".to_string();
    let mut redis_authenticated = false;
    let mut ssh_first_packet = true;
    let mut ssh_banner_sent = false;
    let mut ftp_passive_state = FtpPassiveState::default();
    let mut connection_buf: Vec<u8> = Vec::new();

    // Apply banner delay BEFORE sending banner to frustrate scanners
    let name = ctx.name();
    if ctx.banner_delay_ms() > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(ctx.banner_delay_ms())).await;
    }

    // Protocol-specific banners (only for non-TLS connections)
    // For TLS connections, banners are sent inside handle_wrapped_connection after the handshake
    if !ctx.use_ssl() {
        if let Some(banner_bytes) =
            crate::protocol_handlers::get_protocol_banner(name, ctx.banner())
        {
            stream.write_all(&banner_bytes).await?;
            stream.flush().await?;
            ssh_banner_sent = name == "ssh" || name.starts_with("ssh");
        } else if name == "ftp" || name.starts_with("ftp") {
            stream.write_all(&ftp_handler.get_banner()).await?;
            stream.flush().await?;
        }
    }

    // TLS wrapping
    if ctx.use_ssl() {
        if let Some(ref ca) = ctx.runtime.ca {
            let wrapper = nettrap_tls_mitm::TlsWrapper::new(Arc::clone(ca));
            let mut peek_buf = vec![0u8; 512];
            match stream.peek(&mut peek_buf).await {
                Ok(n)
                    if n >= 3
                        && peek_buf[0] == 0x16
                        && peek_buf[1] == 0x03
                        && peek_buf[2] <= 0x04 =>
                {
                    if let Some((ja3_str, ja3_hash)) =
                        nettrap_proto_tls::ja3::ja3_from_handshake(&peek_buf[..n])
                    {
                        tracing::info!("JA3: {} ({})", ja3_hash, ja3_str);
                        let mut nbi = crate::nbi::tls_nbi(
                            ctx.name(),
                            &peer.ip().to_string(),
                            peer.port(),
                            &destination,
                            "",
                        );
                        nbi.add("ja3", ja3_str);
                        nbi.add("ja3_hash", ja3_hash);
                        if let Some(ja4) =
                            nettrap_proto_tls::ja3::ja4_from_handshake(&peek_buf[..n])
                        {
                            tracing::info!("JA4: {}", ja4);
                            nbi.add("ja4", ja4);
                        }
                        ctx.runtime.nbi_collector.record(&nbi).await;
                    }
                    match wrapper.maybe_wrap(stream, &peek_buf[..n]).await {
                        Ok((wrapped, sni)) => {
                            if let Some(ref sni_name) = sni {
                                tracing::debug!("TLS SNI: {} from {}", sni_name, peer);
                                log_event(output_path, ctx.name(), &peer, "tls_sni", sni_name)
                                    .await;
                                let nbi = crate::nbi::tls_nbi(
                                    ctx.name(),
                                    &peer.ip().to_string(),
                                    peer.port(),
                                    &destination,
                                    sni_name,
                                );
                                ctx.runtime.nbi_collector.record(&nbi).await;
                            }
                            return handle_wrapped_connection(
                                ctx,
                                wrapped,
                                peer,
                                destination.clone(),
                                output_path,
                                &smtp_handler,
                                &ftp_handler,
                                &pop3_handler,
                                &irc_handler,
                                webroot_server.as_ref(),
                                control_local_addr,
                            )
                            .await;
                        }
                        Err(e) => {
                            tracing::debug!("TLS wrap failed for {}: {}", peer, e);
                            return Ok(());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let mut buf = vec![0u8; 4096];

    loop {
        match stream.read(&mut buf).await {
            Ok(0) => {
                tracing::debug!("TCP connection closed by {}", peer);
                return Ok(());
            }
            Ok(len) => {
                tracing::debug!("TCP '{}' received {} bytes from {}", ctx.name(), len, peer);
                let data = &buf[..len];

                if ctx.config.log_hexdump {
                    tracing::debug!("Hexdump:\n{}", crate::hexdump::hexdump(data, 256));
                }

                ctx.write_pcap_event_for_destination(data, &peer, &destination);
                connection_buf.extend_from_slice(data);

                let mut response = Vec::new();
                let mut immediate_sent_bytes = 0u64;
                let mut close_after_response = false;
                loop {
                    match next_tcp_frame(
                        &mut connection_buf,
                        name,
                        destination.port,
                        ctx.runtime.router.as_ref(),
                        smtp_data_mode,
                        ssh_first_packet,
                    ) {
                        TcpFrameResult::Complete(frame) => {
                            let first_bytes = &frame[..frame.len().min(20)];
                            if should_handle_ftp_ordered(&ctx, name, &frame, &destination) {
                                match prepare_ordered_ftp_action(
                                    &ctx,
                                    output_path,
                                    &ftp_handler,
                                    &mut ftp_passive_state,
                                    &frame,
                                    FtpCommandContext {
                                        peer: &peer,
                                        destination: &destination,
                                        control_local_addr,
                                    },
                                )
                                .await
                                {
                                    FtpCommandAction::Response(frame_response) => {
                                        response.extend_from_slice(&frame_response);
                                    }
                                    FtpCommandAction::Transfer { listener, transfer } => {
                                        let start_response = transfer.start_response.to_bytes();
                                        if !start_response.is_empty() {
                                            ctx.write_pcap_response_for_destination(
                                                &start_response,
                                                &peer,
                                                &destination,
                                            );
                                            ctx.apply_response_delay().await;
                                            stream.write_all(&start_response).await?;
                                            stream.flush().await?;
                                            immediate_sent_bytes += start_response.len() as u64;
                                        }
                                        let frame_response =
                                            finish_ftp_passive_transfer(listener, transfer).await;
                                        response.extend_from_slice(&frame_response);
                                    }
                                }
                            } else {
                                let frame_response = handle_tcp_protocol(
                                    &ctx,
                                    name,
                                    &frame,
                                    first_bytes,
                                    &peer,
                                    output_path,
                                    &smtp_handler,
                                    &ftp_handler,
                                    &pop3_handler,
                                    &irc_handler,
                                    &telnet_handler,
                                    &smb_handler,
                                    &rdp_handler,
                                    &redis_handler,
                                    &mysql_handler,
                                    &ldap_handler,
                                    &socks_handler,
                                    &memcached_handler,
                                    &postgres_handler,
                                    webroot_server.as_ref(),
                                    &destination,
                                    false,
                                    &mut smtp_data_mode,
                                    &mut smtp_data_buf,
                                    &mut smtp_auth_state,
                                    &mut irc_nick,
                                    &mut redis_authenticated,
                                    &mut ssh_first_packet,
                                    &mut ftp_passive_state,
                                    ssh_banner_sent,
                                    control_local_addr,
                                )
                                .await;
                                response.extend_from_slice(&frame_response);
                            }
                        }
                        TcpFrameResult::Incomplete => break,
                        TcpFrameResult::Invalid {
                            response: frame_response,
                        }
                        | TcpFrameResult::TooLarge {
                            response: frame_response,
                        } => {
                            if smtp_data_mode {
                                smtp_data_mode = false;
                                smtp_data_buf.clear();
                            }
                            if let Some(frame_response) = frame_response {
                                response.extend_from_slice(&frame_response);
                            }
                            close_after_response = true;
                            break;
                        }
                    }
                }

                let mut sent_bytes = immediate_sent_bytes;
                if !response.is_empty() {
                    ctx.write_pcap_response_for_destination(&response, &peer, &destination);
                    ctx.apply_response_delay().await;
                    let send_result = async {
                        stream.write_all(&response).await?;
                        stream.flush().await
                    }
                    .await;
                    if send_result.is_ok() {
                        sent_bytes += response.len() as u64;
                    }
                    ctx.update_session_bytes(&peer, "TCP", &destination, len as u64, sent_bytes);
                    send_result?;
                } else {
                    ctx.update_session_bytes(
                        &peer,
                        "TCP",
                        &destination,
                        len as u64,
                        immediate_sent_bytes,
                    );
                }
                if close_after_response {
                    return Ok(());
                }
            }
            Err(e) => {
                tracing::debug!("TCP read error from {}: {}", peer, e);
                return Ok(());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_protocol(
    ctx: &Arc<ListenerContext>,
    name: &str,
    data: &[u8],
    first_bytes: &[u8],
    peer: &std::net::SocketAddr,
    output_path: Option<&std::path::Path>,
    smtp_handler: &nettrap_proto_smtp::SmtpHandler,
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    pop3_handler: &nettrap_proto_pop3::Pop3Handler,
    irc_handler: &nettrap_proto_irc::IrcHandler,
    telnet_handler: &nettrap_proto_telnet::TelnetHandler,
    smb_handler: &nettrap_proto_smb::SmbHandler,
    rdp_handler: &nettrap_proto_rdp::RdpHandler,
    redis_handler: &nettrap_proto_redis::RedisHandler,
    mysql_handler: &nettrap_proto_mysql::MysqlHandler,
    ldap_handler: &nettrap_proto_ldap::LdapHandler,
    socks_handler: &nettrap_proto_socks::SocksHandler,
    memcached_handler: &nettrap_proto_memcached::MemcachedHandler,
    postgres_handler: &nettrap_proto_postgres::PostgresHandler,
    webroot_server: Option<&crate::webroot::WebrootServer>,
    destination: &SessionDestination,
    http_over_tls: bool,
    smtp_data_mode: &mut bool,
    smtp_data_buf: &mut Vec<u8>,
    smtp_auth_state: &mut nettrap_proto_smtp::SmtpAuthState,
    irc_nick: &mut String,
    redis_authenticated: &mut bool,
    ssh_first_packet: &mut bool,
    ftp_passive_state: &mut FtpPassiveState,
    ssh_banner_sent: bool,
    control_local_addr: Option<SocketAddr>,
) -> Vec<u8> {
    if let Some(response) = dispatch_named_tcp_protocol(
        ctx,
        name,
        data,
        peer,
        output_path,
        smtp_handler,
        ftp_handler,
        pop3_handler,
        irc_handler,
        telnet_handler,
        smb_handler,
        rdp_handler,
        redis_handler,
        mysql_handler,
        ldap_handler,
        socks_handler,
        memcached_handler,
        postgres_handler,
        webroot_server,
        destination,
        http_over_tls,
        smtp_data_mode,
        smtp_data_buf,
        smtp_auth_state,
        irc_nick,
        redis_authenticated,
        ssh_first_packet,
        ftp_passive_state,
        ssh_banner_sent,
        control_local_addr,
    )
    .await
    {
        response
    } else {
        // Auto-detect protocol via taste router
        handle_detected_protocol(
            ctx,
            data,
            first_bytes,
            peer,
            output_path,
            smtp_handler,
            ftp_handler,
            pop3_handler,
            irc_handler,
            telnet_handler,
            smb_handler,
            rdp_handler,
            redis_handler,
            mysql_handler,
            ldap_handler,
            socks_handler,
            memcached_handler,
            postgres_handler,
            webroot_server,
            destination,
            http_over_tls,
            smtp_data_mode,
            smtp_data_buf,
            smtp_auth_state,
            irc_nick,
            redis_authenticated,
            ssh_first_packet,
            ftp_passive_state,
            ssh_banner_sent,
            control_local_addr,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_named_tcp_protocol(
    ctx: &Arc<ListenerContext>,
    name: &str,
    data: &[u8],
    peer: &std::net::SocketAddr,
    output_path: Option<&std::path::Path>,
    smtp_handler: &nettrap_proto_smtp::SmtpHandler,
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    pop3_handler: &nettrap_proto_pop3::Pop3Handler,
    irc_handler: &nettrap_proto_irc::IrcHandler,
    telnet_handler: &nettrap_proto_telnet::TelnetHandler,
    smb_handler: &nettrap_proto_smb::SmbHandler,
    rdp_handler: &nettrap_proto_rdp::RdpHandler,
    redis_handler: &nettrap_proto_redis::RedisHandler,
    mysql_handler: &nettrap_proto_mysql::MysqlHandler,
    ldap_handler: &nettrap_proto_ldap::LdapHandler,
    socks_handler: &nettrap_proto_socks::SocksHandler,
    memcached_handler: &nettrap_proto_memcached::MemcachedHandler,
    postgres_handler: &nettrap_proto_postgres::PostgresHandler,
    webroot_server: Option<&crate::webroot::WebrootServer>,
    destination: &SessionDestination,
    http_over_tls: bool,
    smtp_data_mode: &mut bool,
    smtp_data_buf: &mut Vec<u8>,
    smtp_auth_state: &mut nettrap_proto_smtp::SmtpAuthState,
    irc_nick: &mut String,
    redis_authenticated: &mut bool,
    ssh_first_packet: &mut bool,
    ftp_passive_state: &mut FtpPassiveState,
    ssh_banner_sent: bool,
    control_local_addr: Option<SocketAddr>,
) -> Option<Vec<u8>> {
    if name == "dns" || name.starts_with("dns") {
        Some(handle_dns_tcp(ctx, data, peer, destination, output_path).await)
    } else if name == "http" || name.starts_with("http") {
        Some(if http_over_tls {
            handle_https(ctx, data, peer, destination, output_path, webroot_server).await
        } else {
            handle_http_plain(ctx, data, peer, destination, output_path, webroot_server).await
        })
    } else if name == "smtp" || name.starts_with("smtp") {
        let cmd_str = std::str::from_utf8(data).unwrap_or("").trim();
        crate::protocol_handlers::log_smtp_event(ctx, output_path, peer, destination, cmd_str)
            .await;
        Some(
            handle_smtp_data(
                data,
                smtp_handler,
                smtp_data_mode,
                smtp_data_buf,
                smtp_auth_state,
                output_path,
                ctx.name(),
                peer,
                ctx.config.smtp_dir.as_deref(),
            )
            .await,
        )
    } else if name == "ftp" || name.starts_with("ftp") {
        let command = std::str::from_utf8(data).unwrap_or("").trim();
        tracing::debug!("FTP command from {}: {}", peer, command);
        crate::protocol_handlers::log_ftp_event(ctx, output_path, peer, destination, command).await;
        Some(
            handle_ftp_command(
                ftp_handler,
                ftp_passive_state,
                command,
                peer,
                destination,
                control_local_addr,
            )
            .await,
        )
    } else if name == "pop3" || name.starts_with("pop3") {
        let command = std::str::from_utf8(data).unwrap_or("").trim();
        tracing::debug!("POP3 command from {}: {}", peer, command);
        crate::protocol_handlers::log_pop3_event(ctx, output_path, peer, destination, command)
            .await;
        Some(match pop3_handler.handle(command).await {
            Ok(resp) => resp.to_bytes(),
            Err(_) => b"-ERR Server error\r\n".to_vec(),
        })
    } else if name == "irc" || name.starts_with("irc") {
        Some(
            handle_irc(
                ctx,
                data,
                peer,
                destination,
                output_path,
                irc_handler,
                irc_nick,
            )
            .await,
        )
    } else if name == "telnet" || name.starts_with("telnet") {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "telnet_command",
            std::str::from_utf8(data).unwrap_or(""),
            "telnet",
        )
        .await;
        Some(
            telnet_handler
                .handle_command(std::str::from_utf8(data).unwrap_or(""))
                .to_vec(),
        )
    } else if name == "finger" || name.starts_with("finger") {
        let query = String::from_utf8_lossy(data);
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "finger_request",
            query.trim_end(),
            "finger",
        )
        .await;
        Some(
            nettrap_proto_finger::FingerHandler::new()
                .handle(&query)
                .into_bytes(),
        )
    } else if name == "ident" || name.starts_with("ident") {
        let query = String::from_utf8_lossy(data);
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "ident_request",
            query.trim_end(),
            "ident",
        )
        .await;
        Some(
            nettrap_proto_ident::IdentHandler::new()
                .handle(&query)
                .into_bytes(),
        )
    } else if name == "daytime" || name.starts_with("daytime") {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "daytime_request",
            &format!("{} bytes", data.len()),
            "daytime",
        )
        .await;
        Some(
            nettrap_proto_daytime::DaytimeHandler::new()
                .handle()
                .into_bytes(),
        )
    } else if name == "time" || name.starts_with("time") {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "time_request",
            &format!("{} bytes", data.len()),
            "time",
        )
        .await;
        Some(nettrap_proto_time::TimeHandler::new().handle())
    } else if name == "chargen" || name.starts_with("chargen") {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "chargen_request",
            &format!("{} bytes", data.len()),
            "chargen",
        )
        .await;
        let mut handler = nettrap_proto_chargen::ChargenHandler::new();
        Some(handler.handle(6))
    } else if name == "quotd" || name.starts_with("quotd") {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "quotd_request",
            &format!("{} bytes", data.len()),
            "quotd",
        )
        .await;
        Some(
            nettrap_proto_quotd::QuotdHandler::new()
                .handle()
                .into_bytes(),
        )
    } else if name == "syslogrecv" || name.starts_with("syslogrecv") {
        let parsed = nettrap_proto_syslogrecv::SyslogRecvHandler::new().handle(data);
        let detail = parsed.as_ref().map_or_else(
            || format!("{} bytes, invalid", data.len()),
            |message| {
                format!(
                    "{} bytes, facility={}, severity={}",
                    data.len(),
                    message.facility_name,
                    message.severity_name
                )
            },
        );
        log_event(output_path, ctx.name(), peer, "syslogrecv_message", &detail).await;
        let nbi = crate::nbi::raw_nbi(
            ctx.name(),
            &peer.ip().to_string(),
            peer.port(),
            destination,
            data.len(),
            "syslogrecv",
        );
        ctx.runtime.nbi_collector.record(&nbi).await;
        Some(Vec::new())
    } else if name == "dummy" || name.starts_with("dummy") {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "dummy_request",
            &format!("{} bytes", data.len()),
            "dummy",
        )
        .await;
        Some(nettrap_proto_dummy::DummyHandler::new().handle(data))
    } else if name == "ssh" || name.starts_with("ssh") {
        Some(
            handle_ssh(
                ctx,
                data,
                peer,
                destination,
                output_path,
                ssh_first_packet,
                ssh_banner_sent,
            )
            .await,
        )
    } else if name == "smb" || name.starts_with("smb") {
        let nbi = crate::nbi::raw_nbi(
            ctx.name(),
            &peer.ip().to_string(),
            peer.port(),
            destination,
            data.len(),
            "smb",
        );
        ctx.runtime.nbi_collector.record(&nbi).await;
        Some(smb_handler.handle(data))
    } else if name == "rdp" || name.starts_with("rdp") {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "rdp_request",
            &format!("{} bytes", data.len()),
            "rdp",
        )
        .await;
        Some(rdp_handler.handle(data))
    } else if name == "redis" || name.starts_with("redis") {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "redis_request",
            &format!("{} bytes", data.len()),
            "redis",
        )
        .await;
        Some(redis_handler.handle_command_with_auth_state(data, redis_authenticated))
    } else if name == "mysql" || name.starts_with("mysql") {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "mysql_request",
            &format!("{} bytes", data.len()),
            "mysql",
        )
        .await;
        Some(mysql_handler.handle(data))
    } else if name == "ldap" || name.starts_with("ldap") {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "ldap_request",
            &format!("{} bytes", data.len()),
            "ldap",
        )
        .await;
        Some(ldap_handler.handle(data))
    } else if name == "socks" || name.starts_with("socks") {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "socks_request",
            &format!("{} bytes", data.len()),
            "socks",
        )
        .await;
        Some(socks_handler.handle(data))
    } else if name == "memcached" || name.starts_with("memcached") {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "memcached_request",
            &format!("{} bytes", data.len()),
            "memcached",
        )
        .await;
        Some(memcached_handler.handle(data))
    } else if name == "mqtt" || name.starts_with("mqtt") {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "mqtt_request",
            &format!("{} bytes", data.len()),
            "mqtt",
        )
        .await;
        let nbi = crate::nbi::raw_nbi(
            ctx.name(),
            &peer.ip().to_string(),
            peer.port(),
            destination,
            data.len(),
            "mqtt",
        );
        ctx.runtime.nbi_collector.record(&nbi).await;
        Some(nettrap_proto_mqtt::MqttHandler::new().handle_packet(data))
    } else if name == "tls" || name.starts_with("tls") {
        Some(handle_tls_plain(ctx, data, peer, destination, output_path).await)
    } else if name == "upnp" || name.starts_with("upnp") {
        Some(handle_upnp_tcp(ctx, data, peer, destination, output_path).await)
    } else if name == "nkn" || name.starts_with("nkn") {
        let handler = nettrap_proto_nkn::NknHandler::new();
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "nkn_request",
            &format!("{} bytes", data.len()),
            "nkn",
        )
        .await;
        Some(handler.handle(data))
    } else if name == "postgres" || name.starts_with("postgres") {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "postgres_request",
            &format!("{} bytes", data.len()),
            "postgres",
        )
        .await;
        Some(postgres_handler.handle(data))
    } else if name == "raw" || name.starts_with("raw") || name == "echo" || name.starts_with("echo")
    {
        let raw_handler = if let Some(custom) = ctx.custom_response() {
            nettrap_proto_raw::RawHandler::from_custom_response(custom)
        } else {
            nettrap_proto_raw::RawHandler::new()
        };
        let raw_resp = raw_handler.handle(data);
        log_event(
            output_path,
            ctx.name(),
            peer,
            "raw",
            &format!("{} bytes", data.len()),
        )
        .await;
        let nbi = crate::nbi::raw_nbi(
            ctx.name(),
            &peer.ip().to_string(),
            peer.port(),
            destination,
            data.len(),
            "",
        );
        ctx.runtime.nbi_collector.record(&nbi).await;
        Some(raw_resp.to_bytes())
    } else {
        None
    }
}

async fn handle_ftp_command(
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    ftp_passive_state: &mut FtpPassiveState,
    command: &str,
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    control_local_addr: Option<SocketAddr>,
) -> Vec<u8> {
    match prepare_ftp_command(
        ftp_handler,
        ftp_passive_state,
        command,
        peer,
        destination,
        control_local_addr,
    )
    .await
    {
        FtpCommandAction::Response(response) => response,
        FtpCommandAction::Transfer { listener, transfer } => {
            let mut response = transfer.start_response.to_bytes();
            response.extend_from_slice(&finish_ftp_passive_transfer(listener, transfer).await);
            response
        }
    }
}

async fn prepare_ftp_command(
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    ftp_passive_state: &mut FtpPassiveState,
    command: &str,
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    control_local_addr: Option<SocketAddr>,
) -> FtpCommandAction {
    let verb = ftp_command_verb(command);
    if verb == "PASV" || verb == "EPSV" {
        return FtpCommandAction::Response(
            open_ftp_passive_data_socket(
                ftp_handler,
                ftp_passive_state,
                peer,
                destination,
                control_local_addr,
                verb == "EPSV",
            )
            .await,
        );
    }

    if matches!(verb.as_str(), "LIST" | "NLST" | "RETR") {
        let Some(listener) = ftp_passive_state.listener.take() else {
            return FtpCommandAction::Response(
                nettrap_proto_ftp::FtpResponse::new(425, "Use PASV or EPSV first").to_bytes(),
            );
        };

        return match ftp_handler.prepare_data_transfer(command) {
            Ok(transfer) => FtpCommandAction::Transfer { listener, transfer },
            Err(response) => FtpCommandAction::Response(response.to_bytes()),
        };
    }

    FtpCommandAction::Response(ftp_handler.handle(command).to_bytes())
}

fn ftp_command_verb(command: &str) -> String {
    command
        .split_ascii_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches('\r')
        .to_ascii_uppercase()
}

fn should_handle_ftp_ordered(
    ctx: &Arc<ListenerContext>,
    name: &str,
    data: &[u8],
    destination: &SessionDestination,
) -> bool {
    let listener = name.to_ascii_lowercase();
    if listener == "ftp" || listener.starts_with("ftp") {
        return true;
    }

    let Some((detected_name, score)) = ctx.runtime.router.route_tcp(data, destination.port) else {
        return false;
    };
    if !(detected_name == "ftp" || detected_name.starts_with("ftp")) {
        return false;
    }

    score >= 50 || ctx.runtime.router.default_tcp_handler() == Some(detected_name.as_str())
}

async fn prepare_ordered_ftp_action(
    ctx: &Arc<ListenerContext>,
    output_path: Option<&std::path::Path>,
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    ftp_passive_state: &mut FtpPassiveState,
    data: &[u8],
    command_context: FtpCommandContext<'_>,
) -> FtpCommandAction {
    let command = std::str::from_utf8(data).unwrap_or("").trim();
    tracing::debug!("FTP command from {}: {}", command_context.peer, command);
    crate::protocol_handlers::log_ftp_event(
        ctx,
        output_path,
        command_context.peer,
        command_context.destination,
        command,
    )
    .await;
    prepare_ftp_command(
        ftp_handler,
        ftp_passive_state,
        command,
        command_context.peer,
        command_context.destination,
        command_context.control_local_addr,
    )
    .await
}

async fn open_ftp_passive_data_socket(
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    ftp_passive_state: &mut FtpPassiveState,
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    control_local_addr: Option<SocketAddr>,
    extended: bool,
) -> Vec<u8> {
    match bind_ftp_passive_listener(ftp_handler, peer, control_local_addr).await {
        Ok((listener, port)) => {
            ftp_passive_state.listener = Some(listener);
            if extended {
                nettrap_proto_ftp::FtpResponse::new(
                    229,
                    format!("Entering Extended Passive Mode (|||{}|)", port),
                )
                .to_bytes()
            } else {
                let host = ftp_passive_response_host(ftp_handler, destination, control_local_addr);
                let p1 = port / 256;
                let p2 = port % 256;
                nettrap_proto_ftp::FtpResponse::new(
                    227,
                    format!("Entering Passive Mode ({},{},{})", host, p1, p2),
                )
                .to_bytes()
            }
        }
        Err(err) => {
            tracing::warn!("FTP passive bind failed for {}: {}", peer, err);
            nettrap_proto_ftp::FtpResponse::new(425, "Can't open passive connection").to_bytes()
        }
    }
}

async fn bind_ftp_passive_listener(
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    peer: &std::net::SocketAddr,
    control_local_addr: Option<SocketAddr>,
) -> std::io::Result<(tokio::net::TcpListener, u16)> {
    let (start, end) = ftp_handler.passive_ports();
    let (lo, hi) = if start <= end {
        (start, end)
    } else {
        (end, start)
    };
    let range = (hi as u32).saturating_sub(lo as u32).saturating_add(1);
    let first = ftp_handler.next_passive_port();
    let first_offset = if (lo..=hi).contains(&first) {
        first - lo
    } else {
        0
    } as u32;
    let bind_ip = ftp_passive_bind_ip(peer, control_local_addr);
    let mut last_error = None;

    for offset in 0..range {
        let port = lo + ((first_offset + offset) % range) as u16;
        let bind_addr = std::net::SocketAddr::new(bind_ip, port);
        match tokio::net::TcpListener::bind(bind_addr).await {
            Ok(listener) => {
                let bound_port = listener
                    .local_addr()
                    .map(|addr| addr.port())
                    .unwrap_or(port);
                return Ok((listener, bound_port));
            }
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "empty FTP PASV range")
    }))
}

fn ftp_passive_bind_ip(peer: &SocketAddr, control_local_addr: Option<SocketAddr>) -> IpAddr {
    if let Some(local_addr) = control_local_addr {
        let local_ip = local_addr.ip();
        if !local_ip.is_unspecified() {
            return local_ip;
        }
    }

    if peer.ip().is_ipv6() {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }
}

fn ftp_passive_response_host(
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    destination: &SessionDestination,
    control_local_addr: Option<SocketAddr>,
) -> String {
    let configured = ftp_handler.passive_address().trim();
    if !configured.is_empty() && configured != "0,0,0,0" {
        if configured.contains(',') {
            return configured.to_string();
        }
        if let Ok(ip) = configured.parse::<std::net::Ipv4Addr>() {
            return ipv4_to_ftp_host(ip);
        }
    }

    if let Some(SocketAddr::V4(local_addr)) = control_local_addr {
        let ip = *local_addr.ip();
        if !ip.is_unspecified() {
            return ipv4_to_ftp_host(ip);
        }
    }

    if let Ok(IpAddr::V4(ip)) = destination.ip.parse::<IpAddr>() {
        if ip.is_loopback() {
            return ipv4_to_ftp_host(ip);
        }
    }

    "127,0,0,1".to_string()
}

fn ipv4_to_ftp_host(ip: std::net::Ipv4Addr) -> String {
    let octets = ip.octets();
    format!("{},{},{},{}", octets[0], octets[1], octets[2], octets[3])
}

fn ftp_passive_transfer_semaphore() -> Arc<Semaphore> {
    static SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();
    Arc::clone(SEMAPHORE.get_or_init(|| Arc::new(Semaphore::new(MAX_FTP_PASSIVE_TRANSFERS))))
}

async fn finish_ftp_passive_transfer(
    listener: tokio::net::TcpListener,
    transfer: nettrap_proto_ftp::FtpDataTransfer,
) -> Vec<u8> {
    let Ok(_permit) = ftp_passive_transfer_semaphore().try_acquire_owned() else {
        return nettrap_proto_ftp::FtpResponse::new(425, "Too many passive transfers").to_bytes();
    };

    let accept_result = tokio::time::timeout(FTP_PASSIVE_ACCEPT_TIMEOUT, listener.accept()).await;
    let (mut data_stream, data_peer) = match accept_result {
        Ok(Ok(accepted)) => accepted,
        Ok(Err(err)) => {
            tracing::warn!("FTP passive accept failed: {}", err);
            return nettrap_proto_ftp::FtpResponse::new(425, "Can't open data connection")
                .to_bytes();
        }
        Err(_) => {
            return nettrap_proto_ftp::FtpResponse::new(425, "Data connection timed out")
                .to_bytes();
        }
    };

    tracing::debug!("FTP passive data connection accepted from {}", data_peer);
    let send_result = async {
        data_stream.write_all(&transfer.data).await?;
        data_stream.flush().await?;
        data_stream.shutdown().await
    }
    .await;

    if let Err(err) = send_result {
        tracing::warn!("FTP passive transfer failed: {}", err);
        nettrap_proto_ftp::FtpResponse::new(426, "Connection closed; transfer aborted").to_bytes()
    } else {
        transfer.complete_response.to_bytes()
    }
}

async fn handle_dns_tcp(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
) -> Vec<u8> {
    use nettrap_proto_dns::handler::DnsHandlerTrait;

    let tcp_dns_handler = crate::protocol_handlers::init_dns_handler(ctx);

    if data.len() < 2 {
        return Vec::new();
    }

    let dns_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + dns_len {
        tracing::debug!(
            "DNS TCP frame incomplete from {}: declared={} available={}",
            peer,
            dns_len,
            data.len().saturating_sub(2)
        );
        return Vec::new();
    }

    let dns_data = &data[2..2 + dns_len];
    match tcp_dns_handler.handle_query(dns_data, *peer).await {
        Ok(response) => {
            let len_bytes = (response.len() as u16).to_be_bytes();
            let mut tcp_response = Vec::with_capacity(2 + response.len());
            tcp_response.extend_from_slice(&len_bytes);
            tcp_response.extend_from_slice(&response);
            log_event(
                output_path,
                ctx.name(),
                peer,
                "dns_tcp_query",
                &format!("{} bytes", data.len()),
            )
            .await;
            let nbi = crate::nbi::dns_nbi(
                ctx.name(),
                &peer.ip().to_string(),
                peer.port(),
                destination,
                "",
                "tcp_query",
            );
            ctx.runtime.nbi_collector.record(&nbi).await;
            tcp_response
        }
        Err(e) => {
            tracing::warn!("DNS TCP error: {}", e);
            Vec::new()
        }
    }
}

async fn handle_irc(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
    irc_handler: &nettrap_proto_irc::IrcHandler,
    irc_nick: &mut String,
) -> Vec<u8> {
    let command = std::str::from_utf8(data).unwrap_or("").trim();
    let upper_cmd = command.to_uppercase();
    if upper_cmd.starts_with("NICK ") {
        let raw_nick = command.get(5..).unwrap_or("").trim();
        *irc_nick = raw_nick
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .take(30)
            .collect();
        if irc_nick.is_empty() {
            *irc_nick = "unknown".to_string();
        }
    }
    tracing::debug!("IRC command from {} ({}): {}", peer, irc_nick, command);
    crate::protocol_handlers::log_irc_event(ctx, output_path, peer, destination, irc_nick, command)
        .await;
    match irc_handler.handle(command, irc_nick).await {
        Ok(resp) => resp.to_bytes(),
        Err(_) => Vec::new(),
    }
}

async fn handle_tls_plain(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
) -> Vec<u8> {
    let sni = nettrap_proto_tls::fingerprint::extract_sni(data).unwrap_or_default();
    let detail = if sni.is_empty() {
        format!("{} bytes", data.len())
    } else {
        format!("{} bytes, sni={}", data.len(), sni)
    };
    log_event(output_path, ctx.name(), peer, "tls_client_hello", &detail).await;

    let mut nbi = crate::nbi::tls_nbi(
        ctx.name(),
        &peer.ip().to_string(),
        peer.port(),
        destination,
        &sni,
    );
    nbi.add("data_length", data.len().to_string());
    if let Some((ja3_str, ja3_hash)) = nettrap_proto_tls::ja3::ja3_from_handshake(data) {
        tracing::info!("JA3: {} ({})", ja3_hash, ja3_str);
        nbi.add("ja3", ja3_str);
        nbi.add("ja3_hash", ja3_hash);
    }
    if let Some(ja4) = nettrap_proto_tls::ja3::ja4_from_handshake(data) {
        tracing::info!("JA4: {}", ja4);
        nbi.add("ja4", ja4);
    }
    ctx.runtime.nbi_collector.record(&nbi).await;

    build_tls_response()
}

async fn handle_upnp_tcp(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
) -> Vec<u8> {
    let response = nettrap_proto_upnp::UpnpHandler::new()
        .with_listen_ip(destination.ip.clone())
        .handle_http(data);
    if response.is_empty() {
        return response;
    }

    log_event(
        output_path,
        ctx.name(),
        peer,
        "upnp_http_request",
        &format!("{} bytes", data.len()),
    )
    .await;
    let nbi = crate::nbi::raw_nbi(
        ctx.name(),
        &peer.ip().to_string(),
        peer.port(),
        destination,
        data.len(),
        "upnp",
    );
    ctx.runtime.nbi_collector.record(&nbi).await;

    response
}

async fn handle_ssh(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
    first_packet: &mut bool,
    banner_already_sent: bool,
) -> Vec<u8> {
    let handler = nettrap_proto_ssh::SshHandler::new();

    if *first_packet {
        *first_packet = false;
        // Parse and log client version string
        if let Some(client_version) = nettrap_proto_ssh::SshHandler::parse_client_version(data) {
            let is_brute = nettrap_proto_ssh::SshHandler::is_brute_force_client(&client_version);
            tracing::warn!(
                "SSH client version from {}: {} (brute_force_indicator={})",
                peer,
                client_version,
                is_brute
            );
            crate::protocol_handlers::log_tcp_event(
                ctx,
                output_path,
                peer,
                destination,
                "ssh_version",
                &client_version,
                "ssh",
            )
            .await;
        } else {
            crate::protocol_handlers::log_tcp_event(
                ctx,
                output_path,
                peer,
                destination,
                "ssh_handshake",
                &format!("{} bytes", data.len()),
                "ssh",
            )
            .await;
        }
        build_ssh_first_response(&handler, banner_already_sent)
    } else {
        // Subsequent packets: log and send auth failure (disconnect)
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            "ssh_data",
            &format!("{} bytes", data.len()),
            "ssh",
        )
        .await;
        handler.build_auth_failure()
    }
}

fn build_ssh_first_response(
    handler: &nettrap_proto_ssh::SshHandler,
    banner_already_sent: bool,
) -> Vec<u8> {
    let mut resp = if banner_already_sent {
        Vec::new()
    } else {
        handler.get_banner()
    };
    resp.extend_from_slice(&handler.build_kexinit());
    resp
}

#[allow(clippy::too_many_arguments)]
async fn handle_detected_protocol(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    _first_bytes: &[u8],
    peer: &std::net::SocketAddr,
    output_path: Option<&std::path::Path>,
    smtp_handler: &nettrap_proto_smtp::SmtpHandler,
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    pop3_handler: &nettrap_proto_pop3::Pop3Handler,
    irc_handler: &nettrap_proto_irc::IrcHandler,
    telnet_handler: &nettrap_proto_telnet::TelnetHandler,
    smb_handler: &nettrap_proto_smb::SmbHandler,
    rdp_handler: &nettrap_proto_rdp::RdpHandler,
    redis_handler: &nettrap_proto_redis::RedisHandler,
    mysql_handler: &nettrap_proto_mysql::MysqlHandler,
    ldap_handler: &nettrap_proto_ldap::LdapHandler,
    socks_handler: &nettrap_proto_socks::SocksHandler,
    memcached_handler: &nettrap_proto_memcached::MemcachedHandler,
    postgres_handler: &nettrap_proto_postgres::PostgresHandler,
    webroot_server: Option<&crate::webroot::WebrootServer>,
    destination: &SessionDestination,
    http_over_tls: bool,
    smtp_data_mode: &mut bool,
    smtp_data_buf: &mut Vec<u8>,
    smtp_auth_state: &mut nettrap_proto_smtp::SmtpAuthState,
    irc_nick: &mut String,
    redis_authenticated: &mut bool,
    ssh_first_packet: &mut bool,
    ftp_passive_state: &mut FtpPassiveState,
    ssh_banner_sent: bool,
    control_local_addr: Option<SocketAddr>,
) -> Vec<u8> {
    if let Some((detected_name, score)) = ctx.runtime.router.route_tcp(data, destination.port) {
        let is_default = ctx.runtime.router.default_tcp_handler() == Some(detected_name.as_str());
        let is_raw_fallback = detected_name == "raw";
        if score >= 50 || is_default || is_raw_fallback {
            tracing::debug!(
                "TCP '{}' routed {} bytes from {} to handler '{}' (score={}, default={})",
                ctx.name(),
                data.len(),
                peer,
                detected_name,
                score,
                is_default
            );

            if let Some(response) = dispatch_named_tcp_protocol(
                ctx,
                &detected_name,
                data,
                peer,
                output_path,
                smtp_handler,
                ftp_handler,
                pop3_handler,
                irc_handler,
                telnet_handler,
                smb_handler,
                rdp_handler,
                redis_handler,
                mysql_handler,
                ldap_handler,
                socks_handler,
                memcached_handler,
                postgres_handler,
                webroot_server,
                destination,
                http_over_tls,
                smtp_data_mode,
                smtp_data_buf,
                smtp_auth_state,
                irc_nick,
                redis_authenticated,
                ssh_first_packet,
                ftp_passive_state,
                ssh_banner_sent,
                control_local_addr,
            )
            .await
            {
                return response;
            }
        }
    }

    tracing::debug!("Unknown TCP protocol from {}", peer);
    log_event(
        output_path,
        ctx.name(),
        peer,
        "raw",
        &format!("{} bytes", data.len()),
    )
    .await;
    let nbi = crate::nbi::raw_nbi(
        ctx.name(),
        &peer.ip().to_string(),
        peer.port(),
        destination,
        data.len(),
        "unknown",
    );
    ctx.runtime.nbi_collector.record(&nbi).await;

    let raw_handler = nettrap_proto_raw::RawHandler::new();
    raw_handler.handle(data).to_bytes()
}

/// Handle connection wrapped with TLS.
#[allow(clippy::too_many_arguments)]
pub async fn handle_wrapped_connection(
    ctx: Arc<ListenerContext>,
    mut stream: nettrap_tls_mitm::WrappedStream,
    peer: std::net::SocketAddr,
    destination: SessionDestination,
    output_path: Option<&std::path::Path>,
    smtp_handler: &nettrap_proto_smtp::SmtpHandler,
    ftp_handler: &nettrap_proto_ftp::FtpHandler,
    pop3_handler: &nettrap_proto_pop3::Pop3Handler,
    irc_handler: &nettrap_proto_irc::IrcHandler,
    webroot_server: Option<&crate::webroot::WebrootServer>,
    control_local_addr: Option<SocketAddr>,
) -> crate::Result<()> {
    let name = ctx.name();
    let telnet_handler = nettrap_proto_telnet::TelnetHandler::new();
    let smb_handler = nettrap_proto_smb::SmbHandler::new();
    let rdp_handler = nettrap_proto_rdp::RdpHandler::new();
    let redis_handler = nettrap_proto_redis::RedisHandler::new();
    let mysql_handler = nettrap_proto_mysql::MysqlHandler::new();
    let ldap_handler = nettrap_proto_ldap::LdapHandler::new();
    let socks_handler = nettrap_proto_socks::SocksHandler::new();
    let memcached_handler = nettrap_proto_memcached::MemcachedHandler::new();
    let postgres_handler = nettrap_proto_postgres::PostgresHandler::new();
    let mut smtp_data_mode = false;
    let mut smtp_data_buf: Vec<u8> = Vec::new();
    let mut smtp_auth_state = nettrap_proto_smtp::SmtpAuthState::None;
    let mut irc_nick = "unknown".to_string();
    let mut redis_authenticated = false;
    let mut ssh_first_packet = true;
    let mut ftp_passive_state = FtpPassiveState::default();
    let mut connection_buf: Vec<u8> = Vec::new();

    // Apply banner delay before sending TLS banner
    if ctx.banner_delay_ms() > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(ctx.banner_delay_ms())).await;
    }

    // Send TLS banner
    if name == "smtp" || name.starts_with("smtp") {
        stream
            .write_all(smtp_handler.get_welcome_banner().as_bytes())
            .await?;
        stream.flush().await?;
    } else if name == "ftp" || name.starts_with("ftp") {
        stream.write_all(&ftp_handler.get_banner()).await?;
        stream.flush().await?;
    } else if name == "pop3" || name.starts_with("pop3") {
        stream
            .write_all(pop3_handler.get_welcome_banner().as_bytes())
            .await?;
        stream.flush().await?;
    }

    let mut buf = vec![0u8; 4096];

    loop {
        match stream.read(&mut buf).await {
            Ok(0) => return Ok(()),
            Ok(len) => {
                let data = &buf[..len];

                if ctx.config.log_hexdump {
                    tracing::debug!("TLS Hexdump:\n{}", crate::hexdump::hexdump(data, 256));
                }

                ctx.write_pcap_event_for_destination(data, &peer, &destination);
                connection_buf.extend_from_slice(data);

                let mut response = Vec::new();
                let mut immediate_sent_bytes = 0u64;
                let mut close_after_response = false;
                loop {
                    match next_tcp_frame(
                        &mut connection_buf,
                        name,
                        destination.port,
                        ctx.runtime.router.as_ref(),
                        smtp_data_mode,
                        ssh_first_packet,
                    ) {
                        TcpFrameResult::Complete(frame) => {
                            let first_bytes = &frame[..frame.len().min(20)];
                            if should_handle_ftp_ordered(&ctx, name, &frame, &destination) {
                                match prepare_ordered_ftp_action(
                                    &ctx,
                                    output_path,
                                    ftp_handler,
                                    &mut ftp_passive_state,
                                    &frame,
                                    FtpCommandContext {
                                        peer: &peer,
                                        destination: &destination,
                                        control_local_addr,
                                    },
                                )
                                .await
                                {
                                    FtpCommandAction::Response(frame_response) => {
                                        response.extend_from_slice(&frame_response);
                                    }
                                    FtpCommandAction::Transfer { listener, transfer } => {
                                        let start_response = transfer.start_response.to_bytes();
                                        if !start_response.is_empty() {
                                            ctx.write_pcap_response_for_destination(
                                                &start_response,
                                                &peer,
                                                &destination,
                                            );
                                            ctx.apply_response_delay().await;
                                            stream.write_all(&start_response).await?;
                                            stream.flush().await?;
                                            immediate_sent_bytes += start_response.len() as u64;
                                        }
                                        let frame_response =
                                            finish_ftp_passive_transfer(listener, transfer).await;
                                        response.extend_from_slice(&frame_response);
                                    }
                                }
                            } else {
                                let frame_response = handle_tcp_protocol(
                                    &ctx,
                                    name,
                                    &frame,
                                    first_bytes,
                                    &peer,
                                    output_path,
                                    smtp_handler,
                                    ftp_handler,
                                    pop3_handler,
                                    irc_handler,
                                    &telnet_handler,
                                    &smb_handler,
                                    &rdp_handler,
                                    &redis_handler,
                                    &mysql_handler,
                                    &ldap_handler,
                                    &socks_handler,
                                    &memcached_handler,
                                    &postgres_handler,
                                    webroot_server,
                                    &destination,
                                    true,
                                    &mut smtp_data_mode,
                                    &mut smtp_data_buf,
                                    &mut smtp_auth_state,
                                    &mut irc_nick,
                                    &mut redis_authenticated,
                                    &mut ssh_first_packet,
                                    &mut ftp_passive_state,
                                    false,
                                    control_local_addr,
                                )
                                .await;
                                response.extend_from_slice(&frame_response);
                            }
                        }
                        TcpFrameResult::Incomplete => break,
                        TcpFrameResult::Invalid {
                            response: frame_response,
                        }
                        | TcpFrameResult::TooLarge {
                            response: frame_response,
                        } => {
                            if smtp_data_mode {
                                smtp_data_mode = false;
                                smtp_data_buf.clear();
                            }
                            if let Some(frame_response) = frame_response {
                                response.extend_from_slice(&frame_response);
                            }
                            close_after_response = true;
                            break;
                        }
                    }
                }

                let mut sent_bytes = immediate_sent_bytes;
                if !response.is_empty() {
                    ctx.write_pcap_response_for_destination(&response, &peer, &destination);
                    ctx.apply_response_delay().await;
                    let send_result = async {
                        stream.write_all(&response).await?;
                        stream.flush().await
                    }
                    .await;
                    if send_result.is_ok() {
                        sent_bytes += response.len() as u64;
                    }
                    ctx.update_session_bytes(&peer, "TCP", &destination, len as u64, sent_bytes);
                    send_result?;
                } else {
                    ctx.update_session_bytes(
                        &peer,
                        "TCP",
                        &destination,
                        len as u64,
                        immediate_sent_bytes,
                    );
                }
                if close_after_response {
                    return Ok(());
                }
            }
            Err(e) => {
                tracing::debug!("TLS read error from {}: {}", peer, e);
                return Ok(());
            }
        }
    }
}

async fn handle_http_plain(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
    webroot_server: Option<&crate::webroot::WebrootServer>,
) -> Vec<u8> {
    handle_http_response(
        ctx,
        data,
        peer,
        destination,
        output_path,
        webroot_server,
        false,
    )
    .await
}

async fn handle_https(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
    webroot_server: Option<&crate::webroot::WebrootServer>,
) -> Vec<u8> {
    handle_http_response(
        ctx,
        data,
        peer,
        destination,
        output_path,
        webroot_server,
        true,
    )
    .await
}

async fn handle_http_response(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
    webroot_server: Option<&crate::webroot::WebrootServer>,
    over_tls: bool,
) -> Vec<u8> {
    let event_name = if over_tls {
        "https_request"
    } else {
        "http_request"
    };
    let transport_label = if over_tls { "HTTPS" } else { "HTTP" };

    log_event(output_path, ctx.name(), peer, event_name, "").await;

    let target = extract_http_target(data);
    let path = extract_http_path(data);
    let host = extract_http_host(data);
    let method = extract_http_method(data);
    let nbi = crate::nbi::http_nbi(crate::nbi::HttpNbiInput {
        listener: ctx.name(),
        src_ip: &peer.ip().to_string(),
        src_port: peer.port(),
        destination,
        method: &method,
        uri: &target,
        host: &host,
        user_agent: "",
        body_len: data.len(),
    });
    ctx.runtime.nbi_collector.record(&nbi).await;

    if ctx.dump_http_posts() && method.eq_ignore_ascii_case("POST") {
        if let Some(body) = extract_http_body(data) {
            let dump_prefix = ctx.dump_prefix().map(|s| s.to_string());
            dump_http_post(&body, &dump_prefix, peer).await;
        }
    }

    // DynDNS checkip emulation
    if is_dyn_dns_checkip_request(&host, &path) {
        let src_ip = peer.ip().to_string();
        let body = format!("Current IP Address: {}", src_ip);
        let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
        tracing::info!(
            "DynDNS checkip response for {} ({})",
            src_ip,
            transport_label
        );
        return format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nDate: {}\r\nServer: DynDNS-CheckIP/1.0\r\n\r\n{}",
            body.len(), date, body
        ).into_bytes();
    }

    // WPAD / proxy.pac
    if path == "/wpad.dat" || path == "/proxy.pac" {
        let pac = "function FindProxyForURL(url, host) { return \"DIRECT\"; }";
        let date = crate::faketime::fake_now().format("%a, %d %b %Y %H:%M:%S GMT");
        tracing::info!("WPAD/PAC response for {} ({})", peer, transport_label);
        return format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nDate: {}\r\n\r\n{}",
            pac.len(), date, pac
        ).into_bytes();
    }

    // Custom response or webroot
    if let Some(ref crc) = ctx.config.custom_response_config {
        if let Some(resp) = crc.build_response_for_request(&host, &path, &target) {
            return resp;
        }
    }

    if let Some(ws) = webroot_server {
        ws.build_http_response(&path)
    } else {
        build_http_response_with_fakefile(&path, ctx.server_version().unwrap_or("NetTrap"))
    }
}

/// Handle SMTP data mode.
#[allow(clippy::too_many_arguments)]
pub async fn handle_smtp_data(
    data: &[u8],
    smtp_handler: &nettrap_proto_smtp::SmtpHandler,
    smtp_data_mode: &mut bool,
    smtp_data_buf: &mut Vec<u8>,
    smtp_auth_state: &mut nettrap_proto_smtp::SmtpAuthState,
    output_path: Option<&std::path::Path>,
    listener_name: &str,
    peer: &std::net::SocketAddr,
    smtp_dir: Option<&std::path::Path>,
) -> Vec<u8> {
    if *smtp_data_mode {
        if smtp_data_buf.len() + data.len() > MAX_SMTP_DATA_SIZE {
            tracing::warn!(
                "SMTP DATA buffer exceeded limit from {} ({} bytes), discarding",
                peer,
                smtp_data_buf.len() + data.len()
            );
            *smtp_data_mode = false;
            smtp_data_buf.clear();
            return b"552 Message too large\r\n".to_vec();
        }
        smtp_data_buf.extend_from_slice(data);
        let has_terminator = smtp_data_buf.windows(5).any(|w| w == b"\r\n.\r\n")
            || smtp_data_buf.windows(3).any(|w| w == b"\n.\n");
        if has_terminator {
            let body_size = smtp_data_buf.len();
            tracing::debug!("SMTP DATA complete from {}: {} bytes", peer, body_size);
            log_event(
                output_path,
                listener_name,
                peer,
                "smtp_data",
                &format!("{} bytes", body_size),
            )
            .await;

            let mbox_dir = smtp_dir
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("/var/log/nettrap/smtp"));
            if let Err(e) = tokio::fs::create_dir_all(&mbox_dir).await {
                tracing::warn!("Failed to create SMTP directory {:?}: {}", mbox_dir, e);
            }
            let filename = format!("{}/{}.eml", mbox_dir.display(), uuid::Uuid::new_v4());
            if let Err(e) = tokio::fs::write(&filename, &*smtp_data_buf).await {
                tracing::warn!("Failed to write SMTP email to {:?}: {}", filename, e);
            } else {
                tracing::info!("SMTP email saved to {}", filename);
            }

            *smtp_data_mode = false;
            smtp_data_buf.clear();
            format!("250 OK Queued as {}\r\n", uuid::Uuid::new_v4()).into_bytes()
        } else {
            Vec::new()
        }
    } else {
        let command = std::str::from_utf8(data).unwrap_or("").trim();
        tracing::debug!("SMTP command from {}: {}", peer, command);
        log_event(output_path, listener_name, peer, "smtp_command", command).await;

        // Use stateful SMTP handler for proper AUTH support
        let (resp, new_state) = smtp_handler.handle_with_state(command, smtp_auth_state.clone());
        *smtp_auth_state = new_state;

        if resp.code == 354 {
            *smtp_data_mode = true;
            smtp_data_buf.clear();
        }
        resp.to_bytes()
    }
}

/// Build minimal TLS ServerHello response (RFC 5246).
pub fn build_tls_response() -> Vec<u8> {
    // ServerHello handshake message
    let mut handshake = Vec::new();
    handshake.push(0x02); // HandshakeType: ServerHello
    // Handshake length placeholder (3 bytes) — filled below
    handshake.extend_from_slice(&[0, 0, 0]);
    // ServerHello body
    handshake.extend_from_slice(&[0x03, 0x03]); // Server version: TLS 1.2
    handshake.extend_from_slice(&[0u8; 32]); // Random (32 bytes)
    handshake.push(0); // Session ID length: 0
    handshake.extend_from_slice(&[0x00, 0x2F]); // Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA
    handshake.push(0x00); // Compression method: null
    // Fill handshake length (bytes after the 4-byte header)
    let body_len = handshake.len() - 4;
    handshake[1] = ((body_len >> 16) & 0xFF) as u8;
    handshake[2] = ((body_len >> 8) & 0xFF) as u8;
    handshake[3] = (body_len & 0xFF) as u8;
    // TLS record header
    let mut response = Vec::new();
    response.push(22); // ContentType: Handshake
    response.extend_from_slice(&[0x03, 0x03]); // Version: TLS 1.2
    response.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    response.extend_from_slice(&handshake);
    response
}

fn build_tls_alert_decode_error() -> Vec<u8> {
    vec![21, 0x03, 0x03, 0x00, 0x02, 0x02, 50]
}

fn is_dyn_dns_checkip_request(host: &str, path: &str) -> bool {
    crate::custom_response::host_matches_pattern(host, "checkip.dyndns.org")
        && matches!(path, "/" | "/checkip")
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn http_frame_rejects_invalid_content_length() {
        let mut buffer =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: abc\r\n\r\nhello"
                .to_vec();
        expect_terminal_response(
            extract_http_request(&mut buffer),
            b"HTTP/1.1 400 Bad Request",
        );
        assert!(buffer.is_empty());
    }

    #[test]
    fn line_framing_leaves_partial_command_buffered() {
        let router = nettrap_proxy::ProtocolRouter::new();
        let mut buffer = b"USER anonymous\r\nPASS se".to_vec();

        let first = expect_complete(next_tcp_frame(
            &mut buffer,
            "ftp",
            21,
            &router,
            false,
            false,
        ));
        assert_eq!(first, b"USER anonymous\r\n");
        assert_eq!(buffer, b"PASS se");

        buffer.extend_from_slice(b"cret\r\n");
        let second = expect_complete(next_tcp_frame(
            &mut buffer,
            "ftp",
            21,
            &router,
            false,
            false,
        ));
        assert_eq!(second, b"PASS secret\r\n");
        assert!(buffer.is_empty());
    }

    #[test]
    fn http_frame_rejects_unsupported_transfer_encoding() {
        let mut buffer =
            b"POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip\r\n\r\nhello"
                .to_vec();
        expect_terminal_response(
            extract_http_request(&mut buffer),
            b"HTTP/1.1 400 Bad Request",
        );
        assert!(buffer.is_empty());
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
        let mut buffer = b"POST /chunk HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntes"
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
    }

    #[test]
    fn mysql_frame_waits_for_complete_packet() {
        let mut buffer = vec![0x03, 0x00, 0x00, 0x01, 0x03, b'S'];
        assert!(extract_mysql_frame(&mut buffer).is_none());

        buffer.push(0);
        let frame = extract_mysql_frame(&mut buffer).expect("mysql packet should be complete");
        assert_eq!(frame, vec![0x03, 0x00, 0x00, 0x01, 0x03, b'S', 0]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn postgres_frames_wait_for_startup_and_typed_messages() {
        let mut startup = vec![0x00, 0x00, 0x00];
        assert!(extract_postgres_frame(&mut startup).is_none());

        startup.extend_from_slice(&[0x08, 0x04, 0xD2, 0x16, 0x2F]);
        let startup_frame =
            extract_postgres_frame(&mut startup).expect("startup frame should be complete");
        assert_eq!(
            startup_frame,
            vec![0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F]
        );
        assert!(startup.is_empty());

        let mut query = vec![b'Q', 0x00, 0x00, 0x00];
        assert!(extract_postgres_frame(&mut query).is_none());

        query.extend_from_slice(&[0x06, b'S', 0x00]);
        let query_frame =
            extract_postgres_frame(&mut query).expect("typed postgres frame should be complete");
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
    fn rdp_frame_waits_for_complete_tpkt() {
        let mut buffer = vec![0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0];
        assert!(extract_rdp_frame(&mut buffer).is_none());

        buffer.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00]);
        let frame = extract_rdp_frame(&mut buffer).expect("rdp tpkt should be complete");
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
    fn tls_frame_rejects_oversized_record() {
        let mut buffer = vec![0x16, 0x03, 0x03, 0xff, 0xff];

        assert!(matches!(
            extract_tls_frame(&mut buffer),
            TcpFrameResult::TooLarge { response: Some(_) }
        ));
        assert!(buffer.is_empty());
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
        let destination = SessionDestination::new("192.0.2.10", 21);
        let local_addr: std::net::SocketAddr = "192.0.2.20:2121".parse().expect("local addr");

        assert_eq!(
            ftp_passive_response_host(&handler, &destination, Some(local_addr)),
            "192,0,2,20"
        );
    }

    #[test]
    fn ftp_pasv_host_falls_back_to_loopback_for_redirect_destination() {
        let handler = nettrap_proto_ftp::FtpHandler::new();
        let destination = SessionDestination::new("192.0.2.10", 21);

        assert_eq!(
            ftp_passive_response_host(&handler, &destination, None),
            "127,0,0,1"
        );
    }

    #[test]
    fn ftp_pasv_host_prefers_configured_address() {
        let handler = nettrap_proto_ftp::FtpHandler::new().with_pasv_address("10.1.2.3");
        let destination = SessionDestination::new("192.0.2.10", 21);
        let local_addr: std::net::SocketAddr = "192.0.2.20:2121".parse().expect("local addr");

        assert_eq!(
            ftp_passive_response_host(&handler, &destination, Some(local_addr)),
            "10,1,2,3"
        );
    }

    #[tokio::test]
    async fn ftp_prefixed_pasv_does_not_open_passive_socket() {
        let handler = nettrap_proto_ftp::FtpHandler::new().with_pasv_ports(0, 0);
        let mut state = FtpPassiveState::default();
        let peer: std::net::SocketAddr = "127.0.0.1:40000".parse().expect("peer addr");
        let destination = SessionDestination::new("127.0.0.1", 21);
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
    }

    #[tokio::test]
    async fn ftp_passive_transfer_uses_data_socket() {
        let handler = nettrap_proto_ftp::FtpHandler::new().with_pasv_ports(0, 0);
        let mut state = FtpPassiveState::default();
        let peer: std::net::SocketAddr = "127.0.0.1:40000".parse().expect("peer addr");
        let destination = SessionDestination::new("127.0.0.1", 21);
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
            FtpCommandAction::Transfer { listener, transfer } => {
                let start_response = transfer.start_response.to_bytes();
                assert!(String::from_utf8_lossy(&start_response).starts_with("150 "));
                (listener, transfer)
            }
            FtpCommandAction::Response(response) => {
                panic!(
                    "expected transfer action, got {}",
                    String::from_utf8_lossy(&response)
                );
            }
        };
        let control_response = finish_ftp_passive_transfer(transfer.0, transfer.1).await;
        let data = data_reader.await.expect("data task");

        assert!(String::from_utf8_lossy(&data).contains("index.html"));
        let control_text = String::from_utf8_lossy(&control_response);
        assert!(control_text.contains("226 Directory send OK."));
        assert!(state.listener.is_none());
    }
}
