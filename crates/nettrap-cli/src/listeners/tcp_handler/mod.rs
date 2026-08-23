//! TCP connection handler functions.
//!
//! Contains the main TCP connection handling logic for protocols.

use nettrap_protocols::handlers::*;
use std::net::SocketAddr;
use std::sync::Arc;

use super::tcp_ftp::{FtpCommandAction, FtpPassiveState, prepare_ftp_command};
use crate::listener_context::ListenerContext;
use crate::listeners::tcp_dispatch::*;
use crate::listeners::tcp_framing::*;
use crate::session::SessionDestination;

pub use crate::listeners::tcp_response::*;

mod forward;

mod plain;
pub use plain::handle_tcp_connection;
pub(crate) use plain::handle_tcp_connection_with_policy;

mod wrapped;
pub use wrapped::handle_wrapped_connection;

#[derive(Clone, Copy)]
struct FtpCommandContext<'a> {
    peer: &'a SocketAddr,
    destination: &'a SessionDestination,
    control_local_addr: Option<SocketAddr>,
}

/// Per-connection protocol handler instances.
///
/// Bundles every protocol emulator constructed once per accepted connection so
/// the dispatch path threads a single reference instead of individual handlers.
pub(crate) struct SessionHandlers {
    pub(crate) smtp: nettrap_proto_smtp::SmtpHandler,
    pub(crate) ftp: nettrap_proto_ftp::FtpHandler,
    pub(crate) pop3: nettrap_proto_pop3::Pop3Handler,
    pub(crate) irc: nettrap_proto_irc::IrcHandler,
    pub(crate) imap: crate::handler_registry::ImapHandler,
    pub(crate) telnet: nettrap_proto_telnet::TelnetHandler,
    pub(crate) smb: nettrap_proto_smb::SmbHandler,
    pub(crate) rdp: nettrap_proto_rdp::RdpHandler,
    pub(crate) redis: nettrap_proto_redis::RedisHandler,
    pub(crate) mysql: nettrap_proto_mysql::MysqlHandler,
    pub(crate) ldap: nettrap_proto_ldap::LdapHandler,
    pub(crate) socks: nettrap_proto_socks::SocksHandler,
    pub(crate) memcached: nettrap_proto_memcached::MemcachedHandler,
    pub(crate) mqtt: nettrap_proto_mqtt::MqttHandler,
    pub(crate) postgres: nettrap_proto_postgres::PostgresHandler,
    pub(crate) chargen: nettrap_proto_chargen::ChargenHandler,
}

impl SessionHandlers {
    fn from_ctx(ctx: &ListenerContext) -> crate::Result<Self> {
        let telnet_name = preferred_hostname(ctx, "Telnet hostname")?;

        let telnet = if let Some(name) = telnet_name {
            nettrap_proto_telnet::TelnetHandler::new()
                .with_now(crate::faketime::fake_now)
                .with_hostname(crate::utils::service_name::resolve_service_name(name))
                .map_err(|err| {
                    crate::Error::Config(format!(
                        "invalid Telnet service name for listener {}: {}",
                        ctx.name(),
                        err
                    ))
                })?
        } else {
            nettrap_proto_telnet::TelnetHandler::new().with_now(crate::faketime::fake_now)
        };

        Ok(Self {
            smtp: crate::protocol_handlers::init_smtp_handler(ctx)?,
            ftp: crate::protocol_handlers::init_ftp_handler(ctx)?,
            pop3: crate::protocol_handlers::init_pop3_handler(ctx)?,
            irc: crate::protocol_handlers::init_irc_handler(ctx)?,
            imap: crate::protocol_handlers::init_imap_handler(ctx)?,
            telnet,
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
        })
    }
}

fn preferred_hostname<'a>(ctx: &'a ListenerContext, label: &str) -> crate::Result<Option<&'a str>> {
    if let Some(name) = ctx.config.server_name.as_deref() {
        if !crate::utils::service_name::is_usable_service_name_input(name) {
            return Err(crate::Error::Config(format!(
                "invalid {} for listener {}: {}",
                label,
                ctx.name(),
                name
            )));
        }
        return Ok(Some(name));
    }
    if let Some(name) = ctx.banner() {
        if !crate::utils::service_name::is_usable_service_name_input(name) {
            return Err(crate::Error::Config(format!(
                "invalid {} for listener {}: {}",
                label,
                ctx.name(),
                name
            )));
        }
        return Ok(Some(name));
    }
    Ok(None)
}

/// Mutable per-connection protocol session state threaded through dispatch.
pub struct TcpSessionState {
    pub(crate) smtp_data_mode: bool,
    pub(crate) smtp_data_buf: Vec<u8>,
    pub(crate) smtp_auth_state: nettrap_proto_smtp::SmtpAuthState,
    pub(crate) irc_nick: String,
    pub(crate) redis_authenticated: bool,
    pub(crate) ssh_first_packet: bool,
    pub(crate) ftp_passive_state: FtpPassiveState,
    pub(crate) telnet_state: nettrap_proto_telnet::TelnetState,
    pub(crate) telnet_username: String,
}

impl TcpSessionState {
    fn new() -> Self {
        Self {
            smtp_data_mode: false,
            smtp_data_buf: Vec::new(),
            smtp_auth_state: nettrap_proto_smtp::SmtpAuthState::None,
            irc_nick: "unknown".to_string(),
            redis_authenticated: false,
            ssh_first_packet: true,
            ftp_passive_state: FtpPassiveState::default(),
            telnet_state: nettrap_proto_telnet::TelnetState::WaitingUsername,
            telnet_username: String::new(),
        }
    }
}

impl Default for TcpSessionState {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn add_sent_bytes(total: u64, chunk_len: usize) -> u64 {
    let chunk = u64::try_from(chunk_len).unwrap_or(u64::MAX);
    total.saturating_add(chunk)
}

fn tcp_frame_closes_session(name: &str, frame: &[u8]) -> bool {
    if listener_name_matches_protocol(name, "mqtt") {
        return nettrap_proto_mqtt::is_valid_disconnect_frame(frame);
    }
    if listener_name_matches_protocol(name, "redis") {
        return redis_frame_closes_session(frame);
    }
    if listener_name_matches_protocol(name, "memcached") {
        return memcached_frame_closes_session(frame);
    }
    if listener_name_matches_protocol(name, "mysql") {
        return mysql_frame_closes_session(frame);
    }
    if listener_name_matches_protocol(name, "postgres") {
        return postgres_frame_closes_session(frame);
    }
    if listener_name_matches_protocol(name, "ssh") {
        return ssh_frame_closes_session(frame);
    }

    if !(listener_name_matches_protocol(name, "ftp")
        || listener_name_matches_protocol(name, "ftps")
        || listener_name_matches_protocol(name, "smtp")
        || listener_name_matches_protocol(name, "smtps")
        || listener_name_matches_protocol(name, "pop3")
        || listener_name_matches_protocol(name, "pop3s")
        || listener_name_matches_protocol(name, "irc"))
    {
        return false;
    }

    let Ok(command) = std::str::from_utf8(frame) else {
        return false;
    };
    let command = command.trim_end_matches(['\r', '\n']);
    let Some(verb) = command.split([' ', '\t']).next() else {
        return false;
    };
    if listener_name_matches_protocol(name, "irc") {
        return verb.eq_ignore_ascii_case("QUIT");
    }

    command.eq_ignore_ascii_case("QUIT")
}

fn redis_frame_closes_session(frame: &[u8]) -> bool {
    let prefix = b"*1\r\n$4\r\n";
    if frame.len() == prefix.len() + b"QUIT\r\n".len()
        && frame.starts_with(prefix)
        && frame[prefix.len()..prefix.len() + 4].eq_ignore_ascii_case(b"QUIT")
        && frame.ends_with(b"\r\n")
    {
        return true;
    }

    let Ok(command) = std::str::from_utf8(frame) else {
        return false;
    };
    let command = command.trim_end_matches(['\r', '\n']);
    command.eq_ignore_ascii_case("QUIT")
}

fn memcached_frame_closes_session(frame: &[u8]) -> bool {
    if frame.first() == Some(&0x80) {
        return memcached_binary_frame_closes_session(frame);
    }

    let Ok(command) = std::str::from_utf8(frame) else {
        return false;
    };
    let command = command.trim_end_matches(['\r', '\n']);
    command.eq_ignore_ascii_case("quit")
}

fn memcached_binary_frame_closes_session(frame: &[u8]) -> bool {
    if frame.len() != 24 {
        return false;
    }
    let opcode = frame[1];
    if !matches!(opcode, 0x07 | 0x17) {
        return false;
    }
    let key_len = u16::from_be_bytes([frame[2], frame[3]]);
    let extras_len = frame[4];
    let body_len = u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]);

    key_len == 0 && extras_len == 0 && body_len == 0
}

fn mysql_frame_closes_session(frame: &[u8]) -> bool {
    if frame.len() != 5 {
        return false;
    }

    let payload_len = frame[0] as usize | ((frame[1] as usize) << 8) | ((frame[2] as usize) << 16);
    payload_len == 1 && frame[3] != 1 && frame[4] == 0x01
}

fn postgres_frame_closes_session(frame: &[u8]) -> bool {
    frame == [b'X', 0, 0, 0, 4]
}

fn ssh_frame_closes_session(frame: &[u8]) -> bool {
    const SSH_PACKET_ALIGNMENT: usize = 8;
    const SSH_STRING_LEN_BYTES: usize = 4;
    const SSH_DISCONNECT_REASON_BYTES: usize = 4;

    if frame.len() < 4 + SSH_PACKET_ALIGNMENT {
        return false;
    }

    let packet_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if frame.len() != 4 + packet_len || !packet_len.is_multiple_of(SSH_PACKET_ALIGNMENT) {
        return false;
    }
    let padding_len = frame[4] as usize;
    if padding_len < 4 || packet_len <= padding_len + 1 {
        return false;
    }

    let payload_end = frame.len() - padding_len;
    let payload = &frame[5..payload_end];
    if payload.first() != Some(&nettrap_proto_ssh::SSH_MSG_DISCONNECT) {
        return false;
    }

    let mut pos = 1usize + SSH_DISCONNECT_REASON_BYTES;
    for _ in 0..2 {
        if pos + SSH_STRING_LEN_BYTES > payload.len() {
            return false;
        }
        let len = u32::from_be_bytes([
            payload[pos],
            payload[pos + 1],
            payload[pos + 2],
            payload[pos + 3],
        ]) as usize;
        pos += SSH_STRING_LEN_BYTES;
        let Some(next_pos) = pos.checked_add(len) else {
            return false;
        };
        if next_pos > payload.len() {
            return false;
        }
        pos = next_pos;
    }

    pos == payload.len()
}

/// Immutable per-request inputs threaded identically through the dispatch path.
#[derive(Clone, Copy)]
pub(crate) struct TcpRequestContext<'a> {
    pub(crate) ctx: &'a Arc<ListenerContext>,
    pub(crate) peer: &'a SocketAddr,
    pub(crate) output_path: Option<&'a std::path::Path>,
    pub(crate) destination: &'a SessionDestination,
    pub(crate) control_local_addr: Option<SocketAddr>,
    pub(crate) http_over_tls: bool,
    pub(crate) ssh_banner_sent: bool,
}

/// Handle a TCP connection after accept.
/// Connection identity bundle threaded through the TCP connection phases,
/// mirroring the per-connection bundle structs (`SessionHandlers`,
/// `TcpSessionState`) used by the dispatch path. The live stream is owned
/// separately by the coordinator because the TLS-upgrade phase consumes it.
struct TcpConnection<'a> {
    ctx: Arc<ListenerContext>,
    peer: std::net::SocketAddr,
    destination: SessionDestination,
    output_path: Option<&'a std::path::Path>,
    control_local_addr: Option<SocketAddr>,
}

/// Outcome of the implicit-TLS upgrade phase: either the connection is
/// finished (delegated to `handle_wrapped_connection` or terminated) and
/// the coordinator must return the carried result, or the stream stayed
/// plaintext and is handed back to continue into the frame loop.
enum TlsUpgradeOutcome {
    Done(crate::Result<()>),
    Plain(tokio::net::TcpStream),
}

async fn handle_tcp_protocol(
    request: TcpRequestContext<'_>,
    name: &str,
    data: &[u8],
    first_bytes: &[u8],
    handlers: &SessionHandlers,
    webroot_server: Option<&crate::webroot::WebrootServer>,
    session: &mut TcpSessionState,
) -> crate::Result<Vec<u8>> {
    if let Some(response) =
        dispatch_named_tcp_protocol(request, name, data, handlers, webroot_server, session).await?
    {
        Ok(response)
    } else {
        handle_detected_protocol(
            request,
            data,
            first_bytes,
            handlers,
            webroot_server,
            session,
        )
        .await
    }
}

fn should_handle_ftp_ordered(
    ctx: &Arc<ListenerContext>,
    name: &str,
    data: &[u8],
    destination: &SessionDestination,
) -> bool {
    if listener_name_matches_protocol(name, "ftp") || listener_name_matches_protocol(name, "ftps") {
        return true;
    }

    // Only auto-detect FTP on generic/auto listeners. A listener with an
    // explicit non-FTP protocol (pop3, smtp, irc, …) must keep speaking that
    // protocol — `USER`/`PASS` are valid FTP verbs too, so FTP taste detection
    // would otherwise hijack POP3/SMTP auth commands and reply with FTP codes.
    if listener_frame_mode(name, false).is_some() {
        return false;
    }

    let Some((detected_name, score)) = ctx.runtime.router.route_tcp(data, destination.port())
    else {
        return false;
    };
    if !(listener_name_matches_protocol(&detected_name, "ftp")
        || listener_name_matches_protocol(&detected_name, "ftps"))
    {
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
    let Ok(command) = std::str::from_utf8(data) else {
        return FtpCommandAction::Response(
            nettrap_proto_ftp::FtpResponse::new(500, "FTP command contains invalid UTF-8")
                .to_bytes(),
        );
    };
    let logged_command = command.trim_end_matches(['\r', '\n']);
    tracing::debug!(
        "FTP command from {}: {}",
        command_context.peer,
        crate::protocol_handlers::redact_ftp_command(logged_command)
    );
    crate::protocol_handlers::log_ftp_event(
        ctx,
        output_path,
        command_context.peer,
        command_context.destination,
        logged_command,
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

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
