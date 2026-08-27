//! Per-protocol named-dispatch TCP handlers.

use nettrap_proto_irc::IrcHandlerTrait;
use nettrap_proto_pop3::Pop3HandlerTrait;
use nettrap_protocols::handlers::*;
use std::sync::Arc;

use super::tcp_ftp::handle_ftp_command;
use crate::handler_registry::{SimpleTcpHandler, parse_imap_command_line};
use crate::listener_context::ListenerContext;
use crate::listeners::tcp_framing::*;
use crate::listeners::tcp_handler::{
    SessionHandlers, TcpRequestContext, TcpSessionState, build_tls_response, handle_http_plain,
    handle_https, handle_smtp_data,
};
use crate::session::SessionDestination;
use crate::utils::canonical_socket_ip_string;
use crate::utils::log_event;

const REDACTED_TELNET_AUTH_FIELD: &str = "***REDACTED***";

pub(crate) async fn dispatch_named_tcp_protocol(
    request: TcpRequestContext<'_>,
    name: &str,
    data: &[u8],
    handlers: &SessionHandlers,
    webroot_server: Option<&crate::webroot::WebrootServer>,
    session: &mut TcpSessionState,
) -> crate::Result<Option<Vec<u8>>> {
    if listener_name_matches_protocol(name, "dns") {
        Ok(Some(handle_dns_named(request, data).await?))
    } else if listener_name_matches_protocol(name, "http")
        || listener_name_matches_protocol(name, "https")
    {
        Ok(Some(handle_http_named(request, data, webroot_server).await))
    } else if listener_name_matches_protocol(name, "smtp")
        || listener_name_matches_protocol(name, "smtps")
    {
        Ok(Some(
            handle_smtp_named(request, data, handlers, session).await?,
        ))
    } else if listener_name_matches_protocol(name, "ftp")
        || listener_name_matches_protocol(name, "ftps")
    {
        Ok(Some(
            handle_ftp_named(request, data, handlers, session).await,
        ))
    } else if listener_name_matches_protocol(name, "pop3")
        || listener_name_matches_protocol(name, "pop3s")
    {
        Ok(Some(handle_pop3_named(request, data, handlers).await))
    } else if listener_name_matches_protocol(name, "imap")
        || listener_name_matches_protocol(name, "imaps")
    {
        Ok(Some(handle_imap_named(request, data, handlers).await))
    } else if listener_name_matches_protocol(name, "irc")
        || listener_name_matches_protocol(name, "ircs")
    {
        Ok(Some(
            handle_irc_named(request, data, handlers, session).await,
        ))
    } else if listener_name_matches_protocol(name, "telnet")
        || listener_name_matches_protocol(name, "telnets")
    {
        Ok(Some(
            handle_telnet_named(request, data, handlers, session).await,
        ))
    } else if listener_name_matches_protocol(name, "finger") {
        Ok(Some(handle_finger_named(request, data).await))
    } else if listener_name_matches_protocol(name, "ident") {
        Ok(Some(handle_ident_named(request, data).await))
    } else if listener_name_matches_protocol(name, "daytime") {
        Ok(Some(handle_daytime_named(request, data).await))
    } else if listener_name_matches_protocol(name, "time") {
        Ok(Some(handle_time_named(request, data).await))
    } else if listener_name_matches_protocol(name, "chargen") {
        Ok(Some(handle_chargen_named(request, data, handlers).await))
    } else if listener_name_matches_protocol(name, "quotd") {
        Ok(Some(handle_quotd_named(request, data).await))
    } else if listener_name_matches_protocol(name, "syslogrecv") {
        Ok(Some(handle_syslogrecv_named(request, data).await))
    } else if listener_name_matches_protocol(name, "dummy") {
        Ok(Some(handle_dummy_named(request, data).await))
    } else if listener_name_matches_protocol(name, "ssh") {
        Ok(Some(handle_ssh_named(request, data, session).await))
    } else if listener_name_matches_protocol(name, "smb") {
        Ok(Some(handle_smb_named(request, data, handlers).await))
    } else if listener_name_matches_protocol(name, "rdp") {
        Ok(Some(handle_rdp_named(request, data, handlers).await))
    } else if listener_name_matches_protocol(name, "redis") {
        Ok(Some(
            handle_redis_named(request, data, handlers, session).await,
        ))
    } else if listener_name_matches_protocol(name, "mysql") {
        Ok(Some(handle_mysql_named(request, data, handlers).await))
    } else if listener_name_matches_protocol(name, "ldap")
        || listener_name_matches_protocol(name, "ldaps")
    {
        Ok(Some(handle_ldap_named(request, data, handlers).await))
    } else if listener_name_matches_protocol(name, "socks") {
        Ok(Some(handle_socks_named(request, data, handlers).await))
    } else if listener_name_matches_protocol(name, "memcached") {
        Ok(Some(handle_memcached_named(request, data, handlers).await))
    } else if listener_name_matches_protocol(name, "mqtt") {
        Ok(Some(handle_mqtt_named(request, data, handlers).await))
    } else if listener_name_matches_protocol(name, "tls")
        || listener_name_matches_protocol(name, "ssl")
    {
        Ok(Some(handle_tls_named(request, data).await))
    } else if listener_name_matches_protocol(name, "upnp") {
        Ok(Some(handle_upnp_named(request, data).await))
    } else if listener_name_matches_protocol(name, "nkn") {
        Ok(Some(handle_nkn_named(request, data).await))
    } else if listener_name_matches_protocol(name, "postgres") {
        Ok(Some(handle_postgres_named(request, data, handlers).await))
    } else if listener_name_matches_protocol(name, "raw")
        || listener_name_matches_protocol(name, "echo")
    {
        Ok(Some(handle_raw_named(request, data).await))
    } else {
        Ok(None)
    }
}

pub(crate) async fn handle_dns_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
) -> crate::Result<Vec<u8>> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    handle_dns_tcp(ctx, data, peer, destination, output_path).await
}

pub(crate) async fn handle_http_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    webroot_server: Option<&crate::webroot::WebrootServer>,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        http_over_tls,
        ..
    } = request;
    if http_over_tls {
        handle_https(ctx, data, peer, destination, output_path, webroot_server).await
    } else {
        handle_http_plain(ctx, data, peer, destination, output_path, webroot_server).await
    }
}

pub(crate) async fn handle_smtp_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
    session: &mut TcpSessionState,
) -> crate::Result<Vec<u8>> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    if session.smtp_data_mode {
        return handle_smtp_data(
            data,
            &handlers.smtp,
            session,
            output_path,
            ctx.name(),
            peer,
            ctx.config.smtp_dir.as_deref(),
        )
        .await;
    }

    let cmd_str = std::str::from_utf8(data)
        .map_err(|e| crate::Error::Other(format!("SMTP command contains invalid UTF-8: {}", e)))?
        .trim_end_matches(['\r', '\n']);
    crate::protocol_handlers::log_smtp_event(ctx, output_path, peer, destination, cmd_str).await;
    handle_smtp_data(
        data,
        &handlers.smtp,
        session,
        output_path,
        ctx.name(),
        peer,
        ctx.config.smtp_dir.as_deref(),
    )
    .await
}

pub(crate) async fn handle_ftp_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
    session: &mut TcpSessionState,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        control_local_addr,
        ..
    } = request;
    let command = match std::str::from_utf8(data) {
        Ok(command) => command,
        Err(e) => {
            tracing::warn!("FTP command from {} is invalid UTF-8: {}", peer, e);
            return nettrap_proto_ftp::FtpResponse::new(502, "FTP command contains invalid UTF-8")
                .to_bytes();
        }
    };
    tracing::debug!(
        "FTP command from {}: {}",
        peer,
        crate::protocol_handlers::redact_ftp_command(command)
    );
    crate::protocol_handlers::log_ftp_event(ctx, output_path, peer, destination, command).await;
    handle_ftp_command(
        &handlers.ftp,
        &mut session.ftp_passive_state,
        command,
        peer,
        destination,
        control_local_addr,
    )
    .await
}

pub(crate) async fn handle_pop3_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    let command = match std::str::from_utf8(data) {
        Ok(command) => command,
        Err(e) => {
            tracing::warn!("POP3 command from {} is invalid UTF-8: {}", peer, e);
            return b"-ERR Invalid command encoding\r\n".to_vec();
        }
    };
    tracing::debug!(
        "POP3 command from {}: {}",
        peer,
        crate::protocol_handlers::redact_pop3_command(command)
    );
    crate::protocol_handlers::log_pop3_event(ctx, output_path, peer, destination, command).await;
    match handlers.pop3.handle(command).await {
        Ok(resp) => resp.to_bytes(),
        Err(_) => b"-ERR Server error\r\n".to_vec(),
    }
}

pub(crate) async fn handle_imap_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    let (command_name, command_data) = match std::str::from_utf8(data) {
        Ok(command) => {
            let command = command.trim_end_matches(['\r', '\n']);
            let command_name = parse_imap_command_line(command).map_or_else(
                || "UNKNOWN".to_string(),
                |(_, cmd)| cmd.to_ascii_uppercase(),
            );
            (command_name, data)
        }
        Err(_) => ("INVALID_UTF8".to_string(), data),
    };
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "imap_request",
            detail: &command_name,
            data_len: data.len(),
            protocol: "imap",
        },
    )
    .await;
    handlers
        .imap
        .handle_tcp(command_data)
        .unwrap_or_else(|| b"* BAD Invalid IMAP command\r\n".to_vec())
}

pub(crate) async fn handle_irc_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
    session: &mut TcpSessionState,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    handle_irc(
        ctx,
        data,
        peer,
        destination,
        output_path,
        &handlers.irc,
        &mut session.irc_nick,
    )
    .await
}

pub(crate) async fn handle_telnet_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
    session: &mut TcpSessionState,
) -> Vec<u8> {
    handle_telnet(
        request,
        data,
        &handlers.telnet,
        &mut session.telnet_state,
        &mut session.telnet_username,
    )
    .await
}

pub(crate) async fn handle_finger_named(request: TcpRequestContext<'_>, data: &[u8]) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    let Ok(query) = std::str::from_utf8(data) else {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            crate::protocol_handlers::TcpEventDetails {
                event_type: "finger_request",
                detail: "invalid UTF-8",
                data_len: data.len(),
                protocol: "finger",
            },
        )
        .await;
        return nettrap_proto_finger::FingerHandler::new()
            .handle("\0")
            .into_bytes();
    };
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "finger_request",
            detail: query.trim_end_matches(['\r', '\n']),
            data_len: data.len(),
            protocol: "finger",
        },
    )
    .await;
    nettrap_proto_finger::FingerHandler::new()
        .handle(query)
        .into_bytes()
}

pub(crate) async fn handle_ident_named(request: TcpRequestContext<'_>, data: &[u8]) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    let Ok(query) = std::str::from_utf8(data) else {
        return b" : ERROR : INVALID-PORT\r\n".to_vec();
    };
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "ident_request",
            detail: query.trim_end_matches(['\r', '\n']),
            data_len: data.len(),
            protocol: "ident",
        },
    )
    .await;
    nettrap_proto_ident::IdentHandler::new()
        .handle(query)
        .into_bytes()
}

pub(crate) async fn handle_daytime_named(request: TcpRequestContext<'_>, data: &[u8]) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "daytime_request",
            detail: &format!("{} bytes", data.len()),
            data_len: data.len(),
            protocol: "daytime",
        },
    )
    .await;
    nettrap_proto_daytime::DaytimeHandler::new()
        .handle_at(crate::faketime::fake_now())
        .into_bytes()
}

pub(crate) async fn handle_time_named(request: TcpRequestContext<'_>, data: &[u8]) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "time_request",
            detail: &format!("{} bytes", data.len()),
            data_len: data.len(),
            protocol: "time",
        },
    )
    .await;
    nettrap_proto_time::TimeHandler::new().handle_at(crate::faketime::fake_now())
}

pub(crate) async fn handle_chargen_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "chargen_request",
            detail: &format!("{} bytes", data.len()),
            data_len: data.len(),
            protocol: "chargen",
        },
    )
    .await;
    handlers.chargen.handle(6)
}

pub(crate) async fn handle_quotd_named(request: TcpRequestContext<'_>, data: &[u8]) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "quotd_request",
            detail: &format!("{} bytes", data.len()),
            data_len: data.len(),
            protocol: "quotd",
        },
    )
    .await;
    nettrap_proto_quotd::QuotdHandler::new()
        .handle()
        .into_bytes()
}

pub(crate) async fn handle_syslogrecv_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
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
    let mut nbi = crate::nbi::raw_nbi(
        ctx.name(),
        &canonical_socket_ip_string(peer),
        peer.port(),
        destination,
        data.len(),
        "",
    );
    nbi.add("detected_protocol", "syslogrecv");
    if let Some(message) = parsed {
        nbi.add("facility", message.facility_name);
        nbi.add("severity", message.severity_name);
    }
    ctx.runtime.nbi_collector.record(&nbi).await;
    Vec::new()
}

pub(crate) async fn handle_dummy_named(request: TcpRequestContext<'_>, data: &[u8]) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "dummy_request",
            detail: &format!("{} bytes", data.len()),
            data_len: data.len(),
            protocol: "dummy",
        },
    )
    .await;
    nettrap_proto_dummy::DummyHandler::new().handle(data)
}

pub(crate) async fn handle_ssh_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    session: &mut TcpSessionState,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ssh_banner_sent,
        ..
    } = request;
    handle_ssh(
        ctx,
        data,
        peer,
        destination,
        output_path,
        &mut session.ssh_first_packet,
        ssh_banner_sent,
    )
    .await
}

pub(crate) async fn handle_smb_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        destination,
        ..
    } = request;
    let mut nbi = crate::nbi::raw_nbi(
        ctx.name(),
        &canonical_socket_ip_string(peer),
        peer.port(),
        destination,
        data.len(),
        "",
    );
    nbi.add("detected_protocol", "smb");
    ctx.runtime.nbi_collector.record(&nbi).await;
    handlers.smb.handle(data)
}

pub(crate) async fn handle_rdp_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "rdp_request",
            detail: &format!("{} bytes", data.len()),
            data_len: data.len(),
            protocol: "rdp",
        },
    )
    .await;
    handlers.rdp.handle(data)
}

pub(crate) async fn handle_redis_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
    session: &mut TcpSessionState,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "redis_request",
            detail: &format!("{} bytes", data.len()),
            data_len: data.len(),
            protocol: "redis",
        },
    )
    .await;
    handlers
        .redis
        .handle_command_with_auth_state(data, &mut session.redis_authenticated)
}

pub(crate) async fn handle_mysql_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "mysql_request",
            detail: &format!("{} bytes", data.len()),
            data_len: data.len(),
            protocol: "mysql",
        },
    )
    .await;
    handlers.mysql.handle(data)
}

pub(crate) async fn handle_ldap_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "ldap_request",
            detail: &format!("{} bytes", data.len()),
            data_len: data.len(),
            protocol: "ldap",
        },
    )
    .await;
    handlers.ldap.handle(data)
}

pub(crate) async fn handle_socks_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "socks_request",
            detail: &format!("{} bytes", data.len()),
            data_len: data.len(),
            protocol: "socks",
        },
    )
    .await;
    handlers.socks.handle(data)
}

pub(crate) async fn handle_memcached_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "memcached_request",
            detail: &format!("{} bytes", data.len()),
            data_len: data.len(),
            protocol: "memcached",
        },
    )
    .await;
    handlers.memcached.handle(data)
}

pub(crate) async fn handle_mqtt_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "mqtt_request",
            detail: &format!("{} bytes", data.len()),
            data_len: data.len(),
            protocol: "mqtt",
        },
    )
    .await;
    let mut nbi = crate::nbi::raw_nbi(
        ctx.name(),
        &canonical_socket_ip_string(peer),
        peer.port(),
        destination,
        data.len(),
        "",
    );
    nbi.add("detected_protocol", "mqtt");
    ctx.runtime.nbi_collector.record(&nbi).await;
    handlers.mqtt.handle_packet(data)
}

pub(crate) async fn handle_tls_named(request: TcpRequestContext<'_>, data: &[u8]) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    handle_tls_plain(ctx, data, peer, destination, output_path).await
}

pub(crate) async fn handle_upnp_named(request: TcpRequestContext<'_>, data: &[u8]) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    handle_upnp_tcp(ctx, data, peer, destination, output_path).await
}

pub(crate) async fn handle_nkn_named(request: TcpRequestContext<'_>, data: &[u8]) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    let handler = nettrap_proto_nkn::NknHandler::new();
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "nkn_request",
            detail: &format!("{} bytes", data.len()),
            data_len: data.len(),
            protocol: "nkn",
        },
    )
    .await;
    handler.handle(data)
}

pub(crate) async fn handle_postgres_named(
    request: TcpRequestContext<'_>,
    data: &[u8],
    handlers: &SessionHandlers,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    crate::protocol_handlers::log_tcp_event(
        ctx,
        output_path,
        peer,
        destination,
        crate::protocol_handlers::TcpEventDetails {
            event_type: "postgres_request",
            detail: &format!("{} bytes", data.len()),
            data_len: data.len(),
            protocol: "postgres",
        },
    )
    .await;
    handlers.postgres.handle(data)
}

pub(crate) async fn handle_raw_named(request: TcpRequestContext<'_>, data: &[u8]) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    let raw_resp = if let Some(custom) = ctx.custom_response() {
        match nettrap_proto_raw::RawHandler::from_custom_response(custom) {
            Ok(handler) => handler.handle(data),
            Err(err) => {
                tracing::warn!(
                    "invalid raw custom response config for {}: {}",
                    ctx.name(),
                    err
                );
                nettrap_proto_raw::RawResponse::new(b"ERROR\n".to_vec())
            }
        }
    } else {
        nettrap_proto_raw::RawHandler::new().handle(data)
    };
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
        &canonical_socket_ip_string(peer),
        peer.port(),
        destination,
        data.len(),
        "",
    );
    ctx.runtime.nbi_collector.record(&nbi).await;
    raw_resp.to_bytes()
}

pub(crate) async fn handle_telnet(
    request: TcpRequestContext<'_>,
    data: &[u8],
    telnet_handler: &nettrap_proto_telnet::TelnetHandler,
    telnet_state: &mut nettrap_proto_telnet::TelnetState,
    telnet_username: &mut String,
) -> Vec<u8> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    let Some(value) = telnet_line_value(data) else {
        return Vec::new();
    };
    let value = value.as_str();

    match telnet_state.clone() {
        nettrap_proto_telnet::TelnetState::WaitingUsername => {
            *telnet_username = value.to_string();
            crate::protocol_handlers::log_tcp_event(
                ctx,
                output_path,
                peer,
                destination,
                crate::protocol_handlers::TcpEventDetails {
                    event_type: "telnet_username",
                    detail: REDACTED_TELNET_AUTH_FIELD,
                    data_len: data.len(),
                    protocol: "telnet",
                },
            )
            .await;
            *telnet_state = nettrap_proto_telnet::TelnetState::WaitingPassword;
            telnet_handler.get_password_prompt()
        }
        nettrap_proto_telnet::TelnetState::WaitingPassword => {
            crate::protocol_handlers::log_tcp_event(
                ctx,
                output_path,
                peer,
                destination,
                crate::protocol_handlers::TcpEventDetails {
                    event_type: "telnet_credentials",
                    detail: &format!(
                        "username={} password={}",
                        REDACTED_TELNET_AUTH_FIELD, REDACTED_TELNET_AUTH_FIELD
                    ),
                    data_len: data.len(),
                    protocol: "telnet",
                },
            )
            .await;
            if !telnet_handler.accepts_credentials(telnet_username, value) {
                crate::protocol_handlers::log_tcp_event(
                    ctx,
                    output_path,
                    peer,
                    destination,
                    crate::protocol_handlers::TcpEventDetails {
                        event_type: "telnet_auth_failure",
                        detail: &format!(
                            "username={} password={}",
                            REDACTED_TELNET_AUTH_FIELD, REDACTED_TELNET_AUTH_FIELD
                        ),
                        data_len: data.len(),
                        protocol: "telnet",
                    },
                )
                .await;
                telnet_username.clear();
                *telnet_state = nettrap_proto_telnet::TelnetState::WaitingUsername;
                return telnet_handler.get_login_failure();
            }
            *telnet_state = nettrap_proto_telnet::TelnetState::Shell;
            telnet_handler.get_login_success()
        }
        nettrap_proto_telnet::TelnetState::Shell => {
            crate::protocol_handlers::log_tcp_event(
                ctx,
                output_path,
                peer,
                destination,
                crate::protocol_handlers::TcpEventDetails {
                    event_type: "telnet_command",
                    detail: value,
                    data_len: data.len(),
                    protocol: "telnet",
                },
            )
            .await;
            let response = telnet_handler.handle_command(value);
            if telnet_command_closes_session(value) {
                *telnet_state = nettrap_proto_telnet::TelnetState::Disconnected;
            }
            response
        }
        nettrap_proto_telnet::TelnetState::Disconnected => Vec::new(),
    }
}

pub(crate) fn telnet_line_value(data: &[u8]) -> Option<String> {
    let cleaned = nettrap_proto_telnet::try_strip_telnet_commands(data)?;
    if cleaned.is_empty() {
        return None;
    }
    let line = std::str::from_utf8(&cleaned).ok()?;
    let line = if let Some(line) = line.strip_suffix("\r\n") {
        if line.chars().any(|ch| matches!(ch, '\r' | '\n')) {
            return None;
        }
        line
    } else if line.ends_with(['\r', '\n']) {
        return None;
    } else {
        if line.chars().any(|ch| matches!(ch, '\r' | '\n')) {
            return None;
        }
        line
    };
    if line
        .chars()
        .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        return None;
    }
    Some(line.to_string())
}

pub(crate) fn telnet_command_closes_session(value: &str) -> bool {
    let raw = value;
    if raw
        .chars()
        .any(|ch| ch.is_whitespace() && !matches!(ch, ' ' | '\t' | '\r' | '\n'))
    {
        return false;
    }
    let value = raw.trim_end_matches([' ', '\t', '\r', '\n']);
    if raw.starts_with([' ', '\t']) {
        return false;
    }

    let mut parts = value.split_whitespace();
    match parts.next() {
        Some("logout" | "exit" | "quit") => parts.next().is_none(),
        _ => false,
    }
}

pub(crate) async fn handle_dns_tcp(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
) -> crate::Result<Vec<u8>> {
    use nettrap_proto_dns::handler::DnsHandlerTrait;

    let tcp_dns_handler = crate::protocol_handlers::init_dns_handler(ctx)?;

    if data.len() < 2 {
        return Ok(Vec::new());
    }

    let dns_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + dns_len {
        tracing::debug!(
            "DNS TCP frame incomplete from {}: declared={} available={}",
            peer,
            dns_len,
            data.len().saturating_sub(2)
        );
        return Ok(Vec::new());
    }

    let dns_data = &data[2..2 + dns_len];
    match tcp_dns_handler.handle_query(dns_data, *peer).await {
        Ok(response) => {
            let Some(tcp_response) = frame_dns_tcp_response(&response) else {
                tracing::warn!(
                    "DNS TCP response too large to frame: {} bytes",
                    response.len()
                );
                return Ok(Vec::new());
            };
            log_event(
                output_path,
                ctx.name(),
                peer,
                "dns_tcp_query",
                &format!("{} bytes", data.len()),
            )
            .await;
            if let Some((domain, query_type)) =
                nettrap_proto_dns::handler::parse_query_summary(dns_data)
            {
                let nbi = crate::nbi::dns_nbi(
                    ctx.name(),
                    &canonical_socket_ip_string(peer),
                    peer.port(),
                    destination,
                    &domain,
                    &query_type,
                );
                ctx.runtime.nbi_collector.record(&nbi).await;
            } else {
                tracing::debug!("Skipping DNS NBI record for malformed TCP query");
            }
            Ok(tcp_response)
        }
        Err(e) => {
            tracing::error!("DNS TCP error: {}", e);
            Err(crate::Error::Other(format!("DNS TCP error: {}", e)))
        }
    }
}

pub(crate) fn frame_dns_tcp_response(response: &[u8]) -> Option<Vec<u8>> {
    let response_len = u16::try_from(response.len()).ok()?;
    let mut tcp_response = Vec::with_capacity(2 + response.len());
    tcp_response.extend_from_slice(&response_len.to_be_bytes());
    tcp_response.extend_from_slice(response);
    Some(tcp_response)
}

pub(crate) async fn handle_irc(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
    irc_handler: &nettrap_proto_irc::IrcHandler,
    irc_nick: &mut String,
) -> Vec<u8> {
    let command = match std::str::from_utf8(data) {
        Ok(command) => match irc_command_line(command) {
            Some(command) => command,
            None => return b":nettrap 421 * INVALID :Unknown command\r\n".to_vec(),
        },
        Err(e) => {
            tracing::warn!("IRC command from {} is invalid UTF-8: {}", peer, e);
            return b":nettrap 421 * :Invalid command encoding\r\n".to_vec();
        }
    };
    let upper_cmd = command.to_uppercase();
    if upper_cmd.starts_with("NICK ") {
        let raw_nick = command.get(5..).unwrap_or("");
        if raw_nick.trim_matches([' ', '\t']) != raw_nick
            || raw_nick.is_empty()
            || raw_nick
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || !raw_nick
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            *irc_nick = "unknown".to_string();
        } else {
            *irc_nick = raw_nick.chars().take(30).collect();
        }
    }
    tracing::debug!(
        "IRC command from {} ({}): {}",
        peer,
        irc_nick,
        crate::protocol_handlers::redact_irc_command(command)
    );
    crate::protocol_handlers::log_irc_event(ctx, output_path, peer, destination, irc_nick, command)
        .await;
    match irc_handler.handle(command, irc_nick).await {
        Ok(resp) => resp.to_bytes(),
        Err(_) => Vec::new(),
    }
}

fn irc_command_line(command: &str) -> Option<&str> {
    if command
        .chars()
        .any(|ch| matches!(ch, '\0' | '\u{0085}' | '\u{2028}' | '\u{2029}'))
    {
        return None;
    }
    if let Some(line) = command.strip_suffix("\r\n") {
        if line.chars().any(|ch| matches!(ch, '\r' | '\n')) {
            return None;
        }
        return Some(line);
    }
    if command.ends_with(['\r', '\n']) {
        return None;
    }
    if command.chars().any(|ch| matches!(ch, '\r' | '\n')) {
        return None;
    }
    Some(command)
}

pub(crate) async fn handle_tls_plain(
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
        &canonical_socket_ip_string(peer),
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

pub(crate) async fn handle_upnp_tcp(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
) -> Vec<u8> {
    let listen_host = ctx
        .config
        .server_name
        .as_deref()
        .unwrap_or(destination.ip());
    let Ok(handler) = crate::protocol_handlers::init_upnp_handler(listen_host) else {
        tracing::warn!(
            "Ignoring UPnP TCP request for invalid listener host {}",
            listen_host
        );
        log_event(
            output_path,
            ctx.name(),
            peer,
            "upnp_request_rejected",
            &format!(
                "invalid listener host {}, {} bytes",
                listen_host,
                data.len()
            ),
        )
        .await;
        return Vec::new();
    };
    let response = handler.handle_http(data);
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
    let mut nbi = crate::nbi::raw_nbi(
        ctx.name(),
        &canonical_socket_ip_string(peer),
        peer.port(),
        destination,
        data.len(),
        "",
    );
    nbi.add("detected_protocol", "upnp");
    ctx.runtime.nbi_collector.record(&nbi).await;

    response
}

pub(crate) async fn handle_ssh(
    ctx: &Arc<ListenerContext>,
    data: &[u8],
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    output_path: Option<&std::path::Path>,
    first_packet: &mut bool,
    banner_already_sent: bool,
) -> Vec<u8> {
    let is_first_packet = *first_packet;
    if is_first_packet {
        *first_packet = false;
    }

    let handler = if let Some(banner) = ctx.banner() {
        match nettrap_proto_ssh::SshHandler::new().with_version(banner) {
            Ok(handler) => handler,
            Err(err) => {
                tracing::warn!("invalid SSH banner configured for {}: {}", ctx.name(), err);
                return Vec::new();
            }
        }
    } else {
        nettrap_proto_ssh::SshHandler::new()
    };

    if is_first_packet {
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
                crate::protocol_handlers::TcpEventDetails {
                    event_type: "ssh_version",
                    detail: &client_version,
                    data_len: data.len(),
                    protocol: "ssh",
                },
            )
            .await;
        } else {
            crate::protocol_handlers::log_tcp_event(
                ctx,
                output_path,
                peer,
                destination,
                crate::protocol_handlers::TcpEventDetails {
                    event_type: "ssh_handshake",
                    detail: &format!("{} bytes", data.len()),
                    data_len: data.len(),
                    protocol: "ssh",
                },
            )
            .await;
        }
        build_ssh_first_response(&handler, banner_already_sent)
    } else {
        crate::protocol_handlers::log_tcp_event(
            ctx,
            output_path,
            peer,
            destination,
            crate::protocol_handlers::TcpEventDetails {
                event_type: "ssh_data",
                detail: &format!("{} bytes", data.len()),
                data_len: data.len(),
                protocol: "ssh",
            },
        )
        .await;
        handler.build_auth_failure()
    }
}

pub(crate) fn build_ssh_first_response(
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

pub(crate) async fn handle_detected_protocol(
    request: TcpRequestContext<'_>,
    data: &[u8],
    _first_bytes: &[u8],
    handlers: &SessionHandlers,
    webroot_server: Option<&crate::webroot::WebrootServer>,
    session: &mut TcpSessionState,
) -> crate::Result<Vec<u8>> {
    let TcpRequestContext {
        ctx,
        peer,
        output_path,
        destination,
        ..
    } = request;
    if let Some((detected_name, score)) = ctx.runtime.router.route_tcp(data, destination.port()) {
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
                request,
                &detected_name,
                data,
                handlers,
                webroot_server,
                session,
            )
            .await?
            {
                return Ok(response);
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
    let mut nbi = crate::nbi::raw_nbi(
        ctx.name(),
        &canonical_socket_ip_string(peer),
        peer.port(),
        destination,
        data.len(),
        "",
    );
    nbi.add("note", "no protocol detected");
    ctx.runtime.nbi_collector.record(&nbi).await;

    let raw_handler = nettrap_proto_raw::RawHandler::new();
    Ok(raw_handler.handle(data).to_bytes())
}

#[cfg(test)]
#[path = "tcp_dispatch_tests.rs"]
mod tests;
