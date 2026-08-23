//! Plaintext TCP connection handling.
//!
//! Carries the plaintext connection-lifecycle phases (setup, one-shot accept,
//! cleartext banner, implicit-TLS / MySQL-STARTTLS upgrade, and the read /
//! frame / dispatch loop), kept separate from the TLS-wrapped path in
//! `super::wrapped` so the module stays a clean three-part decomposition.

use super::*;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;

use super::super::tcp_ftp::{FtpCommandAction, finish_ftp_passive_transfer};
use crate::listener_context::ListenerContext;
use crate::session::SessionDestination;
use crate::utils::canonical_socket_ip_string;
use crate::utils::log_event;
use crate::utils::service_name::{is_usable_service_name_input, resolve_service_name};

pub async fn handle_tcp_connection(
    ctx: Arc<ListenerContext>,
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    destination: SessionDestination,
    output_path: Option<&std::path::Path>,
) -> crate::Result<()> {
    handle_tcp_connection_with_policy(
        ctx,
        stream,
        peer,
        destination,
        output_path,
        nettrap_engine::FlowPolicy::new(nettrap_engine::FlowDecision::Emulate).resolve(true),
    )
    .await
}

pub(crate) async fn handle_tcp_connection_with_policy(
    ctx: Arc<ListenerContext>,
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    destination: SessionDestination,
    output_path: Option<&std::path::Path>,
    configured: nettrap_engine::FlowPolicyResolution,
) -> crate::Result<()> {
    let control_local_addr = control_local_addr_or_log(stream.local_addr(), ctx.name(), &peer);
    let conn = TcpConnection {
        ctx,
        peer,
        destination,
        output_path,
        control_local_addr,
    };

    let (decision, rule) = if super::forward::is_forward_listener(conn.ctx.name()) {
        (
            nettrap_engine::FlowDecision::Pass,
            "listener.protocol=forward",
        )
    } else {
        (configured.decision(), configured.rule().as_str())
    };
    log_event(
        output_path,
        conn.ctx.name(),
        &peer,
        "policy_decision",
        &format!("decision={} rule={}", decision, rule),
    )
    .await;

    match decision {
        nettrap_engine::FlowDecision::Pass => {
            return super::forward::forward_to_original_destination(&conn, stream, false).await;
        }
        nettrap_engine::FlowDecision::Capture => {
            return super::forward::forward_to_original_destination(&conn, stream, true).await;
        }
        nettrap_engine::FlowDecision::Sinkhole => {
            return sinkhole_tcp_connection(&conn, &mut stream).await;
        }
        nettrap_engine::FlowDecision::Block => return Ok(()),
        nettrap_engine::FlowDecision::Emulate => {}
    }

    let (handlers, webroot_server, session, mut ssh_banner_sent, connection_buf) =
        tcp_session_setup(&conn).await?;

    if accept_tcp_one_shot(&conn, &mut stream).await? {
        return Ok(());
    }

    send_tcp_banner(&conn, &mut stream, &handlers, &mut ssh_banner_sent).await?;

    let stream = match try_tcp_tls_upgrade(&conn, stream, &webroot_server).await {
        TlsUpgradeOutcome::Done(result) => return result,
        TlsUpgradeOutcome::Plain(stream) => stream,
    };

    run_tcp_frame_loop(
        conn,
        stream,
        handlers,
        session,
        webroot_server,
        ssh_banner_sent,
        connection_buf,
    )
    .await
}

async fn sinkhole_tcp_connection(
    conn: &TcpConnection<'_>,
    stream: &mut tokio::net::TcpStream,
) -> crate::Result<()> {
    const SINKHOLE_BUFFER_SIZE: usize = 16 * 1024;

    let deadline = tokio::time::Instant::now() + Duration::from_millis(conn.ctx.timeout_ms());
    let mut buffer = [0_u8; SINKHOLE_BUFFER_SIZE];
    let mut received = 0_u64;
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut buffer)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(length)) => {
                conn.ctx.write_pcap_event_for_destination(
                    &buffer[..length],
                    &conn.peer,
                    &conn.destination,
                );
                received = received.saturating_add(length as u64);
            }
            Ok(Err(error)) => return Err(error.into()),
        }
    }
    conn.ctx
        .update_session_bytes(&conn.peer, "TCP", &conn.destination, received, 0);
    Ok(())
}

fn control_local_addr_or_log(
    result: io::Result<SocketAddr>,
    listener_name: &str,
    peer: &SocketAddr,
) -> Option<SocketAddr> {
    result
        .map_err(|err| {
            tracing::debug!(
                "TCP '{}' control local address lookup failed for {}: {}",
                listener_name,
                peer,
                err
            );
            err
        })
        .ok()
}

/// Phase A: rate-limited connect logging, execute-cmd firing, per-connection
/// handler/state construction, and the pre-banner scanner-frustration delay.
async fn tcp_session_setup(
    conn: &TcpConnection<'_>,
) -> crate::Result<(
    SessionHandlers,
    Option<crate::webroot::WebrootServer>,
    TcpSessionState,
    bool,
    Vec<u8>,
)> {
    let ctx = &conn.ctx;
    let peer = &conn.peer;
    let destination = &conn.destination;
    let output_path = conn.output_path;

    // Rate-limited connection logging - deduplicate connect events
    let dedup_key = format!("{}:{}", ctx.name(), canonical_socket_ip_string(peer));
    if ctx.connection_dedup.should_log(&dedup_key) {
        log_event(output_path, ctx.name(), peer, "connect", "").await;
    }
    ctx.fire_execute_cmd_for_session(peer, "TCP", destination);

    let handlers = SessionHandlers::from_ctx(ctx)?;

    let webroot_server = match ctx.webroot() {
        Some(root) => Some(
            crate::webroot::WebrootServer::new(root)?.with_server_version(ctx.server_version())?,
        ),
        None => None,
    };

    let session = TcpSessionState::new();
    let ssh_banner_sent = false;
    let connection_buf: Vec<u8> = Vec::new();

    // Apply banner delay BEFORE sending banner to frustrate scanners
    if ctx.banner_delay_ms() > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(ctx.banner_delay_ms())).await;
    }

    Ok((
        handlers,
        webroot_server,
        session,
        ssh_banner_sent,
        connection_buf,
    ))
}

/// Phase B: one-shot protocol handling. Returns `true` when the connection
/// was fully serviced as a one-shot and the coordinator must return `Ok(())`.
async fn accept_tcp_one_shot(
    conn: &TcpConnection<'_>,
    stream: &mut tokio::net::TcpStream,
) -> crate::Result<bool> {
    Ok(!conn.ctx.use_ssl()
        && handle_tcp_one_shot_connection(
            &conn.ctx,
            stream,
            &conn.peer,
            &conn.destination,
            conn.output_path,
        )
        .await?)
}

/// Phase C: protocol-specific cleartext banner / MySQL STARTTLS handshake.
async fn send_tcp_banner(
    conn: &TcpConnection<'_>,
    stream: &mut tokio::net::TcpStream,
    handlers: &SessionHandlers,
    ssh_banner_sent: &mut bool,
) -> crate::Result<()> {
    let ctx = &conn.ctx;
    let destination = &conn.destination;

    // Protocol-specific banners (only for non-TLS connections)
    // For TLS connections, banners are sent inside handle_wrapped_connection after the handshake.
    // Implicit TLS ports must not receive a cleartext protocol banner before the ClientHello.
    // A MySQL+SSL listener performs a STARTTLS-style upgrade: it must send
    // the cleartext seq-0 handshake (advertising CLIENT_SSL) first, then
    // upgrade the live stream when the client replies with an SSLRequest.
    let mysql_starttls = listener_name_matches_protocol(ctx.name(), "mysql")
        && ctx.use_ssl()
        && ctx.runtime.ca.is_some();
    if (!ctx.use_ssl() || mysql_starttls) && !is_implicit_tls_port(destination.port()) {
        if mysql_starttls {
            let handshake = handlers.mysql.get_handshake_with_tls(true);
            write_tcp_with_timeout(ctx, stream, &handshake, &conn.peer, "TCP").await?;
        } else if let Some(banner_bytes) = cleartext_banner_bytes(ctx, handlers, ssh_banner_sent)? {
            write_tcp_with_timeout(ctx, stream, &banner_bytes, &conn.peer, "TCP").await?;
        }
    }

    Ok(())
}

fn cleartext_banner_bytes(
    ctx: &ListenerContext,
    handlers: &SessionHandlers,
    ssh_banner_sent: &mut bool,
) -> crate::Result<Option<Vec<u8>>> {
    let name = ctx.name();

    if listener_name_matches_protocol(name, "irc") {
        // Use the session handler's banner so the connect NOTICE AUTH lines
        // carry the configured ServerName, matching the 001+ welcome replies
        // (get_protocol_banner keys only off `banner`).
        return Ok(Some(handlers.irc.get_welcome_banner().as_bytes().to_vec()));
    }
    if listener_name_matches_protocol(name, "smtp") || listener_name_matches_protocol(name, "smtps")
    {
        // Same rationale as IRC: the session handler honors ServerName
        // (server_name, falling back to banner), so route the 220 greeting
        // through it instead of get_protocol_banner, which sees only banner.
        return Ok(Some(handlers.smtp.get_welcome_banner().as_bytes().to_vec()));
    }
    if listener_name_matches_protocol(name, "pop3") || listener_name_matches_protocol(name, "pop3s")
    {
        return Ok(Some(handlers.pop3.get_welcome_banner().as_bytes().to_vec()));
    }
    if listener_name_matches_protocol(name, "imap") || listener_name_matches_protocol(name, "imaps")
    {
        return Ok(Some(handlers.imap.get_welcome_banner().as_bytes().to_vec()));
    }
    if listener_name_matches_protocol(name, "ftp") || listener_name_matches_protocol(name, "ftps") {
        return Ok(Some(
            handlers.ftp.get_banner_at(crate::faketime::fake_now()),
        ));
    }
    if let Some(banner_bytes) = crate::protocol_handlers::get_protocol_banner(name, ctx.banner())? {
        *ssh_banner_sent = listener_name_matches_protocol(name, "ssh");
        return Ok(Some(banner_bytes));
    }
    Ok(None)
}

/// Phase D: implicit-TLS detection and upgrade. On a successful or failed
/// wrap (or peek error) the connection is finished and the carried result
/// is returned; otherwise the still-plaintext stream is handed back.
async fn try_tcp_tls_upgrade(
    conn: &TcpConnection<'_>,
    stream: tokio::net::TcpStream,
    webroot_server: &Option<crate::webroot::WebrootServer>,
) -> TlsUpgradeOutcome {
    let ctx = conn.ctx.clone();
    let name = ctx.name();
    let peer = conn.peer;
    let destination = &conn.destination;
    let output_path = conn.output_path;
    let control_local_addr = conn.control_local_addr;

    // TLS wrapping. MySQL is excluded here: it never sends a ClientHello
    // first; its TLS upgrade is the STARTTLS-style flow handled in the
    // plaintext frame loop below.
    if ctx.use_ssl()
        && !listener_name_matches_protocol(name, "mysql")
        && let Some(ref ca) = ctx.runtime.ca
    {
        let wrapper = nettrap_tls_mitm::TlsWrapper::new(Arc::clone(ca));
        match peek_complete_tls_record(&stream, Duration::from_millis(ctx.timeout_ms())).await {
            Ok(Some(peek_buf)) => {
                if let Some((ja3_str, ja3_hash)) =
                    nettrap_proto_tls::ja3::ja3_from_handshake(&peek_buf)
                {
                    tracing::info!("JA3: {} ({})", ja3_hash, ja3_str);
                    let mut nbi = crate::nbi::tls_nbi(
                        ctx.name(),
                        &canonical_socket_ip_string(&peer),
                        peer.port(),
                        destination,
                        "",
                    );
                    nbi.add("ja3", ja3_str);
                    nbi.add("ja3_hash", ja3_hash);
                    if let Some(ja4) = nettrap_proto_tls::ja3::ja4_from_handshake(&peek_buf) {
                        tracing::info!("JA4: {}", ja4);
                        nbi.add("ja4", ja4);
                    }
                    ctx.runtime.nbi_collector.record(&nbi).await;
                }
                match maybe_wrap_tls_with_timeout(
                    wrapper,
                    stream,
                    &peek_buf,
                    Duration::from_millis(ctx.timeout_ms()),
                )
                .await
                {
                    Ok((wrapped, sni)) => {
                        if let Some(ref sni_name) = sni {
                            tracing::debug!("TLS SNI: {} from {}", sni_name, peer);
                            log_event(output_path, ctx.name(), &peer, "tls_sni", sni_name).await;
                            let nbi = crate::nbi::tls_nbi(
                                ctx.name(),
                                &canonical_socket_ip_string(&peer),
                                peer.port(),
                                destination,
                                sni_name,
                            );
                            ctx.runtime.nbi_collector.record(&nbi).await;
                        }
                        return TlsUpgradeOutcome::Done(
                            handle_wrapped_connection(
                                ctx,
                                wrapped,
                                peer,
                                destination.clone(),
                                output_path,
                                webroot_server.as_ref(),
                                control_local_addr,
                            )
                            .await,
                        );
                    }
                    Err(e) => {
                        tracing::debug!("TLS wrap failed for {}: {}", peer, e);
                        return TlsUpgradeOutcome::Done(Ok(()));
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::debug!("TLS peek failed for {}: {}", peer, e);
                return TlsUpgradeOutcome::Done(Ok(()));
            }
        }
    }

    TlsUpgradeOutcome::Plain(stream)
}

/// Phase E: the plaintext read / frame / dispatch loop.
async fn run_tcp_frame_loop(
    conn: TcpConnection<'_>,
    mut stream: tokio::net::TcpStream,
    handlers: SessionHandlers,
    mut session: TcpSessionState,
    webroot_server: Option<crate::webroot::WebrootServer>,
    ssh_banner_sent: bool,
    mut connection_buf: Vec<u8>,
) -> crate::Result<()> {
    let TcpConnection {
        ctx,
        peer,
        destination,
        output_path,
        control_local_addr,
    } = conn;
    let name = ctx.name();

    let mut buf = vec![0u8; 4096];

    loop {
        match read_tcp_with_timeout(&ctx, &mut stream, &mut buf, &peer, "TCP").await {
            Some(len) => {
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
                    let (frame_mode, frame_result) = next_tcp_frame_with_mode(
                        &mut connection_buf,
                        name,
                        destination.port(),
                        ctx.runtime.router.as_ref(),
                        session.smtp_data_mode,
                        session.ssh_first_packet,
                    );
                    match frame_result {
                        TcpFrameResult::Complete(frame) => {
                            // MySQL STARTTLS: client replied to the cleartext
                            // handshake with an SSLRequest — upgrade the live
                            // stream to TLS, then resume MySQL over TLS.
                            if listener_name_matches_protocol(name, "mysql")
                                && ctx.use_ssl()
                                && ctx.runtime.ca.is_some()
                                && is_mysql_ssl_request(&frame)
                            {
                                if !response.is_empty() {
                                    ctx.apply_response_delay().await;
                                    write_tcp_with_timeout(
                                        &ctx,
                                        &mut stream,
                                        &response,
                                        &peer,
                                        "TCP",
                                    )
                                    .await?;
                                    ctx.write_pcap_response_for_destination(
                                        &response,
                                        &peer,
                                        &destination,
                                    );
                                }
                                // Any further buffered bytes would be cleartext
                                // smuggled into the TLS session — refuse.
                                if !connection_buf.is_empty() {
                                    tracing::debug!(
                                        "MySQL STARTTLS: unexpected trailing cleartext from {}, closing",
                                        peer
                                    );
                                    return Ok(());
                                }
                                let Some(ca) = ctx.runtime.ca.clone() else {
                                    return Ok(());
                                };
                                let hostname = mysql_starttls_hostname(&ctx)?;
                                let wrapper = nettrap_tls_mitm::TlsWrapper::new(ca);
                                let wrapped = match wrap_mysql_starttls_with_timeout(
                                    wrapper,
                                    stream,
                                    &hostname,
                                    Duration::from_millis(ctx.timeout_ms()),
                                )
                                .await
                                {
                                    Ok(wrapped) => wrapped,
                                    Err(e) => {
                                        tracing::debug!(
                                            "MySQL STARTTLS handshake failed for {}: {}",
                                            peer,
                                            e
                                        );
                                        return Ok(());
                                    }
                                };
                                log_event(output_path, ctx.name(), &peer, "mysql_starttls", "")
                                    .await;
                                return handle_wrapped_connection(
                                    ctx,
                                    wrapped,
                                    peer,
                                    destination.clone(),
                                    output_path,
                                    webroot_server.as_ref(),
                                    control_local_addr,
                                )
                                .await;
                            }
                            let first_bytes = &frame[..frame.len().min(20)];
                            let dispatch_name = tcp_dispatch_name_for_frame(name, frame_mode);
                            if frame_mode != TcpFrameMode::Tls
                                && should_handle_ftp_ordered(&ctx, name, &frame, &destination)
                            {
                                match prepare_ordered_ftp_action(
                                    &ctx,
                                    output_path,
                                    &handlers.ftp,
                                    &mut session.ftp_passive_state,
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
                                        if tcp_frame_closes_session("ftp", &frame) {
                                            close_after_response = true;
                                            break;
                                        }
                                    }
                                    FtpCommandAction::Transfer {
                                        listener,
                                        permit,
                                        transfer,
                                    } => {
                                        let start_response = transfer.start_response.to_bytes();
                                        if !start_response.is_empty() {
                                            ctx.apply_response_delay().await;
                                            write_tcp_with_timeout(
                                                &ctx,
                                                &mut stream,
                                                &start_response,
                                                &peer,
                                                "TCP",
                                            )
                                            .await?;
                                            ctx.write_pcap_response_for_destination(
                                                &start_response,
                                                &peer,
                                                &destination,
                                            );
                                            immediate_sent_bytes = add_sent_bytes(
                                                immediate_sent_bytes,
                                                start_response.len(),
                                            );
                                        }
                                        let frame_response =
                                            finish_ftp_passive_transfer(listener, permit, transfer)
                                                .await;
                                        response.extend_from_slice(&frame_response);
                                    }
                                }
                            } else {
                                let request = TcpRequestContext {
                                    ctx: &ctx,
                                    peer: &peer,
                                    output_path,
                                    destination: &destination,
                                    control_local_addr,
                                    http_over_tls: false,
                                    ssh_banner_sent,
                                };
                                let frame_response = handle_tcp_protocol(
                                    request,
                                    dispatch_name,
                                    &frame,
                                    first_bytes,
                                    &handlers,
                                    webroot_server.as_ref(),
                                    &mut session,
                                )
                                .await?;
                                response.extend_from_slice(&frame_response);
                                if tcp_frame_closes_session(dispatch_name, &frame) {
                                    close_after_response = true;
                                    break;
                                }
                            }
                        }
                        TcpFrameResult::Incomplete => break,
                        TcpFrameResult::Invalid {
                            response: frame_response,
                        }
                        | TcpFrameResult::TooLarge {
                            response: frame_response,
                        } => {
                            if session.smtp_data_mode {
                                session.smtp_data_mode = false;
                                session.smtp_data_buf.clear();
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
                    ctx.apply_response_delay().await;
                    let send_result =
                        write_tcp_with_timeout(&ctx, &mut stream, &response, &peer, "TCP").await;
                    if send_result.is_ok() {
                        ctx.write_pcap_response_for_destination(&response, &peer, &destination);
                        sent_bytes = add_sent_bytes(sent_bytes, response.len());
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
            None => return Ok(()),
        }
    }
}

fn mysql_starttls_hostname(ctx: &ListenerContext) -> crate::Result<String> {
    if let Some(name) = ctx.config.server_name.as_deref() {
        if !is_usable_service_name_input(name) {
            return Err(crate::Error::Config(format!(
                "invalid MySQL STARTTLS hostname for listener {}: {}",
                ctx.name(),
                name
            )));
        }
        return Ok(resolve_service_name(name));
    }

    if let Some(name) = ctx.config.banner.as_deref() {
        if !is_usable_service_name_input(name) {
            return Err(crate::Error::Config(format!(
                "invalid MySQL STARTTLS hostname for listener {}: {}",
                ctx.name(),
                name
            )));
        }
        return Ok(resolve_service_name(name));
    }

    Ok(resolve_service_name(ctx.name()))
}

async fn maybe_wrap_tls_with_timeout(
    wrapper: nettrap_tls_mitm::TlsWrapper,
    stream: tokio::net::TcpStream,
    peeked: &[u8],
    timeout_duration: Duration,
) -> io::Result<(nettrap_tls_mitm::WrappedStream, Option<String>)> {
    match tokio::time::timeout(timeout_duration, wrapper.maybe_wrap(stream, peeked)).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(io::Error::other(err.to_string())),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "TLS handshake timed out",
        )),
    }
}

async fn wrap_mysql_starttls_with_timeout(
    wrapper: nettrap_tls_mitm::TlsWrapper,
    stream: tokio::net::TcpStream,
    hostname: &str,
    timeout_duration: Duration,
) -> io::Result<nettrap_tls_mitm::WrappedStream> {
    match tokio::time::timeout(
        timeout_duration,
        wrapper.wrap_with_hostname(stream, hostname),
    )
    .await
    {
        Ok(Ok(tls_stream)) => Ok(nettrap_tls_mitm::WrappedStream::Tls(Box::new(tls_stream))),
        Ok(Err(err)) => Err(io::Error::other(err.to_string())),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "MySQL STARTTLS handshake timed out",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        control_local_addr_or_log, maybe_wrap_tls_with_timeout, mysql_starttls_hostname,
        wrap_mysql_starttls_with_timeout,
    };
    use crate::listener_context::ListenerContext;
    use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
    use crate::process_filter::ProcessFilter;
    use crate::session::{PortForwardTable, SessionTracker};
    use std::io;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};

    fn test_context(server_name: Option<String>, banner: Option<String>) -> ListenerContext {
        ListenerContext::builder()
            .name("mysql")
            .port(3306)
            .server_name(server_name)
            .banner(banner)
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
            .expect("listener context should build")
    }

    fn test_ftp_context(banner: Option<String>) -> Arc<ListenerContext> {
        Arc::new(
            ListenerContext::builder()
                .name("ftp")
                .port(21)
                .banner(banner)
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
        )
    }

    #[test]
    fn mysql_starttls_hostname_prefers_server_name_over_banner() {
        let ctx = test_context(
            Some("mainframe01".to_string()),
            Some("banner.example".to_string()),
        );

        assert_eq!(
            mysql_starttls_hostname(&ctx).expect("hostname"),
            "mainframe01"
        );
    }

    #[test]
    fn mysql_starttls_hostname_ignores_blank_server_name() {
        let ctx = test_context(Some(" ".to_string()), Some("banner.example".to_string()));

        assert_eq!(
            mysql_starttls_hostname(&ctx).expect("hostname"),
            "banner.example"
        );
    }

    #[test]
    fn mysql_starttls_hostname_ignores_unicode_whitespace_server_name() {
        let ctx = test_context(
            Some("mainframe01\u{00a0}".to_string()),
            Some("banner.example".to_string()),
        );

        let err = mysql_starttls_hostname(&ctx).expect_err("hostname should be rejected");
        assert!(err.to_string().contains("invalid MySQL STARTTLS hostname"));
    }

    #[test]
    fn mysql_starttls_hostname_ignores_c1_control_server_name() {
        let ctx = test_context(
            Some("mainframe01\u{009f}".to_string()),
            Some("banner.example".to_string()),
        );

        let err = mysql_starttls_hostname(&ctx).expect_err("hostname should be rejected");
        assert!(err.to_string().contains("invalid MySQL STARTTLS hostname"));
    }

    #[test]
    fn mysql_starttls_hostname_ignores_ascii_padded_server_name() {
        let ctx = test_context(
            Some(" mainframe01 ".to_string()),
            Some("banner.example".to_string()),
        );

        let err = mysql_starttls_hostname(&ctx).expect_err("hostname should be rejected");
        assert!(err.to_string().contains("invalid MySQL STARTTLS hostname"));
    }

    #[test]
    fn mysql_starttls_hostname_uses_banner_when_server_name_missing() {
        let ctx = test_context(None, Some("banner.example".to_string()));

        assert_eq!(
            mysql_starttls_hostname(&ctx).expect("hostname"),
            "banner.example"
        );
    }

    #[test]
    fn mysql_starttls_hostname_rejects_invalid_server_name_without_defaulting() {
        let ctx = test_context(
            Some("bad><name".to_string()),
            Some("banner.example".to_string()),
        );

        let err = mysql_starttls_hostname(&ctx).expect_err("hostname should be rejected");
        assert!(err.to_string().contains("invalid MySQL STARTTLS hostname"));
    }

    #[test]
    fn mysql_starttls_hostname_defaults_to_listener_name() {
        let ctx = test_context(None, None);

        assert_eq!(mysql_starttls_hostname(&ctx).expect("hostname"), "mysql");
    }

    #[tokio::test]
    async fn cleartext_banner_bytes_uses_configured_ftp_banner_bytes() {
        let ctx = test_ftp_context(Some("banner.example".to_string()));
        let handlers = super::SessionHandlers::from_ctx(&ctx).expect("handlers should initialize");
        let mut ssh_banner_sent = false;

        let banner = super::cleartext_banner_bytes(&ctx, &handlers, &mut ssh_banner_sent)
            .expect("banner")
            .expect("banner bytes");
        let text = String::from_utf8_lossy(&banner);

        assert!(
            text.contains("banner.example"),
            "unexpected banner: {text:?}"
        );
        assert!(
            !text.contains("NetTrap FTP Ready"),
            "default banner leaked: {text:?}"
        );
        assert!(!ssh_banner_sent);
    }

    #[test]
    fn control_local_addr_preserves_successful_socket_addr() {
        let peer = "127.0.0.1:50000".parse().expect("peer addr");
        let local = "127.0.0.1:21".parse().expect("local addr");

        assert_eq!(
            control_local_addr_or_log(Ok(local), "ftp", &peer),
            Some(local)
        );
    }

    #[test]
    fn control_local_addr_surfaces_lookup_error() {
        let peer = "127.0.0.1:50000".parse().expect("peer addr");

        let result =
            control_local_addr_or_log(Err(io::Error::from_raw_os_error(libc::EBADF)), "ftp", &peer);

        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn mysql_starttls_handshake_times_out_when_client_stalls() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local listener");
        let addr = listener.local_addr().expect("listener addr");
        let client = TcpStream::connect(addr).await.expect("connect test client");
        let (server_stream, _) = listener.accept().await.expect("accept test client");
        let ca = Arc::new(nettrap_tls_mitm::CertificateAuthority::generate().expect("test CA"));
        let wrapper = nettrap_tls_mitm::TlsWrapper::new(ca);

        let result = wrap_mysql_starttls_with_timeout(
            wrapper,
            server_stream,
            "mysql",
            Duration::from_millis(10),
        )
        .await;
        drop(client);

        let Err(err) = result else {
            panic!("idle client should time out");
        };
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn implicit_tls_wrapper_leaves_plain_stream_without_waiting_for_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local listener");
        let addr = listener.local_addr().expect("listener addr");
        let client = TcpStream::connect(addr).await.expect("connect test client");
        let (server_stream, _) = listener.accept().await.expect("accept test client");
        let ca = Arc::new(nettrap_tls_mitm::CertificateAuthority::generate().expect("test CA"));
        let wrapper = nettrap_tls_mitm::TlsWrapper::new(ca);

        let (wrapped, sni) = maybe_wrap_tls_with_timeout(
            wrapper,
            server_stream,
            b"GET / HTTP/1.1\r\n",
            Duration::from_millis(10),
        )
        .await
        .expect("plaintext stream should pass through");
        drop(client);

        assert!(!wrapped.is_tls());
        assert_eq!(sni, None);
    }
}
