//! TLS-wrapped TCP connection handling.
//!
//! Carries the wrapped-stream variant of the TCP frame loop, kept separate
//! from the plaintext path in `super` because it diverges in banner gating,
//! upgrade handling, and the `http_over_tls` request flag.

use super::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::{future::Future, io};

use super::super::tcp_ftp::{FtpCommandAction, finish_ftp_passive_transfer};
use crate::listener_context::ListenerContext;
use crate::protocol_handlers::get_protocol_banner;
use crate::session::SessionDestination;

/// Borrowed per-connection inputs threaded through the TLS-wrapped frame
/// processing phase. The wrapped path diverges from the plaintext path
/// (no implicit-TLS upgrade, no MySQL STARTTLS, `http_over_tls = true`),
/// so it carries its own verbatim helpers rather than reusing the
/// `handle_tcp_connection` phase helpers.
struct WrappedFrameCtx<'a> {
    ctx: &'a Arc<ListenerContext>,
    name: &'a str,
    peer: &'a std::net::SocketAddr,
    destination: &'a SessionDestination,
    output_path: Option<&'a std::path::Path>,
    webroot_server: Option<&'a crate::webroot::WebrootServer>,
    control_local_addr: Option<SocketAddr>,
}

/// Outcome of processing one read's worth of buffered TLS bytes.
struct WrappedFrameOutcome {
    response: Vec<u8>,
    immediate_sent_bytes: u64,
    close_after_response: bool,
}

/// Wrapped Phase A: per-connection handler/state construction and the
/// pre-banner scanner-frustration delay. Unlike `tcp_session_setup` this
/// path performs no connect dedup logging, execute-cmd firing, or webroot
/// construction (the webroot server is passed in by the caller).
async fn wrapped_session_setup(
    ctx: &Arc<ListenerContext>,
) -> crate::Result<(SessionHandlers, TcpSessionState)> {
    let handlers = SessionHandlers::from_ctx(ctx)?;
    let session = TcpSessionState::new();

    if ctx.banner_delay_ms() > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(ctx.banner_delay_ms())).await;
    }

    Ok((handlers, session))
}

/// Wrapped Phase C: protocol-specific banner sent over the already-wrapped
/// TLS stream. Distinct from `send_tcp_banner`: it operates on a
/// `WrappedStream`, has no implicit-TLS / MySQL STARTTLS gating, and emits
/// only the SMTP/FTP/POP3 post-handshake banners.
async fn send_wrapped_banner(
    ctx: &Arc<ListenerContext>,
    stream: &mut nettrap_tls_mitm::WrappedStream,
    handlers: &SessionHandlers,
    peer: &std::net::SocketAddr,
) -> crate::Result<()> {
    if let Some(banner) = wrapped_banner_bytes(ctx, handlers)? {
        write_wrapped_with_timeout(ctx, stream, &banner, peer).await?;
    }

    Ok(())
}

async fn write_wrapped_with_timeout(
    ctx: &ListenerContext,
    stream: &mut nettrap_tls_mitm::WrappedStream,
    data: &[u8],
    peer: &std::net::SocketAddr,
) -> std::io::Result<()> {
    write_with_timeout(
        ctx,
        async {
            stream.write_all(data).await?;
            stream.flush().await
        },
        peer,
    )
    .await
}

async fn write_with_timeout<F>(
    ctx: &ListenerContext,
    operation: F,
    peer: &std::net::SocketAddr,
) -> io::Result<()>
where
    F: Future<Output = io::Result<()>>,
{
    let timeout = Duration::from_millis(ctx.timeout_ms());
    match tokio::time::timeout(timeout, operation).await {
        Ok(result) => result,
        Err(_) => {
            tracing::debug!(
                "TLS '{}' write timed out after {} ms to {}",
                ctx.name(),
                ctx.timeout_ms(),
                peer
            );
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "TLS '{}' write timed out after {} ms to {}",
                    ctx.name(),
                    ctx.timeout_ms(),
                    peer
                ),
            ))
        }
    }
}

fn wrapped_banner_bytes(
    ctx: &Arc<ListenerContext>,
    handlers: &SessionHandlers,
) -> crate::Result<Option<Vec<u8>>> {
    let name = ctx.name();

    if listener_name_matches_protocol(name, "smtp") || listener_name_matches_protocol(name, "smtps")
    {
        return Ok(Some(handlers.smtp.get_welcome_banner().as_bytes().to_vec()));
    }

    if listener_name_matches_protocol(name, "ftp") || listener_name_matches_protocol(name, "ftps") {
        return Ok(Some(
            handlers.ftp.get_banner_at(crate::faketime::fake_now()),
        ));
    }

    if listener_name_matches_protocol(name, "pop3") || listener_name_matches_protocol(name, "pop3s")
    {
        return Ok(Some(handlers.pop3.get_welcome_banner().as_bytes().to_vec()));
    }

    if listener_name_matches_protocol(name, "imap") || listener_name_matches_protocol(name, "imaps")
    {
        return Ok(Some(handlers.imap.get_welcome_banner().as_bytes().to_vec()));
    }

    if listener_name_matches_protocol(name, "irc") || listener_name_matches_protocol(name, "ircs") {
        return Ok(Some(handlers.irc.get_welcome_banner().as_bytes().to_vec()));
    }

    get_protocol_banner(name, ctx.banner())
}

/// Drain `connection_buf` into framed requests and accumulate the response.
async fn process_wrapped_frames(
    fc: &WrappedFrameCtx<'_>,
    stream: &mut nettrap_tls_mitm::WrappedStream,
    handlers: &SessionHandlers,
    session: &mut TcpSessionState,
    connection_buf: &mut Vec<u8>,
) -> crate::Result<WrappedFrameOutcome> {
    let WrappedFrameCtx {
        ctx,
        name,
        peer,
        destination,
        output_path,
        webroot_server,
        control_local_addr,
    } = *fc;

    let mut response = Vec::new();
    let mut immediate_sent_bytes = 0u64;
    let mut close_after_response = false;
    loop {
        let (frame_mode, frame_result) = next_tcp_frame_with_mode(
            connection_buf,
            name,
            destination.port(),
            ctx.runtime.router.as_ref(),
            session.smtp_data_mode,
            session.ssh_first_packet,
        );
        match frame_result {
            TcpFrameResult::Complete(frame) => {
                let first_bytes = &frame[..frame.len().min(20)];
                let dispatch_name = tcp_dispatch_name_for_frame(name, frame_mode);
                if frame_mode != TcpFrameMode::Tls
                    && should_handle_ftp_ordered(ctx, name, &frame, destination)
                {
                    match prepare_ordered_ftp_action(
                        ctx,
                        output_path,
                        &handlers.ftp,
                        &mut session.ftp_passive_state,
                        &frame,
                        FtpCommandContext {
                            peer,
                            destination,
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
                                write_wrapped_with_timeout(ctx, stream, &start_response, peer)
                                    .await?;
                                ctx.write_pcap_response_for_destination(
                                    &start_response,
                                    peer,
                                    destination,
                                );
                                immediate_sent_bytes =
                                    add_sent_bytes(immediate_sent_bytes, start_response.len());
                            }
                            let frame_response =
                                finish_ftp_passive_transfer(listener, permit, transfer).await;
                            response.extend_from_slice(&frame_response);
                        }
                    }
                } else {
                    let request = TcpRequestContext {
                        ctx,
                        peer,
                        output_path,
                        destination,
                        control_local_addr,
                        http_over_tls: true,
                        ssh_banner_sent: false,
                    };
                    let frame_response = handle_tcp_protocol(
                        request,
                        dispatch_name,
                        &frame,
                        first_bytes,
                        handlers,
                        webroot_server,
                        session,
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

    Ok(WrappedFrameOutcome {
        response,
        immediate_sent_bytes,
        close_after_response,
    })
}

/// Send the accumulated response over TLS and account session byte counters.
async fn flush_wrapped_response(
    fc: &WrappedFrameCtx<'_>,
    stream: &mut nettrap_tls_mitm::WrappedStream,
    outcome: &WrappedFrameOutcome,
    len: usize,
) -> crate::Result<()> {
    let WrappedFrameCtx {
        ctx,
        peer,
        destination,
        ..
    } = *fc;
    let WrappedFrameOutcome {
        response,
        immediate_sent_bytes,
        ..
    } = outcome;
    let immediate_sent_bytes = *immediate_sent_bytes;

    let mut sent_bytes = immediate_sent_bytes;
    if !response.is_empty() {
        ctx.apply_response_delay().await;
        let send_result = write_wrapped_with_timeout(ctx, stream, response, peer).await;
        if send_result.is_ok() {
            ctx.write_pcap_response_for_destination(response, peer, destination);
            sent_bytes = add_sent_bytes(sent_bytes, response.len());
        }
        ctx.update_session_bytes(peer, "TCP", destination, len as u64, sent_bytes);
        send_result?;
    } else {
        ctx.update_session_bytes(peer, "TCP", destination, len as u64, immediate_sent_bytes);
    }

    Ok(())
}

/// Handle connection wrapped with TLS.
pub async fn handle_wrapped_connection(
    ctx: Arc<ListenerContext>,
    mut stream: nettrap_tls_mitm::WrappedStream,
    peer: std::net::SocketAddr,
    destination: SessionDestination,
    output_path: Option<&std::path::Path>,
    webroot_server: Option<&crate::webroot::WebrootServer>,
    control_local_addr: Option<SocketAddr>,
) -> crate::Result<()> {
    let name = ctx.name();
    let (handlers, mut session) = wrapped_session_setup(&ctx).await?;
    let mut connection_buf: Vec<u8> = Vec::new();

    send_wrapped_banner(&ctx, &mut stream, &handlers, &peer).await?;

    let fc = WrappedFrameCtx {
        ctx: &ctx,
        name,
        peer: &peer,
        destination: &destination,
        output_path,
        webroot_server,
        control_local_addr,
    };

    let mut buf = vec![0u8; 4096];

    loop {
        match tokio::time::timeout(
            Duration::from_millis(ctx.timeout_ms()),
            stream.read(&mut buf),
        )
        .await
        {
            Ok(Ok(0)) => {
                tracing::debug!("TLS connection closed by {}", peer);
                return Ok(());
            }
            Ok(Ok(len)) => {
                let data = &buf[..len];

                if ctx.config.log_hexdump {
                    tracing::debug!("TLS Hexdump:\n{}", crate::hexdump::hexdump(data, 256));
                }

                ctx.write_pcap_event_for_destination(data, &peer, &destination);
                connection_buf.extend_from_slice(data);

                let outcome = process_wrapped_frames(
                    &fc,
                    &mut stream,
                    &handlers,
                    &mut session,
                    &mut connection_buf,
                )
                .await?;

                flush_wrapped_response(&fc, &mut stream, &outcome, len).await?;

                if outcome.close_after_response {
                    return Ok(());
                }
            }
            Ok(Err(e)) => {
                tracing::debug!("TLS read error from {}: {}", peer, e);
                return Ok(());
            }
            Err(_) => {
                tracing::debug!(
                    "TLS '{}' read timed out after {} ms from {}",
                    ctx.name(),
                    ctx.timeout_ms(),
                    peer
                );
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
    use crate::process_filter::ProcessFilter;
    use std::sync::Arc;
    use std::time::Duration;

    fn test_listener_context(name: &str) -> Arc<ListenerContext> {
        let config = crate::listener_config::ListenerConfig {
            name: name.to_string(),
            port: 443,
            use_ssl: true,
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
        Arc::new(ListenerContext::new(config, security, runtime))
    }

    #[test]
    fn wrapped_banner_bytes_includes_irc_and_telnet_banners() {
        let ctx = test_listener_context("irc");
        let handlers = SessionHandlers::from_ctx(&ctx).expect("handlers should initialize");
        assert_eq!(
            wrapped_banner_bytes(&ctx, &handlers).expect("banner"),
            Some(handlers.irc.get_welcome_banner().as_bytes().to_vec())
        );

        let ctx = test_listener_context("imap");
        let handlers = SessionHandlers::from_ctx(&ctx).expect("handlers should initialize");
        assert_eq!(
            wrapped_banner_bytes(&ctx, &handlers).expect("banner"),
            Some(handlers.imap.get_welcome_banner().as_bytes().to_vec())
        );

        let ctx = test_listener_context("imaps");
        let handlers = SessionHandlers::from_ctx(&ctx).expect("handlers should initialize");
        assert_eq!(
            wrapped_banner_bytes(&ctx, &handlers).expect("banner"),
            Some(handlers.imap.get_welcome_banner().as_bytes().to_vec())
        );

        let ctx = test_listener_context("ircs");
        let handlers = SessionHandlers::from_ctx(&ctx).expect("handlers should initialize");
        assert_eq!(
            wrapped_banner_bytes(&ctx, &handlers).expect("banner"),
            Some(handlers.irc.get_welcome_banner().as_bytes().to_vec())
        );

        let ctx = test_listener_context("telnet");
        let handlers = SessionHandlers::from_ctx(&ctx).expect("handlers should initialize");
        let expected = get_protocol_banner(ctx.name(), ctx.banner()).expect("banner");
        assert_eq!(
            wrapped_banner_bytes(&ctx, &handlers).expect("banner"),
            expected
        );
    }

    #[tokio::test]
    async fn write_wrapped_with_timeout_returns_timed_out_under_backpressure() {
        use tokio::io::AsyncWriteExt;

        let ctx = test_listener_context("https");
        let (mut server, _client) = tokio::io::duplex(64);
        let peer = "127.0.0.1:42424".parse().expect("valid peer");
        let payload = vec![b'x'; 1024 * 1024];

        let err = write_with_timeout(
            &ctx,
            async {
                server.write_all(&payload).await?;
                server.flush().await
            },
            &peer,
        )
        .await
        .expect_err("unread wrapped peer should trigger write timeout");

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }
}
