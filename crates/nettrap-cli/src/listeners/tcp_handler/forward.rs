//! Transparent TCP forwarding to the original destination.
//!
//! A forward listener relays the connection to the destination the client
//! originally intended to reach (recovered via `SO_ORIGINAL_DST` / the session
//! tracker before redirection). This enables selective interception — forward
//! trusted processes/hosts to the real network while emulating everything else.
//!
//! Forwarding is only meaningful when traffic is intercepted (NFQUEUE /
//! REDIRECT), which is what populates the original destination. When the
//! original destination is unknown or resolves back to this listener's own
//! address (e.g. a direct connection with no redirection), forwarding is
//! refused to avoid an infinite self-relay loop.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::TcpConnection;
use crate::listeners::tcp_framing::listener_name_matches_protocol;
use crate::utils::log_event;

/// Maximum time to wait when connecting to the upstream destination.
const FORWARD_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether this listener relays to the original destination instead of
/// emulating a protocol. Recognizes the `forward` / `forwarder` names.
pub(crate) fn is_forward_listener(name: &str) -> bool {
    listener_name_matches_protocol(name, "forward")
        || listener_name_matches_protocol(name, "forwarder")
}

/// Resolve the upstream target to relay to, refusing self-loops and unknown
/// destinations.
fn resolve_forward_target(conn: &TcpConnection<'_>) -> Option<SocketAddr> {
    resolve_forward_target_inner(
        conn.destination.ip(),
        conn.destination.port(),
        conn.control_local_addr,
    )
}

/// Pure target-resolution decision: parse the original destination and reject
/// unusable cases — port 0, unspecified/unparseable IP, or a destination that
/// points back at this listener's own address (which would loop forever
/// because no redirection actually moved the destination).
fn resolve_forward_target_inner(
    ip: &str,
    port: u16,
    control_local_addr: Option<SocketAddr>,
) -> Option<SocketAddr> {
    if port == 0 {
        return None;
    }
    let ip: std::net::IpAddr = ip.parse().ok()?;
    if is_unusable_forward_target_ip(&ip) {
        return None;
    }
    let target = SocketAddr::new(normalize_forward_target_ip(ip), port);
    let control_local_addr = control_local_addr
        .map(|addr| SocketAddr::new(normalize_forward_target_ip(addr.ip()), addr.port()));
    if control_local_addr == Some(target) {
        return None;
    }
    Some(target)
}

fn normalize_forward_target_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V4(ip) => std::net::IpAddr::V4(ip),
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
    }
}

fn is_unusable_forward_target_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()
        }
        std::net::IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.to_ipv4_mapped().is_some_and(|mapped| {
                    mapped.is_unspecified()
                        || mapped.is_loopback()
                        || mapped.is_multicast()
                        || mapped.is_broadcast()
                })
        }
    }
}

/// Relay the accepted connection to its original destination, pumping bytes in
/// both directions until either side closes.
pub(crate) async fn forward_to_original_destination(
    conn: &TcpConnection<'_>,
    mut stream: tokio::net::TcpStream,
    capture: bool,
) -> crate::Result<()> {
    let ctx = &conn.ctx;
    let peer = &conn.peer;
    let output_path = conn.output_path;

    let Some(target) = resolve_forward_target(conn) else {
        tracing::debug!(
            "Forward listener '{}': no usable original destination for {}, closing",
            ctx.name(),
            peer
        );
        return Ok(());
    };

    ctx.fire_execute_cmd_for_session(peer, "TCP", &conn.destination);

    let mut upstream = match tokio::time::timeout(
        FORWARD_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(target),
    )
    .await
    {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(e)) => {
            tracing::debug!("Forward to {} failed: {}", target, e);
            return Err(forward_connect_error(target, e));
        }
        Err(_) => {
            tracing::debug!("Forward to {} timed out", target);
            return Err(forward_connect_timeout_error(target));
        }
    };

    log_event(
        output_path,
        ctx.name(),
        peer,
        "forward",
        &target.to_string(),
    )
    .await;

    let relay_result = if capture {
        captured_bidirectional_copy(ctx, peer, &conn.destination, stream, upstream).await
    } else {
        tokio::io::copy_bidirectional(&mut stream, &mut upstream).await
    };

    finalize_forward_relay(ctx, peer, &conn.destination, target, relay_result)
}

async fn captured_bidirectional_copy(
    ctx: &crate::listener_context::ListenerContext,
    peer: &SocketAddr,
    destination: &crate::session::SessionDestination,
    client: tokio::net::TcpStream,
    upstream: tokio::net::TcpStream,
) -> std::io::Result<(u64, u64)> {
    let (client_reader, client_writer) = client.into_split();
    let (upstream_reader, upstream_writer) = upstream.into_split();
    tokio::try_join!(
        copy_with_capture(ctx, peer, destination, client_reader, upstream_writer, true,),
        copy_with_capture(
            ctx,
            peer,
            destination,
            upstream_reader,
            client_writer,
            false,
        )
    )
}

async fn copy_with_capture<R, W>(
    ctx: &crate::listener_context::ListenerContext,
    peer: &SocketAddr,
    destination: &crate::session::SessionDestination,
    mut reader: R,
    mut writer: W,
    request_direction: bool,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    const RELAY_BUFFER_SIZE: usize = 16 * 1024;

    let mut buffer = [0_u8; RELAY_BUFFER_SIZE];
    let mut copied = 0_u64;
    loop {
        let length = reader.read(&mut buffer).await?;
        if length == 0 {
            writer.shutdown().await?;
            return Ok(copied);
        }
        if request_direction {
            ctx.write_pcap_event_for_destination(&buffer[..length], peer, destination);
        } else {
            ctx.write_pcap_response_for_destination(&buffer[..length], peer, destination);
        }
        writer.write_all(&buffer[..length]).await?;
        copied = copied.saturating_add(length as u64);
    }
}

fn forward_connect_error(target: SocketAddr, err: std::io::Error) -> crate::Error {
    crate::Error::Io(std::io::Error::new(
        err.kind(),
        format!("forward connect to {target} failed: {err}"),
    ))
}

fn forward_connect_timeout_error(target: SocketAddr) -> crate::Error {
    crate::Error::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("forward connect to {target} timed out"),
    ))
}

fn finalize_forward_relay(
    ctx: &crate::listener_context::ListenerContext,
    peer: &std::net::SocketAddr,
    destination: &crate::session::SessionDestination,
    target: SocketAddr,
    relay_result: std::io::Result<(u64, u64)>,
) -> crate::Result<()> {
    match relay_result {
        Ok((client_to_upstream, upstream_to_client)) => {
            ctx.update_session_bytes(
                peer,
                "TCP",
                destination,
                upstream_to_client,
                client_to_upstream,
            );
            tracing::debug!(
                "Forward {} <-> {} closed ({} up, {} down bytes)",
                peer,
                target,
                client_to_upstream,
                upstream_to_client
            );
            Ok(())
        }
        Err(e) => Err(crate::Error::from(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener_context::ListenerContext;
    use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
    use crate::process_filter::ProcessFilter;
    use crate::session::{PortForwardTable, SessionDestination, SessionTracker};
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;

    #[test]
    fn forward_listener_name_matching() {
        assert!(is_forward_listener("forward"));
        assert!(is_forward_listener("forwarder"));
        assert!(is_forward_listener("forward-proxy"));
        assert!(is_forward_listener("forwarder_1"));
        assert!(!is_forward_listener("http"));
        assert!(!is_forward_listener("forwarding-table"));
    }

    #[test]
    fn resolve_target_rejects_unusable_destinations() {
        let listen: SocketAddr = "127.0.0.1:8080".parse().expect("addr");
        assert!(resolve_forward_target_inner("1.2.3.4", 0, Some(listen)).is_none());
        assert!(resolve_forward_target_inner("0.0.0.0", 80, Some(listen)).is_none());
        assert!(resolve_forward_target_inner("not-an-ip", 80, Some(listen)).is_none());
        assert!(resolve_forward_target_inner("127.0.0.1", 8080, Some(listen)).is_none());
        let other_listen: SocketAddr = "127.0.0.1:9000".parse().expect("addr");
        assert!(resolve_forward_target_inner("127.0.0.1", 8080, Some(other_listen)).is_none());
        assert!(resolve_forward_target_inner("::1", 8080, None).is_none());
        assert!(resolve_forward_target_inner("255.255.255.255", 8080, None).is_none());
        assert!(resolve_forward_target_inner("::ffff:127.0.0.1", 8080, None).is_none());
        assert_eq!(
            resolve_forward_target_inner("1.2.3.4", 80, Some(listen)),
            Some("1.2.3.4:80".parse().expect("addr"))
        );
    }

    #[test]
    fn resolve_target_canonicalizes_ipv4_mapped_destinations() {
        let target =
            resolve_forward_target_inner("::ffff:203.0.113.10", 8080, None).expect("target");

        assert_eq!(target, "203.0.113.10:8080".parse().expect("addr"));
    }

    #[test]
    fn resolve_target_rejects_ipv4_mapped_self_loop_with_mapped_control_addr() {
        let control_local_addr: SocketAddr = "[::ffff:192.0.2.10]:8080".parse().expect("addr");

        assert!(
            resolve_forward_target_inner("::ffff:192.0.2.10", 8080, Some(control_local_addr))
                .is_none()
        );
    }

    fn forward_context() -> ListenerContext {
        ListenerContext::builder()
            .name("forward")
            .port(0)
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

    #[tokio::test]
    async fn refuses_self_loop_without_relay() {
        // Destination equal to the accept socket's local address must not relay
        // (it would loop). The connection is simply closed.
        let relay = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind relay");
        let relay_addr = relay.local_addr().expect("relay addr");

        let ctx = Arc::new(forward_context());
        let server = tokio::spawn(async move {
            let (stream, peer) = relay.accept().await.expect("accept");
            let control_local_addr = stream.local_addr().ok();
            let conn = TcpConnection {
                ctx,
                peer,
                // Original destination resolves back to our own local address.
                destination: SessionDestination::new_unchecked(
                    relay_addr.ip().to_string(),
                    relay_addr.port(),
                ),
                output_path: None,
                control_local_addr,
            };
            forward_to_original_destination(&conn, stream, false)
                .await
                .expect("forward ok");
        });

        let mut client = tokio::net::TcpStream::connect(relay_addr)
            .await
            .expect("client connect");
        // The forwarder closes immediately; reading yields EOF (0 bytes).
        let mut buf = [0u8; 1];
        let n = client.read(&mut buf).await.expect("read");
        assert_eq!(n, 0, "self-loop forward should close without relaying");
        server.await.expect("relay task");
    }

    #[tokio::test]
    async fn captured_relay_preserves_both_directions() {
        let client_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind client side");
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream side");
        let mut client = tokio::net::TcpStream::connect(
            client_listener.local_addr().expect("client listener addr"),
        )
        .await
        .expect("connect client");
        let (relay_client, peer) = client_listener.accept().await.expect("accept client");
        let relay_upstream =
            tokio::net::TcpStream::connect(upstream_listener.local_addr().expect("upstream addr"))
                .await
                .expect("connect upstream");
        let (mut upstream, _) = upstream_listener.accept().await.expect("accept upstream");
        let ctx = forward_context();
        let destination = SessionDestination::new_unchecked("192.0.2.1".to_string(), 443);

        let relay =
            captured_bidirectional_copy(&ctx, &peer, &destination, relay_client, relay_upstream);
        let exchange = async {
            use tokio::io::AsyncWriteExt;

            client.write_all(b"request").await.expect("write request");
            client.shutdown().await.expect("close request side");
            let mut request = Vec::new();
            upstream
                .read_to_end(&mut request)
                .await
                .expect("read request");
            assert_eq!(request, b"request");
            upstream
                .write_all(b"response")
                .await
                .expect("write response");
            upstream.shutdown().await.expect("close response side");
            let mut response = Vec::new();
            client
                .read_to_end(&mut response)
                .await
                .expect("read response");
            assert_eq!(response, b"response");
        };

        let (relay_result, ()) = tokio::join!(relay, exchange);
        assert_eq!(relay_result.expect("captured relay"), (7, 8));
    }

    #[test]
    fn finalize_forward_relay_propagates_io_errors() {
        let ctx = forward_context();
        let peer: SocketAddr = "127.0.0.1:53000".parse().expect("peer addr");
        let destination = SessionDestination::new_unchecked("1.2.3.4".to_string(), 80);
        let target: SocketAddr = "1.2.3.4:80".parse().expect("target addr");

        let err = finalize_forward_relay(
            &ctx,
            &peer,
            &destination,
            target,
            Err(std::io::Error::other("relay failed")),
        )
        .expect_err("relay errors should propagate");

        assert!(err.to_string().contains("relay failed"));
    }

    #[test]
    fn forward_connect_error_preserves_source_error() {
        let target: SocketAddr = "192.0.2.10:443".parse().expect("target addr");
        let source = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");

        let err = forward_connect_error(target, source);

        assert!(matches!(err, crate::Error::Io(_)));
        assert!(
            err.to_string()
                .contains("forward connect to 192.0.2.10:443 failed")
        );
        assert!(err.to_string().contains("refused"));
    }

    #[test]
    fn forward_connect_timeout_is_reported_as_timeout() {
        let target: SocketAddr = "192.0.2.10:443".parse().expect("target addr");

        let err = forward_connect_timeout_error(target);

        assert!(matches!(err, crate::Error::Io(_)));
        assert_eq!(
            err.to_string(),
            "IO error: forward connect to 192.0.2.10:443 timed out"
        );
    }
}
