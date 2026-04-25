//! TCP listener module.
//!
//! Contains the main TCP listener loop and connection handling.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::net::{TcpListener, TcpStream};

use crate::listener_context::ListenerContext;
use crate::listeners::tcp_handler::handle_tcp_connection;
use crate::session::SessionDestination;

/// Run a TCP listener for HTTP, HTTPS, SMTP, FTP, POP3, IRC, and raw protocols.
pub async fn run_tcp_listener(
    ctx: Arc<ListenerContext>,
    listener: TcpListener,
    output_path: Option<&std::path::Path>,
) -> crate::Result<()> {
    let addr = listener.local_addr()?;
    let active_connections = Arc::new(AtomicU32::new(0));

    tracing::info!("TCP listener '{}' listening on {}", ctx.name(), addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // Atomically increment and check limit using compare_exchange
                // This prevents TOCTOU race conditions between check and increment
                let conn_counter = Arc::clone(&active_connections);
                let max_connections = ctx.max_connections();

                // Try to atomically acquire a connection slot
                let accepted = acquire_connection_slot(&conn_counter, max_connections);

                if !accepted {
                    tracing::warn!(
                        "TCP '{}' max connections ({}) reached, rejecting {}",
                        ctx.name(),
                        max_connections.unwrap_or(u32::MAX),
                        peer
                    );
                    // stream is dropped here when rejected
                    continue;
                }

                if !ctx.is_host_allowed(&peer.ip().to_string()) {
                    tracing::debug!("Host {} blocked by filter on {}", peer.ip(), ctx.name());
                    conn_counter.fetch_sub(1, Ordering::AcqRel);
                    continue;
                }

                tracing::debug!("TCP '{}' accepted connection from {}", ctx.name(), peer);

                // Register the session before attribution so any resolved
                // process metadata can be attached to the live session state.
                let local_destination = original_tcp_destination(&stream).or_else(|| {
                    stream.local_addr().ok().map(|addr| {
                        crate::session::SessionDestination::new(addr.ip().to_string(), addr.port())
                    })
                });
                let destination = ctx.register_session(&peer, "TCP", local_destination);

                let ctx_clone = Arc::clone(&ctx);
                let out = output_path.map(|p| p.to_path_buf());
                tokio::spawn(async move {
                    if !apply_tcp_process_filter(&ctx_clone, &peer, &destination).await {
                        tracing::debug!("Process blocked by filter on {}", ctx_clone.name());
                        ctx_clone.remove_session(&peer, "TCP", &destination);
                        conn_counter.fetch_sub(1, Ordering::AcqRel);
                        return;
                    }

                    let result = handle_tcp_connection(
                        Arc::clone(&ctx_clone),
                        stream,
                        peer,
                        destination.clone(),
                        out.as_deref(),
                    )
                    .await;
                    ctx_clone.remove_session(&peer, "TCP", &destination);
                    if let Err(e) = result {
                        tracing::debug!("TCP connection error from {}: {}", peer, e);
                    }
                    conn_counter.fetch_sub(1, Ordering::AcqRel);
                });
            }
            Err(e) => {
                tracing::warn!("TCP accept error: {}", e);
            }
        }
    }
}

async fn apply_tcp_process_filter(
    ctx: &ListenerContext,
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
) -> bool {
    let Some(attr_engine) = ctx.runtime.attribution.as_ref() else {
        return true;
    };

    let dst_ip = destination
        .ip
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let five_tuple = nettrap_core::prelude::FiveTuple::new(
        peer.ip(),
        dst_ip,
        peer.port(),
        destination.port,
        nettrap_core::prelude::Protocol::Tcp,
    );

    match tokio::time::timeout(
        ctx.runtime.attribution_timeout,
        tokio::task::spawn_blocking({
            let attr_engine = Arc::clone(attr_engine);
            move || attr_engine.attribute_flow(&five_tuple)
        }),
    )
    .await
    {
        Ok(Ok(attr)) if attr.confidence != nettrap_core::prelude::AttributionConfidence::None => {
            let proc_name = &attr.process.name;
            tracing::debug!(
                "Attribution: {} -> {} (pid={})",
                peer,
                proc_name,
                attr.process.pid
            );
            apply_attributed_tcp_process_filter(ctx, peer, destination, proc_name, attr.process.pid)
        }
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            tracing::warn!("Attribution timeout/error for {}: {}", peer, e);
            true
        }
        Err(_) => {
            tracing::warn!(
                "Attribution timed out after {} ms for {}",
                ctx.runtime.attribution_timeout.as_millis(),
                peer
            );
            true
        }
    }
}

#[cfg(target_os = "linux")]
fn original_tcp_destination(stream: &TcpStream) -> Option<SessionDestination> {
    match stream.local_addr().ok()? {
        std::net::SocketAddr::V4(_) => linux_original_ipv4_destination(stream),
        std::net::SocketAddr::V6(_) => linux_original_ipv6_destination(stream),
    }
}

#[cfg(not(target_os = "linux"))]
fn original_tcp_destination(_stream: &TcpStream) -> Option<SessionDestination> {
    None
}

#[cfg(target_os = "linux")]
fn linux_original_ipv4_destination(stream: &TcpStream) -> Option<SessionDestination> {
    use std::mem::{size_of, zeroed};
    use std::os::fd::AsRawFd;

    const SO_ORIGINAL_DST: libc::c_int = 80;

    let mut addr: libc::sockaddr_in = unsafe { zeroed() };
    let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            (&mut addr as *mut libc::sockaddr_in).cast::<libc::c_void>(),
            &mut len,
        )
    };

    if result == 0 && len as usize >= size_of::<libc::sockaddr_in>() {
        Some(session_destination_from_sockaddr_in(addr))
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn linux_original_ipv6_destination(stream: &TcpStream) -> Option<SessionDestination> {
    use std::mem::{size_of, zeroed};
    use std::os::fd::AsRawFd;

    const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

    let mut addr: libc::sockaddr_in6 = unsafe { zeroed() };
    let mut len = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_IPV6,
            IP6T_SO_ORIGINAL_DST,
            (&mut addr as *mut libc::sockaddr_in6).cast::<libc::c_void>(),
            &mut len,
        )
    };

    if result == 0 && len as usize >= size_of::<libc::sockaddr_in6>() {
        Some(session_destination_from_sockaddr_in6(addr))
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn session_destination_from_sockaddr_in(addr: libc::sockaddr_in) -> SessionDestination {
    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    SessionDestination::new(ip.to_string(), port)
}

#[cfg(target_os = "linux")]
fn session_destination_from_sockaddr_in6(addr: libc::sockaddr_in6) -> SessionDestination {
    let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
    let port = u16::from_be(addr.sin6_port);
    SessionDestination::new(ip.to_string(), port)
}

fn apply_attributed_tcp_process_filter(
    ctx: &ListenerContext,
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
    process_name: &str,
    process_pid: u32,
) -> bool {
    ctx.runtime.session_tracker.set_process(
        peer,
        "TCP",
        destination,
        Some(process_name.to_string()),
        Some(process_pid),
    );
    ctx.is_process_allowed(process_name)
}

/// Atomically acquire a connection slot, respecting the maximum limit.
/// Returns true if the slot was acquired, false if the limit was reached.
fn acquire_connection_slot(counter: &Arc<AtomicU32>, max: Option<u32>) -> bool {
    for _ in 0..64 {
        let current = counter.load(Ordering::Acquire);

        if let Some(limit) = max {
            if current >= limit {
                return false;
            }
        }

        // Try to increment atomically
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(_) => std::hint::spin_loop(),
        }
    }
    // After 64 retries under extreme contention, reject the connection
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener_context::ListenerContext;
    use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
    use crate::process_filter::ProcessFilter;
    use crate::session::{PortForwardTable, SessionTracker};

    #[test]
    fn blocked_tcp_process_keeps_session_visible_until_ttl() {
        let tracker = Arc::new(SessionTracker::new());
        let ctx = ListenerContext::builder().name("http").port(80).build(
            ListenerSecurity::new(
                ProcessFilter::build(
                    Vec::new(),
                    Vec::new(),
                    vec!["allowed.exe".into()],
                    Vec::new(),
                ),
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
                nbi_collector: Arc::new(crate::nbi::NbiCollector::new(None)),
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::new(PortForwardTable::new()),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        );
        let peer: std::net::SocketAddr = "127.0.0.1:54000".parse().unwrap();
        let destination = SessionDestination::new("127.0.0.1", 80);
        tracker.register(&peer, &destination, "http", "TCP");

        assert!(!apply_attributed_tcp_process_filter(
            &ctx,
            &peer,
            &destination,
            "blocked.exe",
            4244,
        ));
        assert_eq!(tracker.active_count(), 1);
        assert_eq!(
            tracker.get_process(&peer, "TCP", &destination),
            Some((Some("blocked.exe".to_string()), Some(4244)))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_sockaddr_in_original_destination_preserves_ip_and_port() {
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 8443u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_be_bytes([203, 0, 113, 10]).to_be(),
            },
            sin_zero: [0; 8],
        };

        assert_eq!(
            session_destination_from_sockaddr_in(addr),
            SessionDestination::new("203.0.113.10", 8443)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_sockaddr_in6_original_destination_preserves_ip_and_port() {
        let addr = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: 9443u16.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            },
            sin6_scope_id: 0,
        };

        assert_eq!(
            session_destination_from_sockaddr_in6(addr),
            SessionDestination::new("2001:db8::1", 9443)
        );
    }
}
