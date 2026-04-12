//! TCP listener module.
//!
//! Contains the main TCP listener loop and connection handling.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::net::TcpListener;

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
                let local_destination = stream.local_addr().ok().map(|addr| {
                    crate::session::SessionDestination::new(addr.ip().to_string(), addr.port())
                });
                let destination = ctx.register_session(&peer, "TCP", local_destination);

                // Attribution + process filtering
                let process_allowed = if let Some(ref attr_engine) = ctx.runtime.attribution {
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
                    match tokio::task::spawn_blocking({
                        let attr_engine = Arc::clone(attr_engine);
                        move || attr_engine.attribute_flow(&five_tuple)
                    })
                    .await
                    {
                        Ok(attr)
                            if attr.confidence
                                != nettrap_core::prelude::AttributionConfidence::None =>
                        {
                            let proc_name = &attr.process.name;
                            tracing::debug!(
                                "Attribution: {} -> {} (pid={})",
                                peer,
                                proc_name,
                                attr.process.pid
                            );
                            apply_attributed_tcp_process_filter(
                                &ctx,
                                &peer,
                                &destination,
                                proc_name,
                                attr.process.pid,
                            )
                        }
                        Ok(_) => true,
                        Err(e) => {
                            tracing::warn!("Attribution timeout/error for {}: {}", peer, e);
                            true
                        }
                    }
                } else {
                    true
                };

                if !process_allowed {
                    tracing::debug!("Process blocked by filter on {}", ctx.name());
                    ctx.remove_session(&peer, "TCP", &destination);
                    conn_counter.fetch_sub(1, Ordering::AcqRel);
                    continue;
                }

                let ctx_clone = Arc::clone(&ctx);
                let out = output_path.map(|p| p.to_path_buf());
                tokio::spawn(async move {
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
    use crate::listener_runtime::{ListenerRuntime, ListenerSecurity};
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
            ),
            ListenerRuntime::new(
                None,
                Arc::new(nettrap_proxy::ProtocolRouter::new()),
                None,
                None,
                Arc::new(crate::nbi::NbiCollector::new(None)),
                Arc::clone(&tracker),
                Arc::new(PortForwardTable::new()),
                Arc::new(nettrap_flow::FlowManager::default()),
            ),
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
}
