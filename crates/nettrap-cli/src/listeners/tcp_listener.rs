//! TCP listener module.
//!
//! Contains the main TCP listener loop and connection handling.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

use crate::listener_context::ListenerContext;
use crate::listeners::attribution_semaphore;
use crate::listeners::tcp_handler::handle_tcp_connection;
#[cfg(target_os = "linux")]
use crate::session::is_usable_session_destination_ip;
use crate::session::{SessionDestination, normalize_session_ip};
use crate::utils::canonical_socket_ip_string;

/// Run a TCP listener for HTTP, HTTPS, SMTP, FTP, POP3, IRC, and raw protocols.
pub async fn run_tcp_listener(
    ctx: Arc<ListenerContext>,
    listener: TcpListener,
    output_path: Option<&std::path::Path>,
) -> crate::Result<()> {
    let addr = listener.local_addr()?;
    let active_connections = Arc::new(AtomicU32::new(0));

    tracing::info!("TCP listener '{}' listening on {}", ctx.name(), addr);

    let mut connection_tasks = JoinSet::new();
    loop {
        while let Some(result) = connection_tasks.try_join_next() {
            if let Err(err) = result
                && !err.is_cancelled()
            {
                tracing::warn!("TCP connection task failed: {}", err);
            }
        }

        match listener.accept().await {
            Ok((stream, peer)) => {
                // Atomically increment and check limit using compare_exchange
                // This prevents TOCTOU race conditions between check and increment
                let conn_counter = Arc::clone(&active_connections);
                let max_connections = ctx.max_connections();

                // Try to atomically acquire a connection slot. The returned
                // guard releases the slot on drop — including if the connection
                // task panics during unwinding — so a handler panic can never
                // permanently leak a slot and exhaust the pool (self-DoS).
                let Some(slot) = acquire_connection_slot(&conn_counter, max_connections) else {
                    tracing::warn!(
                        "TCP '{}' max connections ({}) reached, rejecting {}",
                        ctx.name(),
                        max_connections.unwrap_or(u32::MAX),
                        peer
                    );
                    continue;
                };

                if !ctx.is_host_allowed(&canonical_socket_ip_string(&peer)) {
                    tracing::debug!("Host {} blocked by filter on {}", peer.ip(), ctx.name());
                    continue;
                }

                tracing::debug!("TCP '{}' accepted connection from {}", ctx.name(), peer);

                // Register the session before attribution so any resolved
                // process metadata can be attached to the live session state.
                let local_destination = original_tcp_destination(&stream)
                    .map_err(|err| {
                        tracing::debug!(
                            "TCP '{}' original destination lookup failed for {}: {}",
                            ctx.name(),
                            peer,
                            err
                        );
                        err
                    })
                    .ok()
                    .flatten()
                    .or_else(|| {
                        stream
                            .local_addr()
                            .map_err(|err| {
                                tracing::debug!(
                                    "TCP '{}' fallback local destination lookup failed for {}: {}",
                                    ctx.name(),
                                    peer,
                                    err
                                );
                                err
                            })
                            .ok()
                            .map(|addr| {
                                crate::session::SessionDestination::new_unchecked(
                                    normalize_session_ip(addr.ip()).to_string(),
                                    addr.port(),
                                )
                            })
                    });
                let destination = ctx.register_session(&peer, "TCP", local_destination);

                let ctx_clone = Arc::clone(&ctx);
                let out = output_path.map(|p| p.to_path_buf());
                connection_tasks.spawn(async move {
                    let _slot = slot;
                    if !apply_tcp_process_filter(&ctx_clone, &peer, &destination).await {
                        tracing::debug!("Process blocked by filter on {}", ctx_clone.name());
                        ctx_clone.remove_session(&peer, "TCP", &destination);
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

    let Some(five_tuple) = ctx.session_flow_five_tuple(peer, "TCP", destination) else {
        return true;
    };

    let permit = match tokio::time::timeout(
        ctx.runtime.attribution_timeout,
        attribution_semaphore().acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        Ok(Err(err)) => {
            tracing::warn!("Attribution semaphore unavailable for {}: {}", peer, err);
            return true;
        }
        Err(_) => {
            tracing::warn!(
                "Attribution queue timed out after {} ms for {}",
                ctx.runtime.attribution_timeout.as_millis(),
                peer
            );
            return true;
        }
    };

    match tokio::time::timeout(
        ctx.runtime.attribution_timeout,
        tokio::task::spawn_blocking({
            let attr_engine = Arc::clone(attr_engine);
            move || {
                let _permit = permit;
                attr_engine.attribute_flow(&five_tuple)
            }
        }),
    )
    .await
    {
        Ok(Ok(attr)) if attr.confidence != nettrap_core::prelude::AttributionConfidence::None => {
            let proc_name = attr.process.name();
            tracing::debug!(
                "Attribution: {} -> {} (pid={})",
                peer,
                proc_name,
                attr.process.pid()
            );
            apply_attributed_tcp_process_filter(
                ctx,
                peer,
                destination,
                proc_name,
                attr.process.pid(),
            )
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
fn original_tcp_destination(stream: &TcpStream) -> io::Result<Option<SessionDestination>> {
    match stream.local_addr()? {
        std::net::SocketAddr::V4(_) => linux_original_ipv4_destination(stream),
        std::net::SocketAddr::V6(_) => linux_original_ipv6_destination(stream),
    }
}

#[cfg(not(target_os = "linux"))]
fn original_tcp_destination(_stream: &TcpStream) -> io::Result<Option<SessionDestination>> {
    Ok(None)
}

#[cfg(target_os = "linux")]
fn linux_original_ipv4_destination(stream: &TcpStream) -> io::Result<Option<SessionDestination>> {
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

    if !getsockopt_result_has_complete_value(result, len, size_of::<libc::sockaddr_in>())? {
        return Ok(None);
    }

    Ok(session_destination_from_sockaddr_in(addr))
}

#[cfg(target_os = "linux")]
fn linux_original_ipv6_destination(stream: &TcpStream) -> io::Result<Option<SessionDestination>> {
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

    if !getsockopt_result_has_complete_value(result, len, size_of::<libc::sockaddr_in6>())? {
        return Ok(None);
    }

    Ok(session_destination_from_sockaddr_in6(addr))
}

#[cfg(target_os = "linux")]
fn getsockopt_result_has_complete_value(
    result: libc::c_int,
    len: libc::socklen_t,
    expected_len: usize,
) -> io::Result<bool> {
    if result != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(len as usize >= expected_len)
}

#[cfg(all(test, target_os = "linux"))]
fn getsockopt_result_has_complete_value_with_error(
    result: libc::c_int,
    len: libc::socklen_t,
    expected_len: usize,
    last_error: io::Error,
) -> io::Result<bool> {
    if result != 0 {
        return Err(last_error);
    }

    Ok(len as usize >= expected_len)
}

#[cfg(target_os = "linux")]
fn session_destination_from_sockaddr_in(addr: libc::sockaddr_in) -> Option<SessionDestination> {
    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    if port == 0 || !is_usable_session_destination_ip(std::net::IpAddr::V4(ip)) {
        return None;
    }

    Some(SessionDestination::new_unchecked(ip.to_string(), port))
}

#[cfg(target_os = "linux")]
fn session_destination_from_sockaddr_in6(addr: libc::sockaddr_in6) -> Option<SessionDestination> {
    let ip = normalize_session_ip(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
        addr.sin6_addr.s6_addr,
    )));
    let port = u16::from_be(addr.sin6_port);
    if port == 0 || !is_usable_session_destination_ip(ip) {
        return None;
    }

    Some(SessionDestination::new_unchecked(ip.to_string(), port))
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

/// RAII guard for an acquired connection slot. Decrements the active-connection
/// counter on drop, so the slot is released on every exit path of the connection
/// task — including a panic during unwinding — preventing slot leaks that would
/// otherwise exhaust the pool and stop the listener accepting (self-DoS).
struct ConnectionSlot {
    counter: Arc<AtomicU32>,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Atomically acquire a connection slot, respecting the maximum limit.
/// Returns a guard that releases the slot on drop, or `None` if the limit was
/// reached (or extreme contention prevented acquisition).
fn acquire_connection_slot(counter: &Arc<AtomicU32>, max: Option<u32>) -> Option<ConnectionSlot> {
    for _ in 0..64 {
        let current = counter.load(Ordering::Acquire);

        if let Some(limit) = max
            && current >= limit
        {
            return None;
        }

        let next = current.checked_add(1)?;

        // Try to increment atomically
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                return Some(ConnectionSlot {
                    counter: Arc::clone(counter),
                });
            }
            Err(_) => std::hint::spin_loop(),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener_context::ListenerContext;
    use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
    use crate::process_filter::ProcessFilter;
    use crate::session::{PortForwardTable, SessionTracker};

    #[test]
    fn connection_slot_guard_enforces_limit_and_releases_on_drop() {
        let counter = Arc::new(AtomicU32::new(0));
        {
            let _a = acquire_connection_slot(&counter, Some(2)).expect("first slot");
            let _b = acquire_connection_slot(&counter, Some(2)).expect("second slot");
            assert_eq!(counter.load(Ordering::Acquire), 2);
            // At the limit, acquisition is rejected.
            assert!(acquire_connection_slot(&counter, Some(2)).is_none());
            assert_eq!(counter.load(Ordering::Acquire), 2);
        }
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }

    #[test]
    fn connection_slot_released_when_task_scope_panics() {
        // A panic in the connection task must still release the slot (Drop runs
        // during unwinding), so a handler panic cannot leak a slot.
        let counter = Arc::new(AtomicU32::new(0));
        let counter_in = Arc::clone(&counter);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _slot = acquire_connection_slot(&counter_in, None).expect("slot");
            assert_eq!(counter_in.load(Ordering::Acquire), 1);
            panic!("simulated handler panic");
        }));
        assert!(result.is_err());
        assert_eq!(
            counter.load(Ordering::Acquire),
            0,
            "slot must be released after a panic unwinds the task"
        );
    }

    #[test]
    fn connection_slot_rejects_saturated_counter_without_overflowing() {
        let counter = Arc::new(AtomicU32::new(u32::MAX));

        assert!(acquire_connection_slot(&counter, None).is_none());
        assert_eq!(counter.load(Ordering::Acquire), u32::MAX);
    }

    #[test]
    fn blocked_tcp_process_keeps_session_visible_until_ttl() {
        let tracker = Arc::new(SessionTracker::new());
        let ctx = ListenerContext::builder()
            .name("http")
            .port(80)
            .build(
                ListenerSecurity::new(
                    ProcessFilter::build(
                        Vec::new(),
                        Vec::new(),
                        vec!["allowed.exe".into()],
                        Vec::new(),
                    )
                    .expect("host rules should compile"),
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
                    nbi_collector: Arc::new(
                        crate::nbi::NbiCollector::new(None).expect("collector should build"),
                    ),
                    session_tracker: Arc::clone(&tracker),
                    port_forward_table: Arc::new(PortForwardTable::new()),
                    flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
                }),
            )
            .expect("listener context should build");
        let peer: std::net::SocketAddr = "127.0.0.1:54000".parse().unwrap();
        let destination = SessionDestination::new_unchecked("127.0.0.1", 80);
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
            Some(SessionDestination::new_unchecked("203.0.113.10", 8443))
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
            Some(SessionDestination::new_unchecked("2001:db8::1", 9443))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_sockaddr_in6_original_destination_canonicalizes_ipv4_mapped_address() {
        let addr = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: 9443u16.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 198, 51, 100, 7],
            },
            sin6_scope_id: 0,
        };

        assert_eq!(
            session_destination_from_sockaddr_in6(addr),
            Some(SessionDestination::new_unchecked("198.51.100.7", 9443))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_sockaddr_in_original_destination_rejects_unspecified_ip() {
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 8443u16.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_be_bytes([0, 0, 0, 0]).to_be(),
            },
            sin_zero: [0; 8],
        };

        assert_eq!(session_destination_from_sockaddr_in(addr), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_original_destination_rejects_short_getsockopt_value() {
        let has_value = getsockopt_result_has_complete_value(
            0,
            (std::mem::size_of::<libc::sockaddr_in>() - 1) as libc::socklen_t,
            std::mem::size_of::<libc::sockaddr_in>(),
        )
        .expect("successful getsockopt with short length is not an OS error");

        assert!(!has_value);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_original_destination_surfaces_getsockopt_errors() {
        let err = getsockopt_result_has_complete_value_with_error(
            -1,
            0,
            std::mem::size_of::<libc::sockaddr_in>(),
            io::Error::from_raw_os_error(libc::EBADF),
        )
        .expect_err("failed getsockopt must be surfaced");

        assert_eq!(err.raw_os_error(), Some(libc::EBADF));
    }
}
