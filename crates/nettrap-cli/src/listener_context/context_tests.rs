use super::*;
use crate::listener_runtime::{ListenerRuntime, ListenerRuntimeResources, ListenerSecurity};
use crate::process_filter::ProcessFilter;
use crate::session::{PortForwardTable, SessionTracker};
use nettrap_pcap::{PcapReader, PcapWriter};
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn register_session_uses_original_redirect_destination_when_available() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let ctx = ListenerContext::builder()
        .name("raw")
        .port(9000)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53000".parse().unwrap();
    let original_dst: std::net::SocketAddr = "10.0.0.7:4444".parse().unwrap();

    port_forward_table.record_original_dest(&src, "UDP", 9000, &original_dst);

    let destination = ctx.register_session(
        &src,
        "UDP",
        Some(SessionDestination::new_unchecked("192.168.1.50", 9000)),
    );

    assert_eq!(
        destination,
        SessionDestination::new_unchecked("10.0.0.7", 4444)
    );
    assert_eq!(
        tracker.get_original_dest(&src, "UDP", &destination),
        Some((original_dst.ip().to_string(), 4444))
    );
}

#[test]
fn register_session_uses_fallback_destination_when_not_redirected() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let ctx = ListenerContext::builder()
        .name("raw")
        .port(9000)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53000".parse().unwrap();
    let fallback = SessionDestination::new_unchecked("192.168.1.50", 9000);

    let destination = ctx.register_session(&src, "UDP", Some(fallback.clone()));

    assert_eq!(destination, fallback);
    assert_eq!(
        tracker.get_original_dest(&src, "UDP", &destination),
        Some(("192.168.1.50".to_string(), 9000))
    );
}

#[test]
fn register_session_state_marks_only_first_udp_packet_as_new() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let ctx = ListenerContext::builder()
        .name("dns")
        .port(53)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53000".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.7", 53);

    let (first_destination, first_is_new) =
        ctx.register_session_state(&src, "UDP", Some(destination.clone()));
    let (second_destination, second_is_new) =
        ctx.register_session_state(&src, "UDP", Some(destination.clone()));

    assert_eq!(first_destination, destination);
    assert_eq!(second_destination, destination);
    assert!(first_is_new);
    assert!(!second_is_new);
}

#[test]
fn register_session_state_uses_peer_family_when_no_destination_exists() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let ctx = ListenerContext::builder()
        .name("dns")
        .port(53)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "[2001:db8::10]:53000".parse().unwrap();

    let destination = ctx.register_session(&src, "UDP", None);

    assert_eq!(destination, SessionDestination::new_unchecked("::", 53));
}

#[test]
fn resolve_session_destination_for_port_uses_tracked_destination() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53000".parse().unwrap();
    let tracked = SessionDestination::new_unchecked("10.0.0.7", 8080);

    ctx.register_session_state(&src, "TCP", Some(tracked.clone()));

    assert_eq!(
        ctx.resolve_session_destination_for_port(&src, "TCP", 8080),
        tracked
    );
}

#[test]
fn session_process_for_destination_reads_existing_attribution() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
        .execute_cmd(Some("echo {procname}:{pid}".to_string()))
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53000".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.7", 8080);

    ctx.register_session_state(&src, "TCP", Some(destination.clone()));
    tracker.set_process(
        &src,
        "TCP",
        &destination,
        Some("curl".to_string()),
        Some(4242),
    );

    assert_eq!(
        ctx.session_process_for_destination(&src, "TCP", &destination),
        (Some("curl".to_string()), Some(4242))
    );
}

#[test]
fn session_lifecycle_updates_flow_manager() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let flow_manager = Arc::new(nettrap_flow::FlowManager::default());
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::clone(&flow_manager),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53000".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.7", 8080);

    ctx.register_session_state(&src, "TCP", Some(destination.clone()));

    let key =
        nettrap_core::prelude::FlowKey::from_five_tuple(&nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            "10.0.0.7".parse().unwrap(),
            src.port(),
            destination.port(),
            nettrap_core::prelude::Protocol::Tcp,
        ));
    let flow = flow_manager.get(&key).expect("flow should be tracked");
    assert_eq!(flow.state, nettrap_core::prelude::FlowState::New);
    assert_eq!(flow.direction, nettrap_flow::FlowDirection::Inbound);

    ctx.update_session_bytes(&src, "TCP", &destination, 64, 32);
    let updated_flow = flow_manager.get(&key).expect("flow should still exist");
    assert_eq!(
        updated_flow.state,
        nettrap_core::prelude::FlowState::Established
    );
    assert_eq!(updated_flow.metadata.bytes_received, 64);
    assert_eq!(updated_flow.metadata.bytes_sent, 32);

    ctx.remove_session(&src, "TCP", &destination);
    assert!(flow_manager.get(&key).is_none());
}

#[test]
fn session_lifecycle_retries_when_refresh_initially_expires() {
    static NOW_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn scripted_now() -> chrono::DateTime<chrono::Utc> {
        match NOW_CALLS.fetch_add(1, Ordering::SeqCst) {
            0 => chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid instant"),
            1 => chrono::DateTime::from_timestamp(1_700_000_011, 0).expect("valid instant"),
            2 => chrono::DateTime::from_timestamp(1_700_000_011, 0).expect("valid instant"),
            3 => chrono::DateTime::from_timestamp(1_700_000_012, 0).expect("valid instant"),
            4 => chrono::DateTime::from_timestamp(1_700_000_013, 0).expect("valid instant"),
            _ => chrono::DateTime::from_timestamp(1_700_000_014, 0).expect("valid instant"),
        }
    }

    NOW_CALLS.store(0, Ordering::SeqCst);

    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let flow_manager = Arc::new(
        nettrap_flow::FlowManager::new(nettrap_flow::FlowManagerConfig {
            cleanup_interval: std::time::Duration::from_secs(3600),
            flow_timeout: std::time::Duration::from_secs(10),
            ..Default::default()
        })
        .with_now(scripted_now),
    );
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::clone(&flow_manager),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53001".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.8", 8080);

    ctx.register_session_state(&src, "TCP", Some(destination.clone()));
    ctx.update_session_bytes(&src, "TCP", &destination, 8, 4);

    let key =
        nettrap_core::prelude::FlowKey::from_five_tuple(&nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            "10.0.0.8".parse().unwrap(),
            src.port(),
            destination.port(),
            nettrap_core::prelude::Protocol::Tcp,
        ));
    let flow = flow_manager.get(&key).expect("flow should still exist");
    assert_eq!(flow.direction, nettrap_flow::FlowDirection::Inbound);
    assert_eq!(flow.state, nettrap_core::prelude::FlowState::Established);
    assert_eq!(flow.metadata.bytes_received, 8);
    assert_eq!(flow.metadata.bytes_sent, 4);
    assert_eq!(flow_manager.active_count(), 1);
}

#[test]
fn session_registration_retries_when_refresh_initially_expires() {
    static NOW_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn scripted_now() -> chrono::DateTime<chrono::Utc> {
        match NOW_CALLS.fetch_add(1, Ordering::SeqCst) {
            0 => chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid instant"),
            1 => chrono::DateTime::from_timestamp(1_700_000_011, 0).expect("valid instant"),
            2 => chrono::DateTime::from_timestamp(1_700_000_012, 0).expect("valid instant"),
            _ => chrono::DateTime::from_timestamp(1_700_000_013, 0).expect("valid instant"),
        }
    }

    NOW_CALLS.store(0, Ordering::SeqCst);

    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let flow_manager = Arc::new(
        nettrap_flow::FlowManager::new(nettrap_flow::FlowManagerConfig {
            cleanup_interval: std::time::Duration::from_secs(3600),
            flow_timeout: std::time::Duration::from_secs(5),
            ..Default::default()
        })
        .with_now(scripted_now),
    );
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::clone(&flow_manager),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53003".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.10", 8080);

    let (returned_destination, is_new) =
        ctx.register_session_state(&src, "TCP", Some(destination.clone()));
    assert_eq!(returned_destination, destination);
    assert!(is_new);

    let key =
        nettrap_core::prelude::FlowKey::from_five_tuple(&nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            "10.0.0.10".parse().unwrap(),
            src.port(),
            destination.port(),
            nettrap_core::prelude::Protocol::Tcp,
        ));
    let flow = flow_manager.get(&key).expect("flow should still exist");
    assert_eq!(flow.direction, nettrap_flow::FlowDirection::Inbound);
    assert_eq!(flow.state, nettrap_core::prelude::FlowState::New);
    assert_eq!(flow_manager.active_count(), 1);
}

#[test]
fn session_byte_updates_retry_when_flow_expires_between_writes() {
    static NOW_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn scripted_now() -> chrono::DateTime<chrono::Utc> {
        match NOW_CALLS.fetch_add(1, Ordering::SeqCst) {
            0..=5 => chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid instant"),
            6..=10 => chrono::DateTime::from_timestamp(1_700_000_011, 0).expect("valid instant"),
            _ => chrono::DateTime::from_timestamp(1_700_000_012, 0).expect("valid instant"),
        }
    }

    NOW_CALLS.store(0, Ordering::SeqCst);

    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let flow_manager = Arc::new(
        nettrap_flow::FlowManager::new(nettrap_flow::FlowManagerConfig {
            cleanup_interval: std::time::Duration::from_secs(3600),
            flow_timeout: std::time::Duration::from_secs(5),
            ..Default::default()
        })
        .with_now(scripted_now),
    );
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::clone(&flow_manager),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53002".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.9", 8080);

    ctx.register_session_state(&src, "TCP", Some(destination.clone()));
    ctx.update_session_bytes(&src, "TCP", &destination, 8, 4);

    let key =
        nettrap_core::prelude::FlowKey::from_five_tuple(&nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            "10.0.0.9".parse().unwrap(),
            src.port(),
            destination.port(),
            nettrap_core::prelude::Protocol::Tcp,
        ));
    let flow = flow_manager.get(&key).expect("flow should still exist");
    assert_eq!(flow.metadata.bytes_received, 8);
    assert_eq!(flow.metadata.bytes_sent, 4);
    assert_eq!(flow.state, nettrap_core::prelude::FlowState::Established);
    assert_eq!(flow_manager.active_count(), 1);
}

#[test]
fn session_lifecycle_marks_loopback_sessions_internal() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let flow_manager = Arc::new(nettrap_flow::FlowManager::default());
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::clone(&flow_manager),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53002".parse().unwrap();
    let destination = SessionDestination::new_unchecked("127.0.0.1", 8080);

    ctx.register_session_state(&src, "TCP", Some(destination.clone()));

    let key =
        nettrap_core::prelude::FlowKey::from_five_tuple(&nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            "127.0.0.1".parse().unwrap(),
            src.port(),
            destination.port(),
            nettrap_core::prelude::Protocol::Tcp,
        ));
    let flow = flow_manager.get(&key).expect("flow should be tracked");

    assert_eq!(flow.direction, nettrap_flow::FlowDirection::Internal);
}

#[test]
fn session_lifecycle_marks_mapped_loopback_sessions_internal() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let flow_manager = Arc::new(nettrap_flow::FlowManager::default());
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::clone(&flow_manager),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "[::ffff:127.0.0.1]:53003".parse().unwrap();
    let destination = SessionDestination::new_unchecked("::ffff:127.0.0.1", 8080);

    ctx.register_session_state(&src, "TCP", Some(destination.clone()));

    let canonical_src: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let key =
        nettrap_core::prelude::FlowKey::from_five_tuple(&nettrap_core::prelude::FiveTuple::new(
            canonical_src,
            "127.0.0.1".parse().unwrap(),
            src.port(),
            destination.port(),
            nettrap_core::prelude::Protocol::Tcp,
        ));
    let flow = flow_manager.get(&key).expect("flow should be tracked");

    assert_eq!(flow.direction, nettrap_flow::FlowDirection::Internal);
}

#[test]
fn session_lifecycle_treats_multicast_destinations_as_unknown() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let flow_manager = Arc::new(nettrap_flow::FlowManager::default());
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::clone(&flow_manager),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "192.0.2.10:53003".parse().unwrap();
    let destination = SessionDestination::new_unchecked("224.0.0.1", 8080);

    ctx.register_session_state(&src, "TCP", Some(destination));

    let key =
        nettrap_core::prelude::FlowKey::from_five_tuple(&nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            "224.0.0.1".parse().unwrap(),
            src.port(),
            8080,
            nettrap_core::prelude::Protocol::Tcp,
        ));
    let flow = flow_manager.get(&key).expect("flow should be tracked");

    assert_eq!(flow.direction, nettrap_flow::FlowDirection::Unknown);
}

#[test]
fn pcap_destination_ip_rejects_multicast_and_broadcast_addresses() {
    let multicast = SessionDestination::new_unchecked("224.0.0.1", 8080);
    let broadcast = SessionDestination::new_unchecked("255.255.255.255", 8080);
    let mapped_multicast = SessionDestination::new_unchecked("::ffff:224.0.0.1", 8080);

    assert_eq!(ListenerContext::pcap_destination_ip(&multicast), None);
    assert_eq!(ListenerContext::pcap_destination_ip(&broadcast), None);
    assert_eq!(
        ListenerContext::pcap_destination_ip(&mapped_multicast),
        None
    );
}

#[test]
fn pcap_destination_ip_canonicalizes_ipv4_mapped_addresses() {
    let mapped = SessionDestination::new_unchecked("::ffff:203.0.113.10", 8080);

    assert_eq!(
        ListenerContext::pcap_destination_ip(&mapped),
        Some("203.0.113.10".parse().unwrap())
    );
}

#[test]
fn session_lifecycle_marks_unknown_destinations_unknown() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let flow_manager = Arc::new(nettrap_flow::FlowManager::default());
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::clone(&flow_manager),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53004".parse().unwrap();
    let destination = unknown_session_destination_for_peer(&src, 8080);

    ctx.register_session_state(&src, "TCP", Some(destination.clone()));

    let key =
        nettrap_core::prelude::FlowKey::from_five_tuple(&nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            src.port(),
            destination.port(),
            nettrap_core::prelude::Protocol::Tcp,
        ));
    let flow = flow_manager.get(&key).expect("flow should be tracked");

    assert_eq!(flow.direction, nettrap_flow::FlowDirection::Unknown);
}

#[test]
fn session_lifecycle_marks_ipv6_unknown_destinations_as_ipv6_unspecified() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let flow_manager = Arc::new(nettrap_flow::FlowManager::default());
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::clone(&flow_manager),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "[::1]:53004".parse().unwrap();
    let destination = unknown_session_destination_for_peer(&src, 8080);

    ctx.register_session_state(&src, "TCP", Some(destination.clone()));

    let key =
        nettrap_core::prelude::FlowKey::from_five_tuple(&nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            src.port(),
            destination.port(),
            nettrap_core::prelude::Protocol::Tcp,
        ));
    let flow = flow_manager.get(&key).expect("flow should be tracked");

    assert_eq!(flow.direction, nettrap_flow::FlowDirection::Unknown);
}

#[test]
fn session_process_metadata_is_cleared_when_tracker_clears_attribution() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let flow_manager = Arc::new(nettrap_flow::FlowManager::default());
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::clone(&flow_manager),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53001".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.7", 8080);

    ctx.register_session_state(&src, "TCP", Some(destination.clone()));
    tracker.set_process(
        &src,
        "TCP",
        &destination,
        Some("curl".to_string()),
        Some(4242),
    );
    ctx.update_session_bytes(&src, "TCP", &destination, 1, 1);

    let key =
        nettrap_core::prelude::FlowKey::from_five_tuple(&nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            "10.0.0.7".parse().unwrap(),
            src.port(),
            destination.port(),
            nettrap_core::prelude::Protocol::Tcp,
        ));
    let flow = flow_manager.get(&key).expect("flow should exist");
    let process = flow
        .metadata
        .process
        .as_ref()
        .expect("flow should have process attribution");
    assert_eq!(process.pid(), 4242);
    assert_eq!(process.name(), "curl");

    tracker.set_process(&src, "TCP", &destination, None, None);
    ctx.update_session_bytes(&src, "TCP", &destination, 1, 1);

    let updated_flow = flow_manager.get(&key).expect("flow should still exist");
    assert!(updated_flow.metadata.process.is_none());
}

#[test]
fn session_process_metadata_is_not_fabricated_from_name_without_pid() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let flow_manager = Arc::new(nettrap_flow::FlowManager::default());
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::clone(&flow_manager),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53002".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.7", 8080);

    ctx.register_session_state(&src, "TCP", Some(destination.clone()));
    tracker.set_process(&src, "TCP", &destination, Some("curl".to_string()), None);
    ctx.update_session_bytes(&src, "TCP", &destination, 1, 1);

    let key =
        nettrap_core::prelude::FlowKey::from_five_tuple(&nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            "10.0.0.7".parse().unwrap(),
            src.port(),
            destination.port(),
            nettrap_core::prelude::Protocol::Tcp,
        ));
    let flow = flow_manager.get(&key).expect("flow should exist");

    assert!(flow.metadata.process.is_none());
}

#[test]
fn session_process_metadata_treats_blank_name_like_missing_name() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let flow_manager = Arc::new(nettrap_flow::FlowManager::default());
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::clone(&flow_manager),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53004".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.7", 8080);
    let pid = 4245;

    ctx.register_session_state(&src, "TCP", Some(destination.clone()));
    tracker.set_process(
        &src,
        "TCP",
        &destination,
        Some("   ".to_string()),
        Some(pid),
    );
    ctx.update_session_bytes(&src, "TCP", &destination, 1, 1);

    let key =
        nettrap_core::prelude::FlowKey::from_five_tuple(&nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            "10.0.0.7".parse().unwrap(),
            src.port(),
            destination.port(),
            nettrap_core::prelude::Protocol::Tcp,
        ));
    let flow = flow_manager.get(&key).expect("flow should exist");
    let process = flow
        .metadata
        .process
        .as_ref()
        .expect("flow should have process attribution");

    assert_eq!(process.pid(), pid);
    assert_eq!(process.name(), format!("pid-{pid}"));
}

#[test]
fn session_process_metadata_preserves_pid_without_name() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let flow_manager = Arc::new(nettrap_flow::FlowManager::default());
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::clone(&flow_manager),
            }),
        )
        .expect("listener context should build");
    let src: std::net::SocketAddr = "127.0.0.1:53003".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.7", 8080);

    ctx.register_session_state(&src, "TCP", Some(destination.clone()));
    tracker.set_process(&src, "TCP", &destination, None, Some(4244));
    ctx.update_session_bytes(&src, "TCP", &destination, 1, 1);

    let key =
        nettrap_core::prelude::FlowKey::from_five_tuple(&nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            "10.0.0.7".parse().unwrap(),
            src.port(),
            destination.port(),
            nettrap_core::prelude::Protocol::Tcp,
        ));
    let flow = flow_manager.get(&key).expect("flow should exist");
    let process = flow
        .metadata
        .process
        .as_ref()
        .expect("flow should have process attribution");

    assert_eq!(process.pid(), 4244);
    assert_eq!(process.name(), "pid-4244");
}

#[test]
fn session_flow_five_tuple_uses_peer_family_for_invalid_destination_ip() {
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
        .expect("listener context should build");
    let src: std::net::SocketAddr = "[::1]:53000".parse().unwrap();
    let destination = SessionDestination::new_unchecked("not-an-ip", 8080);

    assert_eq!(
        ctx.session_flow_five_tuple(&src, "TCP", &destination),
        Some(nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            src.port(),
            destination.port(),
            nettrap_core::prelude::Protocol::Tcp,
        ))
    );
}

#[test]
fn session_flow_five_tuple_canonicalizes_ipv4_mapped_addresses() {
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
        .expect("listener context should build");
    let src: std::net::SocketAddr = "[::ffff:192.0.2.10]:53000".parse().unwrap();
    let destination = SessionDestination::new_unchecked("::ffff:203.0.113.10", 8080);

    let five_tuple = ctx
        .session_flow_five_tuple(&src, "TCP", &destination)
        .expect("mapped tuple should parse");

    assert_eq!(
        five_tuple.src_ip,
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10))
    );
    assert_eq!(
        five_tuple.dst_ip,
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 10))
    );
}

#[test]
fn write_pcap_event_for_destination_skips_unknown_destination() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-pcap-context-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let path = root.join("capture.pcap");
    let writer = Arc::new(PcapWriter::new(&path).expect("valid pcap path"));
    writer.open().expect("pcap writer should open");

    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
        .build(
            ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                .expect("empty host rules should compile"),
            ListenerRuntime::new(ListenerRuntimeResources {
                ca: None,
                router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                attribution: None,
                attribution_timeout: std::time::Duration::from_millis(5000),
                pcap_writer: Some(Arc::clone(&writer)),
                nbi_collector: Arc::new(
                    crate::nbi::NbiCollector::new(None).expect("collector should build"),
                ),
                session_tracker: Arc::new(SessionTracker::new()),
                port_forward_table: Arc::new(PortForwardTable::new()),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        )
        .expect("listener context should build");
    let peer: std::net::SocketAddr = "198.51.100.7:53000".parse().unwrap();

    for destination in [
        SessionDestination::unknown(8080),
        SessionDestination::new_unchecked("::ffff:0.0.0.0", 8080),
    ] {
        ctx.write_pcap_event_for_destination(b"payload", &peer, &destination);
    }
    writer.close().expect("pcap writer should close");

    let packets = PcapReader::new(&path)
        .read_file()
        .expect("pcap file should be readable");

    assert!(packets.is_empty());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn write_pcap_event_for_destination_skips_invalid_destination_ip() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-pcap-context-invalid-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let path = root.join("capture.pcap");
    let writer = Arc::new(PcapWriter::new(&path).expect("valid pcap path"));
    writer.open().expect("pcap writer should open");

    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
        .build(
            ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                .expect("empty host rules should compile"),
            ListenerRuntime::new(ListenerRuntimeResources {
                ca: None,
                router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                attribution: None,
                attribution_timeout: std::time::Duration::from_millis(5000),
                pcap_writer: Some(Arc::clone(&writer)),
                nbi_collector: Arc::new(
                    crate::nbi::NbiCollector::new(None).expect("collector should build"),
                ),
                session_tracker: Arc::new(SessionTracker::new()),
                port_forward_table: Arc::new(PortForwardTable::new()),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        )
        .expect("listener context should build");
    let peer: std::net::SocketAddr = "198.51.100.7:53000".parse().unwrap();
    let destination = SessionDestination::new_unchecked("not-an-ip", 8080);

    ctx.write_pcap_event_for_destination(b"payload", &peer, &destination);
    writer.close().expect("pcap writer should close");

    let packets = PcapReader::new(&path)
        .read_file()
        .expect("pcap file should remain readable");

    assert!(packets.is_empty());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn write_pcap_event_for_destination_canonicalizes_ipv4_mapped_peer_ip() {
    let root = std::env::temp_dir().join(format!(
        "nettrap-pcap-context-peer-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let path = root.join("capture.pcap");
    let writer = Arc::new(PcapWriter::new(&path).expect("valid pcap path"));
    writer.open().expect("pcap writer should open");

    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
        .build(
            ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                .expect("empty host rules should compile"),
            ListenerRuntime::new(ListenerRuntimeResources {
                ca: None,
                router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
                attribution: None,
                attribution_timeout: std::time::Duration::from_millis(5000),
                pcap_writer: Some(Arc::clone(&writer)),
                nbi_collector: Arc::new(
                    crate::nbi::NbiCollector::new(None).expect("collector should build"),
                ),
                session_tracker: Arc::new(SessionTracker::new()),
                port_forward_table: Arc::new(PortForwardTable::new()),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        )
        .expect("listener context should build");
    let peer: std::net::SocketAddr = "[::ffff:198.51.100.7]:53000".parse().unwrap();
    let destination = SessionDestination::new_unchecked("203.0.113.10", 8080);

    ctx.write_pcap_event_for_destination(b"payload", &peer, &destination);
    writer.close().expect("pcap writer should close");

    let packets = PcapReader::new(&path)
        .read_file()
        .expect("pcap file should be readable");

    assert_eq!(packets.len(), 1);
    assert_eq!(
        packets[0].five_tuple.src_ip,
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7))
    );
    assert_eq!(
        packets[0].five_tuple.dst_ip,
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 10))
    );
    assert_eq!(packets[0].payload.as_ref(), b"payload");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn canonical_execute_src_ip_canonicalizes_ipv4_mapped_addresses() {
    let peer: std::net::SocketAddr = "[::ffff:198.51.100.7]:53000".parse().unwrap();

    assert_eq!(canonical_execute_src_ip(&peer), "198.51.100.7");
}

#[test]
fn canonical_execute_dst_ip_canonicalizes_ipv4_mapped_addresses() {
    let peer: std::net::SocketAddr = "[::1]:53000".parse().unwrap();
    let destination = SessionDestination::new_unchecked("::ffff:203.0.113.10", 8080);

    assert_eq!(
        canonical_execute_dst_ip(&peer, &destination),
        "203.0.113.10"
    );
}

#[test]
fn canonical_execute_dst_ip_uses_peer_family_for_invalid_destination_ip() {
    let ipv4_peer: std::net::SocketAddr = "198.51.100.7:53000".parse().unwrap();
    let ipv6_peer: std::net::SocketAddr = "[2001:db8::7]:53000".parse().unwrap();
    let destination = SessionDestination::new_unchecked("not-an-ip", 8080);

    assert_eq!(
        canonical_execute_dst_ip(&ipv4_peer, &destination),
        "0.0.0.0"
    );
    assert_eq!(canonical_execute_dst_ip(&ipv6_peer, &destination), "::");
}

#[test]
fn resolve_session_destination_for_port_uses_peer_family_for_fallback() {
    let tracker = Arc::new(SessionTracker::new());
    let port_forward_table = Arc::new(PortForwardTable::new());
    let ctx = ListenerContext::builder()
        .name("http")
        .port(8080)
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
                session_tracker: Arc::clone(&tracker),
                port_forward_table: Arc::clone(&port_forward_table),
                flow_manager: Arc::new(nettrap_flow::FlowManager::default()),
            }),
        )
        .expect("listener context should build");
    let ipv4_peer: std::net::SocketAddr = "192.0.2.10:53000".parse().unwrap();
    let ipv6_peer: std::net::SocketAddr = "[2001:db8::10]:53000".parse().unwrap();

    assert_eq!(
        ctx.resolve_session_destination_for_port(&ipv4_peer, "TCP", 8080),
        SessionDestination::new_unchecked("0.0.0.0", 8080)
    );
    assert_eq!(
        ctx.resolve_session_destination_for_port(&ipv6_peer, "TCP", 8080),
        SessionDestination::new_unchecked("::", 8080)
    );
}
