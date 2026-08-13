use super::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

fn tracker_with_ttl(ttl_secs: u64) -> SessionTracker {
    SessionTracker {
        sessions: parking_lot::RwLock::new(HashMap::new()),
        session_ttl_secs: ttl_secs,
        last_cleanup: parking_lot::RwLock::new(Instant::now()),
        cleanup_interval_secs: super::DEFAULT_CLEANUP_INTERVAL_SECS,
        max_sessions: super::DEFAULT_MAX_SESSIONS,
    }
}

fn tracker_with_ttl_and_max_sessions(ttl_secs: u64, max_sessions: usize) -> SessionTracker {
    SessionTracker {
        sessions: parking_lot::RwLock::new(HashMap::new()),
        session_ttl_secs: ttl_secs,
        last_cleanup: parking_lot::RwLock::new(Instant::now()),
        cleanup_interval_secs: super::DEFAULT_CLEANUP_INTERVAL_SECS,
        max_sessions,
    }
}

#[test]
fn test_session_tracker_new() {
    let tracker = SessionTracker::new();
    assert_eq!(tracker.active_count(), 0);
}

#[test]
fn test_session_tracker_register() {
    let tracker = SessionTracker::new();
    let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
    let destination = SessionDestination::unknown(80);

    let is_new = tracker.register(&addr, &destination, "test", "TCP");
    assert!(is_new, "First registration should be new");
    assert_eq!(tracker.active_count(), 1);

    let is_new2 = tracker.register(&addr, &destination, "test", "TCP");
    assert!(!is_new2, "Second registration should not be new");
    assert_eq!(tracker.active_count(), 1);
}

#[test]
fn test_session_tracker_update_bytes() {
    let tracker = SessionTracker::new();
    let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

    let destination = SessionDestination::unknown(80);
    tracker.register(&addr, &destination, "test", "TCP");
    tracker.update_bytes(&addr, "TCP", &destination, 100, 200);

    assert_eq!(tracker.active_count(), 1);
}

#[test]
fn test_session_tracker_update_bytes_saturates_counters() {
    let tracker = SessionTracker::new();
    let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
    let destination = SessionDestination::unknown(80);
    tracker.register(&addr, &destination, "test", "TCP");

    {
        let key = SessionTracker::session_key(&addr, &destination, "TCP");
        let mut sessions = tracker.sessions.write();
        let session = sessions.get_mut(&key).expect("session should exist");
        session.bytes_received = u64::MAX - 1;
        session.bytes_sent = u64::MAX - 2;
        session.packets = u64::MAX;
    }

    tracker.update_bytes(&addr, "TCP", &destination, 10, 10);

    let exported = tracker
        .export_sessions()
        .expect("sessions should serialize");
    let exported: serde_json::Value =
        serde_json::from_str(&exported).expect("sessions should be valid JSON");
    let session = exported
        .as_object()
        .expect("sessions should serialize as an object")
        .values()
        .next()
        .expect("one session should be exported");

    assert_eq!(session["bytes_received"], u64::MAX);
    assert_eq!(session["bytes_sent"], u64::MAX);
    assert_eq!(session["packets"], u64::MAX);
}

#[test]
fn test_session_tracker_remove() {
    let tracker = SessionTracker::new();
    let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

    let destination = SessionDestination::unknown(80);
    tracker.register(&addr, &destination, "test", "TCP");
    assert_eq!(tracker.active_count(), 1);

    tracker.remove(&addr, "TCP", &destination);
    assert_eq!(tracker.active_count(), 0);
}

#[test]
fn test_session_tracker_get_process() {
    let tracker = SessionTracker::new();
    let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

    let destination = SessionDestination::unknown(80);
    tracker.register(&addr, &destination, "test", "TCP");
    tracker.set_process(
        &addr,
        "TCP",
        &destination,
        Some("curl".to_string()),
        Some(1234),
    );

    assert_eq!(
        tracker.get_process(&addr, "TCP", &destination),
        Some((Some("curl".to_string()), Some(1234)))
    );
}

#[test]
fn test_session_tracker_normalizes_blank_process_names() {
    let tracker = SessionTracker::new();
    let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
    let destination = SessionDestination::unknown(80);

    tracker.register(&addr, &destination, "test", "TCP");
    tracker.set_process(
        &addr,
        "TCP",
        &destination,
        Some("   ".to_string()),
        Some(1234),
    );

    assert_eq!(
        tracker.get_process(&addr, "TCP", &destination),
        Some((None, Some(1234)))
    );
}

#[test]
fn test_session_tracker_sanitizes_process_names_to_single_line() {
    let tracker = SessionTracker::new();
    let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
    let destination = SessionDestination::unknown(80);

    tracker.register(&addr, &destination, "test", "TCP");
    tracker.set_process(
        &addr,
        "TCP",
        &destination,
        Some(" alpha\nbeta ".to_string()),
        Some(1234),
    );

    assert_eq!(
        tracker.get_process(&addr, "TCP", &destination),
        Some((Some(" alpha beta ".to_string()), Some(1234)))
    );
}

#[test]
fn test_session_tracker_background_cleanup() {
    let tracker = Arc::new(SessionTracker::new());
    let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

    tracker.register(&addr, &SessionDestination::unknown(80), "test", "TCP");
    assert_eq!(tracker.active_count(), 1);

    let _ = tracker.cleanup_expired_sessions();
    assert_eq!(tracker.active_count(), 1); // Session not expired yet
}

#[test]
fn test_session_tracker_export() {
    let tracker = SessionTracker::new();
    let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

    tracker.register(&addr, &SessionDestination::unknown(80), "test", "TCP");

    assert_eq!(tracker.active_count(), 1);
}

#[test]
fn test_session_tracker_export_sessions_serializes_sessions() {
    let baseline = crate::faketime::get_delta();
    crate::faketime::set_delta(86_400);

    let tracker = SessionTracker::new();
    let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.5", 80);

    tracker.register(&addr, &destination, "test", "TCP");

    let exported = tracker
        .export_sessions()
        .expect("sessions should serialize");
    let exported: serde_json::Value =
        serde_json::from_str(&exported).expect("sessions should be valid JSON");
    let sessions = exported
        .as_object()
        .expect("sessions should serialize as an object");
    assert_eq!(sessions.len(), 1);
    let session = sessions
        .values()
        .next()
        .expect("one session should be exported");
    let expected_date = crate::faketime::fake_now().date_naive().to_string();
    crate::faketime::set_delta(baseline);

    assert_eq!(session["dst_ip"], "10.0.0.5");
    assert_eq!(session["dst_port"], 80);
    assert!(
        session["started_at"]
            .as_str()
            .is_some_and(|value| value.contains(&expected_date))
    );
}

#[test]
fn test_session_key_creation() {
    let key = SessionKey {
        src_ip: "192.168.1.1".to_string(),
        src_port: 12345,
        dst_ip: "10.0.0.5".to_string(),
        dst_port: 80,
        protocol: "TCP".to_string(),
    };

    assert_eq!(key.src_ip, "192.168.1.1");
    assert_eq!(key.src_port, 12345);
    assert_eq!(key.dst_ip, "10.0.0.5");
    assert_eq!(key.dst_port, 80);
    assert_eq!(key.protocol, "TCP");
}

#[test]
fn test_session_tracker_canonicalizes_ipv4_mapped_destination_keys() {
    let tracker = SessionTracker::new();
    let addr: SocketAddr = "[::ffff:192.0.2.10]:12345".parse().unwrap();
    let destination = SessionDestination::new_unchecked("::ffff:10.0.0.5", 80);

    tracker.register(&addr, &destination, "test", "TCP");

    let canonical_destination = SessionDestination::new_unchecked("10.0.0.5", 80);
    let key = SessionTracker::session_key(&addr, &canonical_destination, "TCP");
    let exported = tracker.sessions.read();
    let session = exported.get(&key).expect("canonical key should match");

    assert_eq!(session.dst_ip, "10.0.0.5");
    assert_eq!(session.dst_port, 80);
}

#[test]
fn test_session_tracker_uses_peer_family_for_invalid_destination_ip() {
    let tracker = SessionTracker::new();
    let addr: SocketAddr = "[::1]:12345".parse().unwrap();
    let destination = SessionDestination::new_unchecked("not-an-ip", 80);

    tracker.register(&addr, &destination, "test", "TCP");

    let key = SessionTracker::session_key(&addr, &destination, "TCP");
    let exported = tracker.sessions.read();
    let session = exported
        .get(&key)
        .expect("peer-family fallback should match");

    assert_eq!(session.dst_ip, "::");
    assert_eq!(session.dst_port, 80);
}

#[test]
fn test_session_destination_new_canonicalizes_ipv4_mapped_addresses() {
    let destination = SessionDestination::new("::ffff:203.0.113.10", 8080)
        .expect("mapped address should be accepted");

    assert_eq!(
        destination,
        SessionDestination::new("203.0.113.10", 8080).expect("canonical address should work")
    );
}

#[test]
fn test_session_destination_new_rejects_non_ip_strings() {
    let err = SessionDestination::new("mail.example.com", 25)
        .expect_err("non-IP destination should be rejected");

    assert!(
        err.to_string().contains("invalid session destination IP"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_session_destination_deserialize_canonicalizes_ipv4_mapped_addresses() {
    let destination: SessionDestination =
        serde_json::from_str(r#"{"ip":"::ffff:203.0.113.10","port":8080}"#)
            .expect("destination should deserialize");

    assert_eq!(
        destination,
        SessionDestination::new("203.0.113.10", 8080).expect("canonical address should work")
    );
}

#[test]
fn test_session_destination_deserialize_rejects_invalid_ip_addresses() {
    let err = serde_json::from_str::<SessionDestination>(r#"{"ip":"not-an-ip","port":8080}"#)
        .expect_err("invalid destination IP should fail to deserialize");

    assert!(
        err.to_string().contains("invalid session destination IP"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_session_tracker_canonicalizes_ipv4_mapped_source_keys() {
    let tracker = SessionTracker::new();
    let mapped_src: SocketAddr = "[::ffff:192.0.2.10]:12345".parse().unwrap();
    let canonical_src: SocketAddr = "192.0.2.10:12345".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.5", 80);

    assert!(tracker.register(&mapped_src, &destination, "test", "TCP"));
    assert!(!tracker.register(&canonical_src, &destination, "test", "TCP"));

    tracker.set_process(
        &canonical_src,
        "TCP",
        &destination,
        Some("curl".to_string()),
        Some(1234),
    );

    assert_eq!(
        tracker.get_process(&mapped_src, "TCP", &destination),
        Some((Some("curl".to_string()), Some(1234)))
    );
    assert_eq!(
        tracker.get_destination_for_port(&mapped_src, "TCP", 80),
        Some(destination)
    );
}

#[test]
fn test_session_tracker_normalizes_tcp_udp_protocol_keys() {
    let tracker = SessionTracker::new();
    let src: SocketAddr = "192.0.2.10:12345".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.5", 80);

    assert!(tracker.register(&src, &destination, "listener", " tcp "));
    tracker.set_process(
        &src,
        "TCP",
        &destination,
        Some("curl".to_string()),
        Some(4242),
    );

    assert_eq!(
        tracker.get_process(&src, "TCP", &destination),
        Some((Some("curl".to_string()), Some(4242)))
    );
    assert_eq!(
        tracker.get_process(&src, " tcp ", &destination),
        Some((Some("curl".to_string()), Some(4242)))
    );
    assert_eq!(
        tracker.get_destination_for_port(&src, "TCP", 80),
        Some(destination.clone())
    );
    assert_eq!(
        tracker.get_destination_for_port(&src, " tcp ", 80),
        Some(destination)
    );
}

#[test]
fn test_port_forward_table_normalizes_protocol_keys() {
    let table = PortForwardTable::new();
    let src: SocketAddr = "192.0.2.10:12345".parse().unwrap();
    let original_dst: SocketAddr = "198.51.100.7:8080".parse().unwrap();

    table.set_default_tcp_target(9000);
    table.record_original_dest(&src, " tcp ", 8080, &original_dst);

    assert_eq!(table.resolve_redirect_target(" tcp ", 8080), Some(9000));
    assert_eq!(table.resolve_redirect_target("TCP", 8080), Some(9000));
    assert_eq!(
        table.take_original_dest(&src, "TCP", 8080),
        Some(SessionDestination::new_unchecked("198.51.100.7", 8080))
    );
    assert_eq!(table.take_original_dest(&src, " tcp ", 8080), None);
}

#[test]
fn test_session_key_to_five_tuple_canonicalizes_mapped_addresses() {
    let key = SessionKey {
        src_ip: "::ffff:192.0.2.10".to_string(),
        src_port: 12345,
        dst_ip: "::ffff:10.0.0.5".to_string(),
        dst_port: 80,
        protocol: "TCP".to_string(),
    };

    let five_tuple = key.to_five_tuple().expect("mapped tuple should parse");

    assert_eq!(
        five_tuple.src_ip,
        "192.0.2.10".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(
        five_tuple.dst_ip,
        "10.0.0.5".parse::<std::net::IpAddr>().unwrap()
    );
}

#[test]
fn test_session_key_deserialize_canonicalizes_ipv4_mapped_addresses() {
    let key: SessionKey = serde_json::from_str(
        r#"{
                "src_ip":"::ffff:192.0.2.10",
                "src_port":12345,
                "dst_ip":"::ffff:10.0.0.5",
                "dst_port":80,
                "protocol":"TCP"
            }"#,
    )
    .expect("session key should deserialize");

    assert_eq!(key.src_ip, "192.0.2.10");
    assert_eq!(key.dst_ip, "10.0.0.5");
}

#[test]
fn test_session_key_deserialize_canonicalizes_protocol_case() {
    let key: SessionKey = serde_json::from_str(
        r#"{
                "src_ip":"192.0.2.10",
                "src_port":12345,
                "dst_ip":"10.0.0.5",
                "dst_port":80,
                "protocol":"udp"
            }"#,
    )
    .expect("session key should deserialize");

    assert_eq!(key.protocol, "UDP");
    assert!(key.to_five_tuple().is_some());
}

#[test]
fn test_session_key_deserialize_rejects_invalid_protocol() {
    let err = serde_json::from_str::<SessionKey>(
        r#"{
                "src_ip":"192.0.2.10",
                "src_port":12345,
                "dst_ip":"10.0.0.5",
                "dst_port":80,
                "protocol":"icmp"
            }"#,
    )
    .expect_err("invalid session protocol should fail to deserialize");

    assert!(err.to_string().contains("invalid session protocol"));
}

#[test]
fn test_session_key_deserialize_rejects_invalid_ip_addresses() {
    let err = serde_json::from_str::<SessionKey>(
        r#"{
                "src_ip":"not-an-ip",
                "src_port":12345,
                "dst_ip":"10.0.0.5",
                "dst_port":80,
                "protocol":"TCP"
            }"#,
    )
    .expect_err("invalid session IP should fail to deserialize");

    assert!(
        err.to_string().contains("invalid session source IP"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_port_forward_table() {
    let table = PortForwardTable::new();

    table.add_tcp_forward(8080, 80);
    table.add_udp_forward(5353, 53);

    assert_eq!(table.resolve_tcp(8080), Some(80));
    assert_eq!(table.resolve_udp(5353), Some(53));
    assert_eq!(table.resolve_tcp(9090), None);

    table.remove_tcp(8080);
    assert_eq!(table.resolve_tcp(8080), None);
}

#[test]
fn test_port_forward_table_tracks_original_destinations_by_flow() {
    let table = PortForwardTable::new();
    let src: SocketAddr = "192.168.1.10:53000".parse().unwrap();
    let first_original: SocketAddr = "10.0.0.5:4444".parse().unwrap();
    let second_original: SocketAddr = "10.0.0.5:5555".parse().unwrap();

    table.record_original_dest(&src, "UDP", 5353, &first_original);
    table.record_original_dest(&src, "UDP", 5353, &second_original);

    assert_eq!(
        table.take_original_dest(&src, "UDP", 5353),
        Some(SessionDestination::new_unchecked(
            first_original.ip().to_string(),
            first_original.port()
        ))
    );
    assert_eq!(
        table.take_original_dest(&src, "UDP", 5353),
        Some(SessionDestination::new_unchecked(
            second_original.ip().to_string(),
            second_original.port()
        ))
    );
    assert_eq!(table.take_original_dest(&src, "UDP", 5353), None);
}

#[test]
fn test_port_forward_table_canonicalizes_ipv4_mapped_source_keys() {
    let table = PortForwardTable::new();
    let mapped_src: SocketAddr = "[::ffff:192.0.2.10]:53000".parse().unwrap();
    let canonical_src: SocketAddr = "192.0.2.10:53000".parse().unwrap();
    let original_dst: SocketAddr = "10.0.0.5:4444".parse().unwrap();

    table.record_original_dest(&mapped_src, "UDP", 5353, &original_dst);

    assert_eq!(
        table.take_original_dest(&canonical_src, "UDP", 5353),
        Some(SessionDestination::new_unchecked("10.0.0.5", 4444))
    );
}

#[test]
fn test_port_forward_table_deduplicates_tcp_original_destination_queue() {
    let table = PortForwardTable::new();
    let src: SocketAddr = "192.168.1.10:53000".parse().unwrap();
    let first_original: SocketAddr = "10.0.0.5:4444".parse().unwrap();
    let second_original: SocketAddr = "10.0.0.6:4444".parse().unwrap();

    table.record_original_dest(&src, "TCP", 8080, &first_original);
    table.record_original_dest(&src, "TCP", 8080, &second_original);

    assert_eq!(
        table.take_original_dest(&src, "TCP", 8080),
        Some(SessionDestination::new_unchecked(
            second_original.ip().to_string(),
            second_original.port()
        ))
    );
    assert_eq!(table.take_original_dest(&src, "TCP", 8080), None);
}

#[test]
fn test_port_forward_table_purges_only_stale_original_destinations() {
    let table = PortForwardTable::new();
    let stale_src: SocketAddr = "192.168.1.10:53000".parse().unwrap();
    let fresh_src: SocketAddr = "192.168.1.11:53001".parse().unwrap();
    let stale_dst: SocketAddr = "10.0.0.5:4444".parse().unwrap();
    let fresh_dst: SocketAddr = "10.0.0.6:5555".parse().unwrap();

    table.record_original_dest(&stale_src, "UDP", 5353, &stale_dst);
    std::thread::sleep(Duration::from_millis(20));
    table.record_original_dest(&fresh_src, "UDP", 5353, &fresh_dst);

    table.purge_stale_destinations(Duration::from_millis(10));

    assert_eq!(table.take_original_dest(&stale_src, "UDP", 5353), None);
    assert_eq!(
        table.take_original_dest(&fresh_src, "UDP", 5353),
        Some(SessionDestination::new_unchecked(
            fresh_dst.ip().to_string(),
            fresh_dst.port()
        ))
    );
}

#[test]
fn test_port_forward_table_caps_udp_original_destination_queue() {
    let table = PortForwardTable::new();
    let src: SocketAddr = "192.168.1.10:53000".parse().unwrap();

    for offset in 0..(MAX_ORIGINAL_DESTINATIONS_PER_FLOW + 2) {
        let original_dst: SocketAddr = format!("10.0.0.5:{}", 4000 + offset).parse().unwrap();
        table.record_original_dest(&src, "UDP", 5353, &original_dst);
    }

    assert_eq!(
        table.take_original_dest(&src, "UDP", 5353),
        Some(SessionDestination::new_unchecked("10.0.0.5", 4002))
    );
}

#[test]
fn test_port_forward_table_evicts_oldest_original_destination_flow() {
    let mut destinations = HashMap::new();
    let old_key = RedirectFlowKey::new(&"192.168.1.10:53000".parse().unwrap(), "UDP", 5353);
    let fresh_key = RedirectFlowKey::new(&"192.168.1.11:53001".parse().unwrap(), "UDP", 5353);

    destinations.insert(
        old_key.clone(),
        OriginalDestinationQueue {
            queue: VecDeque::new(),
            last_updated: Instant::now() - Duration::from_secs(10),
        },
    );
    destinations.insert(
        fresh_key.clone(),
        OriginalDestinationQueue {
            queue: VecDeque::new(),
            last_updated: Instant::now(),
        },
    );

    PortForwardTable::enforce_original_destination_flow_capacity(&mut destinations, 2);

    assert!(!destinations.contains_key(&old_key));
    assert!(destinations.contains_key(&fresh_key));
}

#[test]
fn test_session_tracker_with_ttl() {
    let tracker = tracker_with_ttl(60); // 1 minute TTL
    assert_eq!(tracker.active_count(), 0);
}

#[test]
fn test_session_tracker_register_refreshes_last_activity() {
    let tracker = tracker_with_ttl(2);
    let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

    tracker.register(&addr, &SessionDestination::unknown(80), "test", "TCP");
    std::thread::sleep(Duration::from_millis(1100));
    tracker.register(&addr, &SessionDestination::unknown(80), "test", "TCP");
    std::thread::sleep(Duration::from_millis(1100));

    let _ = tracker.cleanup_expired_sessions();

    assert_eq!(tracker.active_count(), 1);
}

#[test]
fn test_session_tracker_register_replaces_expired_session_before_cleanup_interval() {
    let tracker = tracker_with_ttl(1);
    let addr: SocketAddr = "192.168.1.4:12348".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.7", 80);

    tracker.register(&addr, &destination, "tcp-listener", "TCP");
    tracker.update_bytes(&addr, "TCP", &destination, 11, 22);
    std::thread::sleep(Duration::from_millis(1100));

    tracker.register(&addr, &destination, "tcp-listener-2", "TCP");

    let exported = tracker.export_sessions().expect("export should succeed");
    let sessions: serde_json::Value = serde_json::from_str(&exported).expect("valid JSON");
    let session = sessions
        .as_object()
        .and_then(|entries| entries.values().next())
        .expect("session should exist");

    assert_eq!(tracker.active_count(), 1);
    assert_eq!(session["listener"], "tcp-listener-2");
    assert_eq!(session["bytes_sent"], 0);
    assert_eq!(session["bytes_received"], 0);
    assert_eq!(session["packets"], 0);
}

#[test]
fn test_session_tracker_update_bytes_ignores_expired_session_before_cleanup_interval() {
    let tracker = tracker_with_ttl(1);
    let addr: SocketAddr = "192.168.1.5:12349".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.8", 80);

    tracker.register(&addr, &destination, "udp-listener", "UDP");
    std::thread::sleep(Duration::from_millis(1100));

    tracker.update_bytes(&addr, "UDP", &destination, 5, 7);

    assert_eq!(tracker.active_count(), 0);
    assert_eq!(
        tracker.export_sessions().expect("export should succeed"),
        "{}"
    );
}

#[test]
fn test_session_tracker_set_process_ignores_expired_session_before_cleanup_interval() {
    let tracker = tracker_with_ttl(1);
    let addr: SocketAddr = "192.168.1.6:12350".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.9", 80);

    tracker.register(&addr, &destination, "udp-listener", "UDP");
    std::thread::sleep(Duration::from_millis(1100));

    tracker.set_process(
        &addr,
        "UDP",
        &destination,
        Some("ignored".to_string()),
        Some(4242),
    );

    assert_eq!(tracker.active_count(), 0);
    assert!(tracker.get_process(&addr, "UDP", &destination).is_none());
}

#[test]
fn test_session_tracker_cleanup_returns_expired_keys() {
    let tracker = tracker_with_ttl(1);
    let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.5", 80);

    tracker.register(&addr, &destination, "udp-test", "UDP");
    std::thread::sleep(Duration::from_millis(1100));

    let expired = tracker.cleanup_expired_sessions();

    assert_eq!(tracker.active_count(), 0);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].protocol, "UDP");
    assert_eq!(expired[0].dst_ip, "10.0.0.5");
    assert_eq!(expired[0].dst_port, 80);
}

#[test]
fn test_session_tracker_read_methods_cleanup_expired_sessions_before_reporting() {
    let tracker = tracker_with_ttl(1);
    let addr: SocketAddr = "192.168.1.2:12346".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.5", 80);

    tracker.register(&addr, &destination, "udp-test", "UDP");
    std::thread::sleep(Duration::from_millis(1100));

    assert_eq!(tracker.active_count(), 0);
    assert!(tracker.get_process(&addr, "UDP", &destination).is_none());
    assert!(tracker.get_destination_for_port(&addr, "UDP", 80).is_none());
    assert!(
        tracker
            .get_original_dest(&addr, "UDP", &destination)
            .is_none()
    );
    assert_eq!(
        tracker.export_sessions().expect("export should succeed"),
        "{}"
    );
}

#[test]
fn test_session_tracker_keeps_distinct_destinations_separate() {
    let tracker = SessionTracker::new();
    let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

    let http_destination = SessionDestination::new_unchecked("10.0.0.5", 80);
    let https_destination = SessionDestination::new_unchecked("10.0.0.6", 443);
    tracker.register(&addr, &http_destination, "http", "TCP");
    tracker.register(&addr, &https_destination, "https", "TCP");
    tracker.set_process(
        &addr,
        "TCP",
        &http_destination,
        Some("curl".to_string()),
        Some(1001),
    );
    tracker.set_process(
        &addr,
        "TCP",
        &https_destination,
        Some("chrome".to_string()),
        Some(2002),
    );

    assert_eq!(tracker.active_count(), 2);
    assert_eq!(
        tracker.get_process(&addr, "TCP", &http_destination),
        Some((Some("curl".to_string()), Some(1001)))
    );
    assert_eq!(
        tracker.get_process(&addr, "TCP", &https_destination),
        Some((Some("chrome".to_string()), Some(2002)))
    );
}

#[test]
fn test_session_tracker_keeps_same_port_different_destinations_separate() {
    let tracker = SessionTracker::new();
    let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
    let first_destination = SessionDestination::new_unchecked("10.0.0.5", 443);
    let second_destination = SessionDestination::new_unchecked("10.0.0.6", 443);

    tracker.register(&addr, &first_destination, "tls-a", "TCP");
    tracker.register(&addr, &second_destination, "tls-b", "TCP");
    tracker.set_process(
        &addr,
        "TCP",
        &first_destination,
        Some("curl".to_string()),
        Some(1111),
    );
    tracker.set_process(
        &addr,
        "TCP",
        &second_destination,
        Some("browser".to_string()),
        Some(2222),
    );

    assert_eq!(tracker.active_count(), 2);
    assert_eq!(
        tracker.get_process(&addr, "TCP", &first_destination),
        Some((Some("curl".to_string()), Some(1111)))
    );
    assert_eq!(
        tracker.get_process(&addr, "TCP", &second_destination),
        Some((Some("browser".to_string()), Some(2222)))
    );
}

#[test]
fn test_session_tracker_evicts_oldest_session_at_capacity() {
    let tracker = tracker_with_ttl_and_max_sessions(3600, 2);
    let first_addr: SocketAddr = "192.168.1.1:10001".parse().unwrap();
    let second_addr: SocketAddr = "192.168.1.1:10002".parse().unwrap();
    let third_addr: SocketAddr = "192.168.1.1:10003".parse().unwrap();
    let destination = SessionDestination::new_unchecked("10.0.0.5", 443);

    tracker.register(&first_addr, &destination, "first", "TCP");
    std::thread::sleep(Duration::from_millis(5));
    tracker.register(&second_addr, &destination, "second", "TCP");
    std::thread::sleep(Duration::from_millis(5));
    tracker.register(&third_addr, &destination, "third", "TCP");

    assert_eq!(tracker.active_count(), 2);
    assert_eq!(
        tracker.get_original_dest(&first_addr, "TCP", &destination),
        None
    );
    assert_eq!(
        tracker.get_original_dest(&second_addr, "TCP", &destination),
        Some(("10.0.0.5".to_string(), 443))
    );
    assert_eq!(
        tracker.get_original_dest(&third_addr, "TCP", &destination),
        Some(("10.0.0.5".to_string(), 443))
    );
}

#[test]
fn test_session_tracker_capacity_zero_is_unbounded() {
    let tracker = tracker_with_ttl_and_max_sessions(3600, 0);
    let destination = SessionDestination::new_unchecked("10.0.0.5", 443);

    for port in 10000..10003 {
        let addr: SocketAddr = format!("192.168.1.1:{port}").parse().unwrap();
        tracker.register(&addr, &destination, "unbounded", "TCP");
    }

    assert_eq!(tracker.active_count(), 3);
}
