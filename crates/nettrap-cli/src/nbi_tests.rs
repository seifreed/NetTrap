use super::*;
use crate::database::{DatabaseBackend, SqliteStorage};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn saturating_sum_u64_caps_overflow() {
    assert_eq!(saturating_sum_u64([u64::MAX - 1, 10]), u64::MAX);
}

#[test]
fn atomic_fetch_add_saturating_caps_counter() {
    let counter = AtomicU64::new(u64::MAX - 1);

    let updated = atomic_fetch_add_saturating(&counter, 10);

    assert_eq!(updated, u64::MAX);
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
}

struct SlowSink;

#[async_trait::async_trait]
impl crate::distributed::EventSink for SlowSink {
    async fn send(&self, _event: &NetworkBehaviorIndicator) -> crate::distributed::SinkSendResult {
        tokio::time::sleep(Duration::from_millis(200)).await;
        crate::distributed::SinkSendResult::delivered()
    }

    async fn flush(&self) -> Result<(), String> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "slow"
    }
}

struct FailingSink;

#[async_trait::async_trait]
impl crate::distributed::EventSink for FailingSink {
    async fn send(&self, _event: &NetworkBehaviorIndicator) -> crate::distributed::SinkSendResult {
        crate::distributed::SinkSendResult::lost("sink offline")
    }

    async fn flush(&self) -> Result<(), String> {
        Err("sink offline".to_string())
    }

    fn name(&self) -> &'static str {
        "failing"
    }
}

struct CountingSink {
    sends: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::distributed::EventSink for CountingSink {
    async fn send(&self, _event: &NetworkBehaviorIndicator) -> crate::distributed::SinkSendResult {
        self.sends.fetch_add(1, Ordering::Relaxed);
        crate::distributed::SinkSendResult::delivered()
    }

    async fn flush(&self) -> Result<(), String> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "counting"
    }
}

struct FlushCountingSink {
    flushes: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::distributed::EventSink for FlushCountingSink {
    async fn send(&self, _event: &NetworkBehaviorIndicator) -> crate::distributed::SinkSendResult {
        crate::distributed::SinkSendResult::delivered()
    }

    async fn flush(&self) -> Result<(), String> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "flush-counting"
    }
}

struct BufferedFailingSink {
    pending_ids: Arc<parking_lot::RwLock<HashSet<String>>>,
}

#[async_trait::async_trait]
impl crate::distributed::EventSink for BufferedFailingSink {
    async fn send(&self, event: &NetworkBehaviorIndicator) -> crate::distributed::SinkSendResult {
        self.pending_ids.write().insert(event.normalized_event_id());
        crate::distributed::SinkSendResult::buffered(None)
    }

    async fn flush(&self) -> Result<(), String> {
        Err("buffered sink flush failed".to_string())
    }

    fn name(&self) -> &'static str {
        "buffered-failing"
    }

    fn buffered_events(&self) -> usize {
        self.pending_ids.read().len()
    }

    fn buffered_event_ids(&self) -> Vec<String> {
        self.pending_ids.read().iter().cloned().collect()
    }

    fn drop_buffered_events(&self, event_ids: &HashSet<String>) -> usize {
        let mut pending_ids = self.pending_ids.write();
        let before = pending_ids.len();
        pending_ids.retain(|event_id| !event_ids.contains(event_id));
        before.saturating_sub(pending_ids.len())
    }
}

struct BufferedFlushCountingSink {
    flushes: Arc<AtomicUsize>,
    pending_ids: Arc<parking_lot::RwLock<HashSet<String>>>,
}

#[async_trait::async_trait]
impl crate::distributed::EventSink for BufferedFlushCountingSink {
    async fn send(&self, event: &NetworkBehaviorIndicator) -> crate::distributed::SinkSendResult {
        self.pending_ids.write().insert(event.normalized_event_id());
        crate::distributed::SinkSendResult::buffered(None)
    }

    async fn flush(&self) -> Result<(), String> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        self.pending_ids.write().clear();
        Ok(())
    }

    fn name(&self) -> &'static str {
        "buffered-flush-counting"
    }

    fn buffered_events(&self) -> usize {
        self.pending_ids.read().len()
    }

    fn buffered_event_ids(&self) -> Vec<String> {
        self.pending_ids.read().iter().cloned().collect()
    }

    fn drop_buffered_events(&self, event_ids: &HashSet<String>) -> usize {
        let mut pending_ids = self.pending_ids.write();
        let before = pending_ids.len();
        pending_ids.retain(|event_id| !event_ids.contains(event_id));
        before.saturating_sub(pending_ids.len())
    }
}

struct BlockingBufferedFlushSink {
    flushes: Arc<AtomicUsize>,
    gate: Arc<tokio::sync::Semaphore>,
    pending_ids: Arc<parking_lot::RwLock<HashSet<String>>>,
}

#[async_trait::async_trait]
impl crate::distributed::EventSink for BlockingBufferedFlushSink {
    async fn send(&self, event: &NetworkBehaviorIndicator) -> crate::distributed::SinkSendResult {
        self.pending_ids.write().insert(event.normalized_event_id());
        crate::distributed::SinkSendResult::buffered(None)
    }

    async fn flush(&self) -> Result<(), String> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        let permit = self.gate.acquire().await.map_err(|err| err.to_string())?;
        drop(permit);
        self.pending_ids.write().clear();
        Ok(())
    }

    fn name(&self) -> &'static str {
        "blocking-buffered-flush"
    }

    fn buffered_events(&self) -> usize {
        self.pending_ids.read().len()
    }

    fn buffered_event_ids(&self) -> Vec<String> {
        self.pending_ids.read().iter().cloned().collect()
    }

    fn drop_buffered_events(&self, event_ids: &HashSet<String>) -> usize {
        let mut pending_ids = self.pending_ids.write();
        let before = pending_ids.len();
        pending_ids.retain(|event_id| !event_ids.contains(event_id));
        before.saturating_sub(pending_ids.len())
    }
}

struct BlockingCountingSink {
    entered: Arc<AtomicUsize>,
    delivered: Arc<AtomicUsize>,
    gate: Arc<tokio::sync::Semaphore>,
}

#[async_trait::async_trait]
impl crate::distributed::EventSink for BlockingCountingSink {
    async fn send(&self, _event: &NetworkBehaviorIndicator) -> crate::distributed::SinkSendResult {
        self.entered.fetch_add(1, Ordering::Relaxed);
        let permit = self
            .gate
            .acquire()
            .await
            .map_err(|_| "blocking gate closed".to_string());
        let permit = match permit {
            Ok(permit) => permit,
            Err(err) => return crate::distributed::SinkSendResult::lost(err),
        };
        permit.forget();
        self.delivered.fetch_add(1, Ordering::Relaxed);
        crate::distributed::SinkSendResult::delivered()
    }

    async fn flush(&self) -> Result<(), String> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "blocking-counting"
    }
}

async fn spawn_http_event_server() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind http sink server");
    let addr = listener.local_addr().expect("local addr");
    let request_count = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
        let request_count = Arc::clone(&request_count);
        async move {
            loop {
                let (mut stream, _) = listener.accept().await.expect("accept request");
                let request_count = Arc::clone(&request_count);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    request_count.fetch_add(1, Ordering::Relaxed);
                    let body = "{}";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    (format!("http://{}", addr), request_count, task)
}

#[tokio::test]
async fn record_enriches_nbi_with_session_process_metadata() {
    let path =
        std::env::temp_dir().join(format!("nettrap-nbi-test-{}.jsonl", uuid::Uuid::new_v4()));
    let collector = NbiCollector::new(Some(path.clone())).expect("valid NBI path");
    let tracker = std::sync::Arc::new(crate::session::SessionTracker::new());
    let src: std::net::SocketAddr = "127.0.0.1:42424".parse().unwrap();

    let destination = crate::session::SessionDestination::new_unchecked("10.0.0.7", 8080);
    tracker.register(&src, &destination, "http", "TCP");
    tracker.set_process(
        &src,
        "TCP",
        &destination,
        Some("curl".to_string()),
        Some(4242),
    );

    collector.attach_session_tracker(std::sync::Arc::clone(&tracker));
    collector.attach_listener_protocols(std::collections::HashMap::from([(
        "http".to_string(),
        nettrap_core::prelude::Protocol::Tcp,
    )]));

    let nbi = raw_nbi("http", "127.0.0.1", 42424, &destination, 4, "");
    collector.record(&nbi).await;
    collector.flush_all_pending().await;

    let content = tokio::fs::read_to_string(&path).await.unwrap();
    let recorded: NetworkBehaviorIndicator =
        serde_json::from_str(content.lines().next().unwrap()).unwrap();

    assert_eq!(recorded.dst_ip, "10.0.0.7");
    assert_eq!(recorded.dst_port, 8080);
    assert_eq!(recorded.process_name.as_deref(), Some("curl"));
    assert_eq!(recorded.process_pid, Some(4242));

    let _ = std::fs::remove_file(path);
}

#[test]
fn enrich_with_process_uses_peer_family_for_invalid_destination_text() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let tracker = std::sync::Arc::new(crate::session::SessionTracker::new());
    let src: std::net::SocketAddr = "[::1]:42427".parse().unwrap();

    let destination = crate::session::SessionDestination::new_unchecked("not-an-ip", 8080);
    tracker.register(&src, &destination, "http", "TCP");
    tracker.set_process(
        &src,
        "TCP",
        &destination,
        Some("curl".to_string()),
        Some(4245),
    );

    collector.attach_session_tracker(std::sync::Arc::clone(&tracker));
    collector.attach_listener_protocols(std::collections::HashMap::from([(
        "http".to_string(),
        nettrap_core::prelude::Protocol::Tcp,
    )]));

    let mut nbi = raw_nbi("http", "::1", 42427, &destination, 4, "");
    nbi.dst_ip = "still-not-an-ip".to_string();

    let recorded = collector.enrich_with_process(&nbi);

    assert_eq!(recorded.process_name.as_deref(), Some("curl"));
    assert_eq!(recorded.process_pid, Some(4245));
}

#[tokio::test]
async fn record_completes_partial_process_metadata_from_session_tracker() {
    let path =
        std::env::temp_dir().join(format!("nettrap-nbi-test-{}.jsonl", uuid::Uuid::new_v4()));
    let collector = NbiCollector::new(Some(path.clone())).expect("valid NBI path");
    let tracker = std::sync::Arc::new(crate::session::SessionTracker::new());
    let src: std::net::SocketAddr = "127.0.0.1:42425".parse().unwrap();

    let destination = crate::session::SessionDestination::new_unchecked("10.0.0.8", 8080);
    tracker.register(&src, &destination, "http", "TCP");
    tracker.set_process(
        &src,
        "TCP",
        &destination,
        Some("curl".to_string()),
        Some(4243),
    );

    collector.attach_session_tracker(std::sync::Arc::clone(&tracker));
    collector.attach_listener_protocols(std::collections::HashMap::from([(
        "http".to_string(),
        nettrap_core::prelude::Protocol::Tcp,
    )]));

    let nbi = raw_nbi("http", "127.0.0.1", 42425, &destination, 4, "")
        .with_process(Some("manual".to_string()), None);
    collector.record(&nbi).await;
    collector.flush_all_pending().await;

    let content = tokio::fs::read_to_string(&path).await.unwrap();
    let recorded: NetworkBehaviorIndicator =
        serde_json::from_str(content.lines().next().unwrap()).unwrap();

    assert_eq!(recorded.process_name.as_deref(), Some("manual"));
    assert_eq!(recorded.process_pid, Some(4243));

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn record_assigns_a_fresh_event_id_per_delivery() {
    let path =
        std::env::temp_dir().join(format!("nettrap-nbi-test-{}.jsonl", uuid::Uuid::new_v4()));
    let collector = NbiCollector::new(Some(path.clone())).expect("valid NBI path");
    let nbi = raw_nbi(
        "raw",
        "127.0.0.1",
        42424,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    let original_event_id = nbi.event_id.clone();

    collector.record(&nbi).await;
    collector.record(&nbi).await;
    collector.flush_all_pending().await;

    let recorded = tokio::fs::read_to_string(&path)
        .await
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<NetworkBehaviorIndicator>(line).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(recorded.len(), 2);
    assert_ne!(recorded[0].event_id, recorded[1].event_id);
    assert_ne!(recorded[0].event_id, original_event_id);
    assert_ne!(recorded[1].event_id, original_event_id);

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn record_enriches_unicode_listener_names_with_session_metadata() {
    let path =
        std::env::temp_dir().join(format!("nettrap-nbi-test-{}.jsonl", uuid::Uuid::new_v4()));
    let collector = NbiCollector::new(Some(path.clone())).expect("valid NBI path");
    let tracker = std::sync::Arc::new(crate::session::SessionTracker::new());
    let src: std::net::SocketAddr = "127.0.0.1:42426".parse().unwrap();

    let destination = crate::session::SessionDestination::new_unchecked("10.0.0.9", 8080);
    tracker.register(&src, &destination, "TCP", "TCP");
    tracker.set_process(
        &src,
        "TCP",
        &destination,
        Some("curl".to_string()),
        Some(4244),
    );

    collector.attach_session_tracker(std::sync::Arc::clone(&tracker));
    collector.attach_listener_protocols(std::collections::HashMap::from([(
        "MÜLLER".to_string(),
        nettrap_core::prelude::Protocol::Tcp,
    )]));

    let nbi = raw_nbi("müller", "127.0.0.1", 42426, &destination, 4, "");
    collector.record(&nbi).await;
    collector.flush_all_pending().await;

    let content = tokio::fs::read_to_string(&path).await.unwrap();
    let recorded: NetworkBehaviorIndicator =
        serde_json::from_str(content.lines().next().unwrap()).unwrap();

    assert_eq!(recorded.process_name.as_deref(), Some("curl"));
    assert_eq!(recorded.process_pid, Some(4244));

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn record_does_not_wait_for_slow_sink_delivery() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(SlowSink));
    collector.attach_fanout(Arc::new(fanout));

    let nbi = raw_nbi(
        "raw",
        "127.0.0.1",
        42424,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );

    tokio::time::timeout(Duration::from_millis(50), collector.record(&nbi))
        .await
        .expect("record should return before sink completes");

    tokio::time::timeout(Duration::from_secs(1), collector.flush_distributed())
        .await
        .expect("flush should eventually drain the worker");
}

#[tokio::test]
async fn collector_periodically_flushes_http_sink_batches_without_explicit_shutdown() {
    let (url, request_count, server) = spawn_http_event_server().await;
    let collector = NbiCollector::new(None).expect("collector should build");
    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(crate::distributed::HttpSink::new(
        url, None, 10, 50, 1_000,
    )));
    collector.attach_fanout(Arc::new(fanout));

    let nbi = raw_nbi(
        "raw",
        "127.0.0.1",
        42424,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );

    collector.record(&nbi).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while request_count.load(Ordering::Relaxed) == 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("collector supervisor should flush stale HTTP batches");

    collector.stop_background_tasks();
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn slow_export_does_not_block_local_file_persistence() {
    let path =
        std::env::temp_dir().join(format!("nettrap-nbi-test-{}.jsonl", uuid::Uuid::new_v4()));
    let collector = NbiCollector::new(Some(path.clone())).expect("valid NBI path");
    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(SlowSink));
    collector.attach_fanout(Arc::new(fanout));

    let nbi = raw_nbi(
        "raw",
        "127.0.0.1",
        42424,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );

    collector.record(&nbi).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let content = tokio::fs::read_to_string(&path).await.unwrap();
    assert!(
        !content.trim().is_empty(),
        "local persistence should complete first"
    );

    collector.flush_all_pending().await;
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn distributed_export_health_degrades_after_sustained_sink_failures() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();

    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(FailingSink));
    let fanout = Arc::new(fanout);
    fanout.attach_runtime_health(runtime_health.clone());
    collector.attach_fanout(fanout);

    let initial_snapshot = runtime_health.snapshot();
    assert_eq!(
        initial_snapshot.distributed_export.state,
        nettrap_api::ComponentState::Running
    );

    let nbi = raw_nbi(
        "http",
        "127.0.0.1",
        42424,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );

    for _ in 0..3 {
        collector.record(&nbi).await;
    }
    collector.flush_distributed().await;

    let snapshot = runtime_health.snapshot();
    assert_eq!(snapshot.status, nettrap_api::HealthStatus::Degraded);
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .distributed_export
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("distributed export failed")
    );
}

#[tokio::test]
async fn configured_export_is_immediately_marked_running() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();

    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(SlowSink));
    let fanout = Arc::new(fanout);
    fanout.attach_runtime_health(runtime_health.clone());
    collector.attach_fanout(fanout);

    assert_eq!(
        runtime_health.snapshot().distributed_export.state,
        nettrap_api::ComponentState::Running
    );
}

#[tokio::test]
async fn nbi_pipeline_is_disabled_without_local_persistence_targets() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    collector.attach_runtime_health(runtime_health.clone());

    let nbi = raw_nbi(
        "raw",
        "127.0.0.1",
        12345,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&nbi).await;
    collector.flush_all_pending().await;

    let snapshot = runtime_health.snapshot();
    assert_eq!(
        snapshot.nbi_pipeline.state,
        nettrap_api::ComponentState::Disabled
    );
    assert_eq!(snapshot.nbi_pipeline.error, None);
}

#[tokio::test]
async fn attaching_database_promotes_nbi_pipeline_to_running() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    collector.attach_runtime_health(runtime_health.clone());
    assert_eq!(
        runtime_health.snapshot().nbi_pipeline.state,
        nettrap_api::ComponentState::Disabled
    );

    let db_path =
        std::env::temp_dir().join(format!("nettrap-nbi-db-attach-{}.db", uuid::Uuid::new_v4()));
    let db = Arc::new(DatabaseBackend::Sqlite(
        SqliteStorage::new(&db_path, "test-node", "test-run").unwrap(),
    ));
    collector.attach_database(db);

    assert_eq!(
        runtime_health.snapshot().nbi_pipeline.state,
        nettrap_api::ComponentState::Running
    );

    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
    let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
}

#[test]
fn local_persistence_drop_is_reflected_in_health_payload() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    runtime_health.set_distributed_export_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    collector.drop_local_event("forced local drop");

    let snapshot = runtime_health.snapshot();
    assert_eq!(snapshot.status, nettrap_api::HealthStatus::Degraded);
    assert_eq!(
        snapshot.nbi_pipeline.state,
        nettrap_api::ComponentState::Degraded
    );
    assert_eq!(
        snapshot.nbi_pipeline.error.as_deref(),
        Some("local NBI persistence drop: forced local drop")
    );
    assert_eq!(snapshot.nbi_collector.local_dropped, 1);
}

#[test]
fn export_drop_is_reflected_in_distributed_export_health() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(SlowSink));
    let fanout = Arc::new(fanout);
    fanout.attach_runtime_health(runtime_health.clone());
    collector.attach_fanout(fanout);

    collector.drop_export_event("forced export drop");

    let snapshot = runtime_health.snapshot();
    assert_eq!(snapshot.status, nettrap_api::HealthStatus::Degraded);
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Degraded
    );
    assert_eq!(
        snapshot.distributed_export.error.as_deref(),
        Some("distributed export rejected event before fanout acceptance: forced export drop")
    );
    assert_eq!(snapshot.nbi_collector.export_dropped, 0);
    assert_eq!(snapshot.nbi_collector.export_rejected, 1);
}

#[tokio::test]
async fn export_rejection_stays_degraded_after_later_success() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    collector.drop_export_event("forced export rejection");

    let sends = Arc::new(AtomicUsize::new(0));
    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(CountingSink {
        sends: Arc::clone(&sends),
    }));
    collector.attach_fanout(Arc::new(fanout));

    let event = raw_nbi(
        "raw",
        "127.0.0.1",
        48080,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&event).await;
    collector.flush_distributed().await;

    let snapshot = runtime_health.snapshot();
    assert_eq!(sends.load(Ordering::Relaxed), 1);
    assert_eq!(snapshot.nbi_collector.export_rejected, 1);
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .distributed_export
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("distributed export rejected")
    );
}

#[tokio::test]
async fn non_buffered_sink_failure_counts_export_loss() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(FailingSink));
    collector.attach_fanout(Arc::new(fanout));

    let event = raw_nbi(
        "raw",
        "127.0.0.1",
        46000,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&event).await;
    collector.flush_distributed().await;

    let snapshot = runtime_health.snapshot();
    assert_eq!(snapshot.nbi_collector.export_dropped, 1);
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .distributed_export
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("distributed export lost accepted event")
    );
}

#[tokio::test]
async fn mixed_buffered_and_lost_sink_counts_final_loss_once() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    let pending_ids = Arc::new(parking_lot::RwLock::new(HashSet::new()));
    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(FailingSink));
    fanout.add_sink(Box::new(BufferedFailingSink {
        pending_ids: Arc::clone(&pending_ids),
    }));
    let fanout = Arc::new(fanout);
    collector.attach_fanout(Arc::clone(&fanout));

    let event = raw_nbi(
        "raw",
        "127.0.0.1",
        48000,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&event).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while fanout.pending_events() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("mixed fanout should retain one pending logical event");

    assert_eq!(runtime_health.snapshot().nbi_collector.export_dropped, 0);
    assert_eq!(fanout.pending_events(), 1);

    let final_loss = fanout.drop_pending_records() as u64;
    collector.record_retired_export_loss(final_loss, "test sink retirement");

    let snapshot = runtime_health.snapshot();
    assert_eq!(snapshot.nbi_collector.export_dropped, 1);
    assert_eq!(fanout.pending_events(), 0);
    assert_eq!(fanout.drop_pending_records(), 0);
}

#[tokio::test]
async fn drop_pending_records_purges_buffered_sink_state_terminally() {
    let pending_ids = Arc::new(parking_lot::RwLock::new(HashSet::new()));
    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(BufferedFailingSink {
        pending_ids: Arc::clone(&pending_ids),
    }));
    let fanout = Arc::new(fanout);

    let event = raw_nbi(
        "raw",
        "127.0.0.1",
        48100,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    let event_id = event.normalized_event_id();

    fanout.note_queued_record(&event_id);
    let send_outcome = fanout.send(&event).await;
    assert!(send_outcome.error.is_none());
    assert!(!fanout.note_dequeued_record(&event_id).final_loss);
    assert_eq!(fanout.pending_events(), 1);
    assert!(pending_ids.read().contains(&event_id));

    assert_eq!(fanout.drop_pending_records(), 1);
    assert_eq!(fanout.pending_events(), 0);
    assert!(!pending_ids.read().contains(&event_id));
    assert_eq!(fanout.drop_pending_records(), 0);
}

#[test]
fn detaching_sinkless_fanout_disables_distributed_export_health() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    collector.attach_runtime_health(runtime_health.clone());

    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(SlowSink));
    collector.attach_fanout(Arc::new(fanout));
    assert_eq!(
        runtime_health.snapshot().distributed_export.state,
        nettrap_api::ComponentState::Running
    );

    collector.attach_fanout(Arc::new(crate::distributed::EventFanout::new()));
    assert_eq!(
        runtime_health.snapshot().distributed_export.state,
        nettrap_api::ComponentState::Disabled
    );
}

#[tokio::test]
async fn detaching_active_fanout_does_not_disable_export_while_retired_backlog_remains() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    let pending_ids = Arc::new(parking_lot::RwLock::new(HashSet::new()));
    let mut original_fanout = crate::distributed::EventFanout::new();
    original_fanout.add_sink(Box::new(BufferedFailingSink {
        pending_ids: Arc::clone(&pending_ids),
    }));
    collector.attach_fanout(Arc::new(original_fanout));

    let event = raw_nbi(
        "raw",
        "127.0.0.1",
        47000,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&event).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if collector.fanout.read().as_ref().is_some_and(|fanout| {
                fanout.pending_events() > 0
                    && collector.export_worker.queued.load(Ordering::Relaxed) == 0
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("original fanout should retain buffered backlog");

    let mut replacement_fanout = crate::distributed::EventFanout::new();
    replacement_fanout.add_sink(Box::new(SlowSink));
    collector.attach_fanout(Arc::new(replacement_fanout));
    collector.attach_fanout(Arc::new(crate::distributed::EventFanout::new()));

    assert!(
        collector
            .retired_fanouts
            .read()
            .iter()
            .any(|fanout| fanout.pending_events() > 0)
            || runtime_health.snapshot().nbi_collector.export_dropped > 0
    );
    assert_ne!(
        runtime_health.snapshot().distributed_export.state,
        nettrap_api::ComponentState::Disabled
    );
}

#[test]
fn attaching_runtime_health_after_fanout_syncs_distributed_export_state() {
    let collector = NbiCollector::new(None).expect("collector should build");

    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(SlowSink));
    collector.attach_fanout(Arc::new(fanout));

    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    collector.attach_runtime_health(runtime_health.clone());

    assert_eq!(
        runtime_health.snapshot().distributed_export.state,
        nettrap_api::ComponentState::Running
    );
}

#[tokio::test]
async fn replacing_sinkful_fanout_keeps_queued_events_on_original_fanout() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let entered = Arc::new(AtomicUsize::new(0));
    let original_delivered = Arc::new(AtomicUsize::new(0));
    let replacement_delivered = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(tokio::sync::Semaphore::new(0));

    let mut original_fanout = crate::distributed::EventFanout::new();
    original_fanout.add_sink(Box::new(BlockingCountingSink {
        entered: Arc::clone(&entered),
        delivered: Arc::clone(&original_delivered),
        gate: Arc::clone(&gate),
    }));
    collector.attach_fanout(Arc::new(original_fanout));

    let nbi = raw_nbi(
        "raw",
        "127.0.0.1",
        42424,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );

    collector.record(&nbi).await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while entered.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first export should enter the original sink");

    collector.record(&nbi).await;

    let mut replacement_fanout = crate::distributed::EventFanout::new();
    replacement_fanout.add_sink(Box::new(CountingSink {
        sends: Arc::clone(&replacement_delivered),
    }));
    collector.attach_fanout(Arc::new(replacement_fanout));

    gate.add_permits(2);
    collector.flush_distributed().await;

    assert_eq!(original_delivered.load(Ordering::Relaxed), 2);
    assert_eq!(replacement_delivered.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn replacing_sinkful_fanout_does_not_flush_old_fanout_after_backlog_drains() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let original_flushes = Arc::new(AtomicUsize::new(0));
    let replacement_flushes = Arc::new(AtomicUsize::new(0));

    let mut original_fanout = crate::distributed::EventFanout::new();
    original_fanout.add_sink(Box::new(FlushCountingSink {
        flushes: Arc::clone(&original_flushes),
    }));
    collector.attach_fanout(Arc::new(original_fanout));

    let nbi = raw_nbi(
        "raw",
        "127.0.0.1",
        42424,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&nbi).await;

    let mut replacement_fanout = crate::distributed::EventFanout::new();
    replacement_fanout.add_sink(Box::new(FlushCountingSink {
        flushes: Arc::clone(&replacement_flushes),
    }));
    collector.attach_fanout(Arc::new(replacement_fanout));

    collector.flush_distributed().await;
    assert_eq!(original_flushes.load(Ordering::Relaxed), 1);
    assert_eq!(replacement_flushes.load(Ordering::Relaxed), 1);

    collector.flush_distributed().await;
    assert_eq!(original_flushes.load(Ordering::Relaxed), 1);
    assert_eq!(replacement_flushes.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn retired_http_fanout_is_flushed_by_supervisor_without_manual_flush() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let (url, request_count, server) = spawn_http_event_server().await;

    let mut original_fanout = crate::distributed::EventFanout::new();
    original_fanout.add_sink(Box::new(crate::distributed::HttpSink::new(
        url, None, 10, 25, 1_000,
    )));
    collector.attach_fanout(Arc::new(original_fanout));

    let event = raw_nbi(
        "raw",
        "127.0.0.1",
        42424,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&event).await;

    let mut replacement_fanout = crate::distributed::EventFanout::new();
    replacement_fanout.add_sink(Box::new(SlowSink));
    collector.attach_fanout(Arc::new(replacement_fanout));

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while request_count.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retired HTTP fanout should be drained by the supervisor");

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn retired_fanout_without_pending_backlog_does_not_degrade_export_health() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    let mut original_fanout = crate::distributed::EventFanout::new();
    original_fanout.add_sink(Box::new(FailingSink));
    let original_fanout = Arc::new(original_fanout);
    collector.attach_fanout(Arc::clone(&original_fanout));

    let mut replacement_fanout = crate::distributed::EventFanout::new();
    replacement_fanout.add_sink(Box::new(SlowSink));
    let replacement_fanout = Arc::new(replacement_fanout);
    collector.attach_fanout(Arc::clone(&replacement_fanout));

    let _ = original_fanout.flush_all().await;

    let snapshot = runtime_health.snapshot();
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Running
    );
    assert_eq!(snapshot.distributed_export.error, None);
    assert!(!runtime_health.distributed_export_loss_latched());
}

#[tokio::test]
async fn late_runtime_health_attachment_syncs_retired_fanouts() {
    let collector = NbiCollector::new(None).expect("collector should build");

    let mut original_fanout = crate::distributed::EventFanout::new();
    original_fanout.add_sink(Box::new(FailingSink));
    let original_fanout = Arc::new(original_fanout);
    original_fanout.note_queued_record("retired-event");
    collector.attach_fanout(Arc::clone(&original_fanout));

    let mut replacement_fanout = crate::distributed::EventFanout::new();
    replacement_fanout.add_sink(Box::new(SlowSink));
    collector.attach_fanout(Arc::new(replacement_fanout));

    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    let _ = original_fanout.flush_all().await;

    let snapshot = runtime_health.snapshot();
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .distributed_export
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("retired distributed export failed while draining backlog")
    );
}

#[test]
fn detaching_sinkless_fanout_counts_pending_export_loss() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    collector.attach_runtime_health(runtime_health.clone());

    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(SlowSink));
    let fanout = Arc::new(fanout);
    collector.attach_fanout(Arc::clone(&fanout));
    for _ in 0..3 {
        fanout.note_queued_record(&uuid::Uuid::new_v4().to_string());
    }

    collector.attach_fanout(Arc::new(crate::distributed::EventFanout::new()));

    let snapshot = runtime_health.snapshot();
    assert_eq!(snapshot.nbi_collector.export_dropped, 3);
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Degraded
    );
    assert_eq!(
        snapshot.distributed_export.error.as_deref(),
        Some(
            "distributed export lost 3 accepted events while retiring fanout: fanout detached before accepted export events could be drained"
        )
    );
}

#[test]
fn detaching_sinkless_fanout_does_not_hide_worker_loss_under_disabled_state() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    collector.attach_runtime_health(runtime_health.clone());

    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(SlowSink));
    collector.attach_fanout(Arc::new(fanout));
    collector.export_worker.queued.store(1, Ordering::Relaxed);

    collector.attach_fanout(Arc::new(crate::distributed::EventFanout::new()));

    let snapshot = runtime_health.snapshot();
    assert_eq!(snapshot.nbi_collector.export_dropped, 1);
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .distributed_export
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("distributed export lost 1 accepted events while retiring fanout")
    );
}

#[test]
fn attach_runtime_health_replays_prior_export_loss_from_collector_snapshot() {
    let collector = NbiCollector::new(None).expect("collector should build");
    collector.record_shutdown_export_loss(1);

    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    collector.attach_runtime_health(runtime_health.clone());

    let snapshot = runtime_health.snapshot();
    assert_eq!(snapshot.nbi_collector.export_dropped, 1);
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .distributed_export
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("distributed export lost 1 accepted events during shutdown finalization")
    );
}

#[tokio::test]
async fn reconcile_export_worker_interruption_counts_queue_and_fanout_loss_additively() {
    let collector = NbiCollector::new(None).expect("collector should build");
    collector.export_worker.queued.store(3, Ordering::Relaxed);

    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(BufferedFailingSink {
        pending_ids: Arc::new(parking_lot::RwLock::new(HashSet::new())),
    }));
    let fanout = Arc::new(fanout);

    let first = raw_nbi(
        "raw",
        "127.0.0.1",
        44001,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    let second = raw_nbi(
        "raw",
        "127.0.0.1",
        44002,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    let first_id = first.normalized_event_id();
    let second_id = second.normalized_event_id();
    fanout.note_queued_record(&first_id);
    fanout.note_queued_record(&second_id);
    assert!(fanout.send(&first).await.error.is_none());
    assert!(fanout.send(&second).await.error.is_none());
    collector.attach_fanout(Arc::clone(&fanout));

    let interruption = collector.reconcile_export_worker_interruption();

    assert_eq!(interruption.dropped, 5);
    assert_eq!(collector.export_worker.queued.load(Ordering::Relaxed), 0);
    assert_eq!(fanout.pending_events(), 0);
}

#[test]
fn attach_runtime_health_replays_prior_export_rejection_as_degraded() {
    let collector = NbiCollector::new(None).expect("collector should build");
    collector.drop_export_event("pre-health rejection");

    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    collector.attach_runtime_health(runtime_health.clone());

    let snapshot = runtime_health.snapshot();
    assert_eq!(snapshot.nbi_collector.export_dropped, 0);
    assert_eq!(snapshot.nbi_collector.export_rejected, 1);
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .distributed_export
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("distributed export rejected")
    );
    assert!(!runtime_health.distributed_export_loss_latched());
}

#[tokio::test]
async fn attach_runtime_health_replays_prior_buffered_export_failure() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let pending_ids = Arc::new(parking_lot::RwLock::new(HashSet::new()));

    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(BufferedFailingSink {
        pending_ids: Arc::clone(&pending_ids),
    }));
    collector.attach_fanout(Arc::new(fanout));

    let event = raw_nbi(
        "raw",
        "127.0.0.1",
        42425,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&event).await;
    collector.flush_distributed().await;

    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    collector.attach_runtime_health(runtime_health.clone());

    let snapshot = runtime_health.snapshot();
    assert_eq!(snapshot.nbi_collector.export_dropped, 0);
    assert_eq!(snapshot.nbi_collector.export_rejected, 0);
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .distributed_export
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("distributed export previously failed before runtime health attachment")
    );
}

#[test]
fn detaching_sinkless_fanout_counts_buffered_sink_backlog_as_loss() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    collector.attach_runtime_health(runtime_health.clone());

    let pending_ids = Arc::new(parking_lot::RwLock::new(HashSet::from([
        String::from("buffered-a"),
        String::from("buffered-b"),
    ])));
    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(BufferedFailingSink {
        pending_ids: Arc::clone(&pending_ids),
    }));
    collector.attach_fanout(Arc::new(fanout));

    collector.attach_fanout(Arc::new(crate::distributed::EventFanout::new()));

    let snapshot = runtime_health.snapshot();
    assert_eq!(snapshot.nbi_collector.export_dropped, 2);
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .distributed_export
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("distributed export lost 2 accepted events")
    );
}

#[tokio::test]
async fn export_loss_stays_degraded_after_later_success() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(SlowSink));
    let fanout = Arc::new(fanout);
    fanout.attach_runtime_health(runtime_health.clone());
    collector.attach_fanout(Arc::clone(&fanout));

    collector.record_shutdown_export_loss(1);
    let _ = fanout.flush_all().await;

    let snapshot = runtime_health.snapshot();
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Degraded
    );
    assert_eq!(
        snapshot.distributed_export.error.as_deref(),
        Some("distributed export lost 1 accepted events during shutdown finalization")
    );
}

#[tokio::test]
async fn export_worker_crash_clears_fanout_queue_backlog() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let entered = Arc::new(AtomicUsize::new(0));
    let delivered = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(tokio::sync::Semaphore::new(0));

    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(BlockingCountingSink {
        entered: Arc::clone(&entered),
        delivered: Arc::clone(&delivered),
        gate: Arc::clone(&gate),
    }));
    let fanout = Arc::new(fanout);
    collector.attach_fanout(Arc::clone(&fanout));

    let event = raw_nbi(
        "raw",
        "127.0.0.1",
        41000,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&event).await;

    tokio::time::timeout(Duration::from_secs(1), async {
        while entered.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("export worker should start delivering the queued event");

    collector
        .export_worker
        .handle
        .lock()
        .as_ref()
        .expect("export worker handle")
        .abort();

    tokio::time::sleep(Duration::from_millis(NBI_WORKER_SUPERVISOR_INTERVAL_MS * 2)).await;

    assert_eq!(collector.snapshot().export_dropped, 0);
    assert_eq!(collector.snapshot().export_unknown, 1);
    assert_eq!(fanout.pending_events(), 0);
    assert_eq!(delivered.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn export_worker_hot_restart_reconciles_fanout_backlog() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let entered = Arc::new(AtomicUsize::new(0));
    let delivered = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(tokio::sync::Semaphore::new(0));

    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(BlockingCountingSink {
        entered: Arc::clone(&entered),
        delivered: Arc::clone(&delivered),
        gate: Arc::clone(&gate),
    }));
    let fanout = Arc::new(fanout);
    collector.attach_fanout(Arc::clone(&fanout));

    let first_event = raw_nbi(
        "raw",
        "127.0.0.1",
        42000,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&first_event).await;

    tokio::time::timeout(Duration::from_secs(1), async {
        while entered.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("export worker should start delivering the first queued event");

    collector
        .export_worker
        .handle
        .lock()
        .as_ref()
        .expect("export worker handle")
        .abort();

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let finished = collector
                .export_worker
                .handle
                .lock()
                .as_ref()
                .is_some_and(|handle| handle.is_finished());
            if finished {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("aborted export worker should transition to finished");

    let second_event = raw_nbi(
        "raw",
        "127.0.0.1",
        42001,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&second_event).await;

    assert_eq!(collector.snapshot().export_dropped, 0);
    assert_eq!(collector.snapshot().export_unknown, 1);
    assert_eq!(fanout.pending_events(), 1);

    gate.add_permits(1);
    collector.flush_distributed().await;

    assert_eq!(delivered.load(Ordering::Relaxed), 1);
    assert_eq!(fanout.pending_events(), 0);
}

#[tokio::test]
async fn finalize_distributed_shutdown_times_out_inflight_delivery_as_unknown() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let entered = Arc::new(AtomicUsize::new(0));
    let delivered = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(tokio::sync::Semaphore::new(0));

    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(BlockingCountingSink {
        entered: Arc::clone(&entered),
        delivered: Arc::clone(&delivered),
        gate: Arc::clone(&gate),
    }));
    collector.attach_fanout(Arc::new(fanout));

    let event = raw_nbi(
        "raw",
        "127.0.0.1",
        42555,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&event).await;

    tokio::time::timeout(Duration::from_secs(1), async {
        while entered.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("export worker should enter blocking send");

    tokio::time::timeout(
        Duration::from_secs(1),
        collector.finalize_distributed_shutdown(),
    )
    .await
    .expect("shutdown finalization should be bounded by timeout");

    let snapshot = collector.snapshot();
    assert_eq!(snapshot.export_dropped, 0);
    assert_eq!(snapshot.export_unknown, 1);
    assert_eq!(delivered.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn flush_distributed_channel_closed_fallback_flushes_retired_fanouts() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let retired_flushes = Arc::new(AtomicUsize::new(0));
    let pending_ids = Arc::new(parking_lot::RwLock::new(HashSet::from([String::from(
        "retired-flush-event",
    )])));

    let mut original_fanout = crate::distributed::EventFanout::new();
    original_fanout.add_sink(Box::new(BufferedFlushCountingSink {
        flushes: Arc::clone(&retired_flushes),
        pending_ids: Arc::clone(&pending_ids),
    }));
    let original_fanout = Arc::new(original_fanout);
    collector.attach_fanout(Arc::clone(&original_fanout));

    let mut replacement_fanout = crate::distributed::EventFanout::new();
    replacement_fanout.add_sink(Box::new(SlowSink));
    collector.attach_fanout(Arc::new(replacement_fanout));

    collector
        .export_worker
        .rx
        .lock()
        .expect("export worker rx lock")
        .take();
    let fake_handle = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(60)).await;
    });
    *collector.export_worker.handle.lock() = Some(fake_handle);

    collector.flush_distributed().await;

    assert!(retired_flushes.load(Ordering::Relaxed) > 0);

    if let Some(handle) = collector.export_worker.handle.lock().take() {
        handle.abort();
    }
}

#[tokio::test]
async fn finalize_distributed_shutdown_waits_for_retired_flush_completion() {
    let collector = Arc::new(NbiCollector::new(None).expect("collector should build"));
    let flushes = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let pending_ids = Arc::new(parking_lot::RwLock::new(HashSet::new()));

    let mut original_fanout = crate::distributed::EventFanout::new();
    original_fanout.add_sink(Box::new(BlockingBufferedFlushSink {
        flushes: Arc::clone(&flushes),
        gate: Arc::clone(&gate),
        pending_ids: Arc::clone(&pending_ids),
    }));
    let original_fanout = Arc::new(original_fanout);
    collector.attach_fanout(Arc::clone(&original_fanout));

    let event = raw_nbi(
        "raw",
        "127.0.0.1",
        42426,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&event).await;

    tokio::time::timeout(Duration::from_secs(1), async {
        while original_fanout.pending_events() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("original fanout should retain buffered backlog");

    let mut replacement_fanout = crate::distributed::EventFanout::new();
    replacement_fanout.add_sink(Box::new(SlowSink));
    collector.attach_fanout(Arc::new(replacement_fanout));

    let finalize_task = tokio::spawn({
        let collector = Arc::clone(&collector);
        async move {
            collector.finalize_distributed_shutdown().await;
        }
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        while flushes.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown finalization should start draining retired backlog");

    assert!(!finalize_task.is_finished());
    gate.add_permits(1);
    finalize_task
        .await
        .expect("shutdown finalization should complete once flush is unblocked");

    assert_eq!(collector.snapshot().export_dropped, 0);
    assert!(pending_ids.read().is_empty());
    assert_eq!(original_fanout.pending_events(), 0);
}

#[tokio::test]
async fn local_persist_failure_degrades_nbi_pipeline_health() {
    let path = std::env::temp_dir().join(format!("nettrap-nbi-dir-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&path).unwrap();

    let collector = NbiCollector::new(Some(path.clone())).expect("valid NBI path");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    runtime_health.set_distributed_export_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    let nbi = raw_nbi(
        "raw",
        "127.0.0.1",
        42424,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );

    collector.record(&nbi).await;
    collector.flush_all_pending().await;

    let snapshot = runtime_health.snapshot();
    assert_eq!(snapshot.status, nettrap_api::HealthStatus::Degraded);
    assert_eq!(
        snapshot.nbi_pipeline.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .nbi_pipeline
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("local NBI persistence failure")
    );
    assert_eq!(snapshot.nbi_collector.local_persist_failures, 1);
    assert!(
        snapshot
            .nbi_collector
            .last_local_persist_error
            .as_deref()
            .unwrap_or_default()
            .contains("failed to open NBI file")
    );

    let _ = std::fs::remove_dir_all(path);
}

#[cfg(unix)]
#[tokio::test]
async fn local_persist_rejects_symlinked_final_path() {
    let root = std::env::temp_dir().join(format!("nettrap-nbi-link-{}", uuid::Uuid::new_v4()));
    let real_parent = root.join("real");
    std::fs::create_dir_all(&real_parent).unwrap();
    let target = real_parent.join("events.jsonl");
    std::fs::write(&target, "existing\n").unwrap();
    let link = root.join("events.jsonl");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let collector = NbiCollector::new(Some(link.clone())).expect("valid NBI path");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    runtime_health.set_distributed_export_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    let nbi = raw_nbi(
        "raw",
        "127.0.0.1",
        42424,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );

    collector.record(&nbi).await;
    collector.flush_all_pending().await;

    let snapshot = runtime_health.snapshot();
    assert_eq!(
        snapshot.nbi_pipeline.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .nbi_pipeline
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("local NBI persistence failure")
    );
    assert!(
        snapshot
            .nbi_collector
            .last_local_persist_error
            .as_deref()
            .unwrap_or_default()
            .contains("failed to open NBI file")
    );

    let contents = std::fs::read_to_string(&target).expect("read original target");
    assert_eq!(contents, "existing\n");

    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn partial_local_persist_failure_degrades_without_latching_loss() {
    let bad_path =
        std::env::temp_dir().join(format!("nettrap-nbi-partial-dir-{}", uuid::Uuid::new_v4()));
    let db_path = std::env::temp_dir().join(format!(
        "nettrap-nbi-partial-db-{}.db",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&bad_path).unwrap();

    let collector = NbiCollector::new(Some(bad_path.clone())).expect("valid NBI path");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    runtime_health.set_distributed_export_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    let db = Arc::new(DatabaseBackend::Sqlite(
        SqliteStorage::new(&db_path, "test-node", "test-run").unwrap(),
    ));
    collector.attach_database(Arc::clone(&db));

    let nbi = raw_nbi(
        "raw",
        "127.0.0.1",
        42424,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );

    collector.record(&nbi).await;
    collector.flush_all_pending().await;

    let snapshot = runtime_health.snapshot();
    assert_eq!(
        snapshot.nbi_pipeline.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .nbi_pipeline
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("failed to open NBI file")
    );
    assert_eq!(snapshot.nbi_collector.local_persist_failures, 1);
    assert_eq!(db.load_events_for_node("test-node").await.unwrap().len(), 1);

    runtime_health.set_nbi_pipeline_running();
    assert_eq!(
        runtime_health.snapshot().nbi_pipeline.state,
        nettrap_api::ComponentState::Running
    );

    let _ = std::fs::remove_dir_all(&bad_path);
    let _ = std::fs::remove_file(&db_path);
    let _ = std::fs::remove_file(db_path.with_extension("db-wal"));
    let _ = std::fs::remove_file(db_path.with_extension("db-shm"));
}

#[tokio::test]
async fn idle_local_worker_crash_degrades_health_without_new_traffic() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-nbi-idle-local-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let collector = NbiCollector::new(Some(path.clone())).expect("valid NBI path");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    runtime_health.set_distributed_export_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    {
        let handle = collector.local_worker.handle.lock();
        handle.as_ref().expect("local worker").abort();
    }

    tokio::time::sleep(Duration::from_millis(NBI_WORKER_SUPERVISOR_INTERVAL_MS * 2)).await;

    let snapshot = runtime_health.snapshot();
    assert_eq!(snapshot.status, nettrap_api::HealthStatus::Degraded);
    assert_eq!(
        snapshot.nbi_pipeline.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .nbi_pipeline
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("NBI local worker")
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn local_worker_restart_restores_nbi_pipeline_to_running() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-nbi-local-restart-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let collector = NbiCollector::new(Some(path.clone())).expect("valid NBI path");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    runtime_health.set_distributed_export_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    {
        let handle = collector.local_worker.handle.lock();
        handle.as_ref().expect("local worker").abort();
    }

    tokio::time::sleep(Duration::from_millis(NBI_WORKER_SUPERVISOR_INTERVAL_MS * 2)).await;
    assert_eq!(
        runtime_health.snapshot().nbi_pipeline.state,
        nettrap_api::ComponentState::Degraded
    );

    let nbi = raw_nbi(
        "http",
        "127.0.0.1",
        42424,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&nbi).await;
    collector.flush_all_pending().await;

    let snapshot = runtime_health.snapshot();
    assert_eq!(
        snapshot.nbi_pipeline.state,
        nettrap_api::ComponentState::Running
    );
    assert_eq!(snapshot.nbi_pipeline.error, None);

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn idle_export_worker_crash_degrades_health_without_new_traffic() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(SlowSink));
    collector.attach_fanout(Arc::new(fanout));

    let nbi = raw_nbi(
        "http",
        "127.0.0.1",
        42424,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&nbi).await;
    collector.flush_distributed().await;

    {
        let handle = collector.export_worker.handle.lock();
        handle.as_ref().expect("export worker").abort();
    }

    tokio::time::sleep(Duration::from_millis(NBI_WORKER_SUPERVISOR_INTERVAL_MS * 2)).await;

    let snapshot = runtime_health.snapshot();
    assert_eq!(snapshot.status, nettrap_api::HealthStatus::Degraded);
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .distributed_export
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("NBI export worker")
    );
}

#[tokio::test]
async fn retired_fanout_flush_error_with_delivered_event_does_not_latch_loss() {
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();

    let sends = Arc::new(AtomicUsize::new(0));
    let pending_ids = Arc::new(parking_lot::RwLock::new(HashSet::new()));
    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(CountingSink {
        sends: Arc::clone(&sends),
    }));
    fanout.add_sink(Box::new(BufferedFailingSink {
        pending_ids: Arc::clone(&pending_ids),
    }));
    let fanout = Arc::new(fanout);
    fanout.attach_retired_runtime_health(runtime_health.clone());

    let nbi = raw_nbi(
        "raw",
        "127.0.0.1",
        43000,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    let event_id = nbi.normalized_event_id();

    fanout.note_queued_record(&event_id);
    let send_outcome = fanout.send(&nbi).await;
    assert!(send_outcome.error.is_none());
    assert!(!fanout.note_dequeued_record(&event_id).final_loss);
    assert_eq!(sends.load(Ordering::Relaxed), 1);

    let _ = fanout.flush_all().await;

    let snapshot = runtime_health.snapshot();
    assert!(!runtime_health.distributed_export_loss_latched());
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .distributed_export
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("retired distributed export failed while draining backlog")
    );
}

#[tokio::test]
async fn finalize_distributed_shutdown_counts_remaining_buffered_backlog_as_loss() {
    let collector = NbiCollector::new(None).expect("collector should build");
    let runtime_health = Arc::new(nettrap_engine::RuntimeHealth::new());
    runtime_health.register_listener("http", "tcp", 80);
    runtime_health.mark_listener_running("http", 80);
    runtime_health.mark_startup_complete();
    runtime_health.set_api_disabled();
    runtime_health.set_interceptor_disabled();
    collector.attach_runtime_health(runtime_health.clone());

    let pending_ids = Arc::new(parking_lot::RwLock::new(HashSet::new()));
    let mut fanout = crate::distributed::EventFanout::new();
    fanout.add_sink(Box::new(BufferedFailingSink {
        pending_ids: Arc::clone(&pending_ids),
    }));
    collector.attach_fanout(Arc::new(fanout));

    let nbi = raw_nbi(
        "raw",
        "127.0.0.1",
        43100,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );
    collector.record(&nbi).await;

    assert_eq!(collector.snapshot().export_dropped, 0);
    collector.finalize_distributed_shutdown().await;

    let snapshot = runtime_health.snapshot();
    assert_eq!(snapshot.nbi_collector.export_dropped, 1);
    assert_eq!(
        snapshot.distributed_export.state,
        nettrap_api::ComponentState::Degraded
    );
    assert!(
        snapshot
            .distributed_export
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("during shutdown finalization")
    );
}

#[tokio::test]
async fn finalize_distributed_shutdown_reports_worker_task_error() {
    let collector = NbiCollector::new(None).expect("collector should build");

    {
        let mut handle = collector.export_worker.handle.lock();
        *handle = Some(tokio::spawn(async {
            panic!("shutdown boom");
        }));
    }

    collector.finalize_distributed_shutdown().await;

    assert!(collector.worker_restarts.load(Ordering::Relaxed) >= 1);
    assert!(
        collector
            .last_worker_error
            .read()
            .as_deref()
            .is_some_and(|error| error.contains("failed to join shutdown worker"))
    );
}

#[tokio::test]
async fn local_flush_timeout_aborts_stuck_worker() {
    let path = std::env::temp_dir().join(format!(
        "nettrap-nbi-flush-timeout-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let collector = NbiCollector::new(Some(path.clone())).expect("valid NBI path");

    let worker = {
        let mut handle = collector.local_worker.handle.lock();
        handle.take().expect("local worker")
    };
    worker.abort();
    let _ = worker.await;
    let worker_rx = collector
        .local_worker
        .ensure_receiver(NBI_LOCAL_QUEUE_CAPACITY)
        .expect("receiver lock should be available")
        .expect("receiver should be recreated");
    *collector.local_worker.handle.lock() = Some(tokio::spawn(async move {
        let _worker_rx = worker_rx;
        std::future::pending::<()>().await;
    }));

    let started = std::time::Instant::now();
    collector.flush_local().await;

    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert!(collector.local_worker.handle.lock().is_none());
    assert_eq!(collector.snapshot().worker_restarts, 1);
    assert!(
        collector
            .snapshot()
            .last_worker_error
            .as_deref()
            .is_some_and(|error| error.contains("flush timed out"))
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn local_worker_restarts_after_unexpected_exit() {
    let path =
        std::env::temp_dir().join(format!("nettrap-nbi-test-{}.jsonl", uuid::Uuid::new_v4()));
    let collector = NbiCollector::new(Some(path.clone())).expect("valid NBI path");

    {
        let handle = collector.local_worker.handle.lock();
        handle.as_ref().expect("local worker").abort();
    }
    tokio::task::yield_now().await;

    let nbi = raw_nbi(
        "raw",
        "127.0.0.1",
        42424,
        &crate::session::SessionDestination::unknown(8080),
        4,
        "",
    );

    collector.record(&nbi).await;
    collector.flush_all_pending().await;

    let snapshot = collector.snapshot();
    assert!(snapshot.worker_restarts >= 1);
    assert!(snapshot.last_worker_error.is_some());

    let content = tokio::fs::read_to_string(&path).await.unwrap();
    assert!(!content.trim().is_empty());

    let _ = std::fs::remove_file(path);
}
