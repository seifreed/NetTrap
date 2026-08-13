use super::*;
use crate::probe::{
    ProbeServerKind, build_health_response, build_metrics_response, build_ready_response,
    is_transient_accept_error, route_probe_request,
};
use crate::sinks::BufferedHttpEvent;
use nettrap_core::DistributedConfig;
use std::collections::{HashSet, VecDeque};
use std::ffi::OsStr;
#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Equivalent to the binary crate's `nbi::raw_nbi(..)` used by the original
/// tests: `SessionDestination::unknown(8080)` resolves to dst ip "0.0.0.0"
/// port 8080, and `raw_nbi` builds a "RAW" NBI then `add`s "data_length"
/// (and "hexdump" only when the preview is non-empty).
fn raw_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    dst_port: u16,
    data_len: usize,
    hexdump_preview: &str,
) -> nettrap_core::NetworkBehaviorIndicator {
    let mut nbi = nettrap_core::NetworkBehaviorIndicator::new(
        listener, "RAW", src_ip, src_port, "0.0.0.0", dst_port,
    );
    nbi.add("data_length", data_len.to_string());
    if !hexdump_preview.is_empty() {
        nbi.add("hexdump", hexdump_preview);
    }
    nbi
}

fn temp_machine_id_path(prefix: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be monotonic")
        .as_nanos();
    std::env::temp_dir().join(format!("nettrap-{prefix}-{}-{nanos}", std::process::id()))
}

#[test]
fn generate_trims_configured_node_id_and_region() {
    let node = NodeIdentity::generate(
        Some(" node-1 ".to_string()),
        Some(" lab ".to_string()),
        Vec::new(),
    );

    assert_eq!(node.node_id, "node-1");
    assert_eq!(node.region, "lab");
}

#[test]
fn generate_rejects_unicode_whitespace_padding_in_node_id_and_region() {
    let node = NodeIdentity::generate(
        Some("\u{00a0}bad-node-1".to_string()),
        Some("lab\u{2003}".to_string()),
        Vec::new(),
    );

    assert_ne!(node.node_id, "\u{00a0}bad-node-1");
    assert_eq!(node.region, "default");
}

#[test]
fn normalize_fingerprint_component_rejects_unicode_whitespace_padding() {
    assert_eq!(normalize_fingerprint_component("\u{00a0}host"), None);
    assert_eq!(normalize_fingerprint_component("host\u{2003}"), None);
    assert_eq!(normalize_fingerprint_component(" host "), Some("host"));
}

#[test]
fn resolve_node_id_rejects_unicode_whitespace_hostname_padding() {
    let resolved = resolve_node_id(None, Some("\u{00a0}host"));

    assert_ne!(resolved, "\u{00a0}host");
}

#[test]
fn resolve_node_id_rejects_multiple_trailing_dots_hostname() {
    let resolved = resolve_node_id(None, Some("host..."));

    assert_ne!(resolved, "host");
}

#[test]
fn machine_id_reader_accepts_content_at_limit() {
    let path = temp_machine_id_path("machine-id-at-limit");
    std::fs::write(&path, "abcd").expect("write fixture");

    let value = read_machine_id_file(&path, 4).expect("content at limit should load");

    assert_eq!(value, "abcd");
    let _ = std::fs::remove_file(path);
}

#[test]
fn machine_id_reader_rejects_content_past_limit() {
    let path = temp_machine_id_path("machine-id-over-limit");
    std::fs::write(&path, "abcde").expect("write fixture");

    let err = read_machine_id_file(&path, 4).expect_err("oversized content should fail");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("exceeds read limit"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn machine_id_reader_rejects_unrepresentable_sentinel_limit() {
    let path = temp_machine_id_path("machine-id-overflow-limit");
    std::fs::write(&path, "").expect("write fixture");

    let err =
        read_machine_id_file(&path, u64::MAX).expect_err("overflowing sentinel limit should fail");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("read limit is too large"));
    let _ = std::fs::remove_file(path);
}

#[cfg(unix)]
#[test]
fn generate_falls_back_for_non_utf8_hostname() {
    let hostname = OsString::from_vec(b"node-\xff".to_vec());

    assert_eq!(resolve_hostname_label(&hostname), "unknown");
}

#[test]
fn resolve_hostname_label_accepts_absolute_hostnames_with_trailing_dots() {
    assert_eq!(
        resolve_hostname_label(OsStr::new("node.example.")),
        "node.example"
    );
}

#[test]
fn resolve_hostname_label_canonicalizes_hostname_case() {
    assert_eq!(
        resolve_hostname_label(OsStr::new("NODE.EXAMPLE.")),
        resolve_hostname_label(OsStr::new("node.example"))
    );
}

#[test]
fn resolve_hostname_label_rejects_multiple_trailing_dots() {
    assert_eq!(
        resolve_hostname_label(OsStr::new("node.example...")),
        "unknown"
    );
}

#[test]
fn resolve_node_id_accepts_absolute_hostnames_with_trailing_dots() {
    assert_eq!(resolve_node_id(None, Some("node.example.")), "node.example");
}

#[test]
fn resolve_node_id_canonicalizes_hostname_case() {
    assert_eq!(
        resolve_node_id(None, Some("NODE.EXAMPLE.")),
        resolve_node_id(None, Some("node.example"))
    );
}

#[test]
fn generate_falls_back_to_default_region_when_blank() {
    let node = NodeIdentity::generate(None, Some("   ".to_string()), Vec::new());

    assert_eq!(node.region, "default");
}

#[test]
fn generate_with_now_uses_the_injected_clock_for_started_at() {
    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant")
    }

    let node = NodeIdentity::generate_with_now(None, None, Vec::new(), fixed_now);

    assert_eq!(node.started_at, "2024-01-01T00:00:00+00:00");
}

#[test]
fn heartbeat_endpoint_url_joins_path_without_double_slashes() {
    let url = heartbeat_endpoint_url("https://control.example.test/").expect("valid URL");

    assert_eq!(
        url.as_str(),
        "https://control.example.test/api/v1/heartbeat"
    );
}

#[test]
fn heartbeat_endpoint_url_preserves_control_plane_path_prefix() {
    let url = heartbeat_endpoint_url("https://control.example.test/control").expect("valid URL");

    assert_eq!(
        url.as_str(),
        "https://control.example.test/control/api/v1/heartbeat"
    );
}

#[test]
fn heartbeat_endpoint_url_rejects_non_http_scheme() {
    let err = heartbeat_endpoint_url("file:///tmp/control")
        .expect_err("non-http control plane URL should fail");

    assert!(err.to_string().contains("unsupported scheme 'file'"));
}

struct BufferedCountSink {
    pending_ids: Arc<Mutex<HashSet<String>>>,
}

struct BufferedSink {
    pending_ids: Arc<Mutex<HashSet<String>>>,
}

struct UnknownSink;

struct UnknownIdSink {
    unknown_ids: Arc<Mutex<Vec<String>>>,
}

struct ErrorSink;

#[async_trait::async_trait]
impl EventSink for BufferedCountSink {
    async fn send(&self, _event: &nettrap_core::NetworkBehaviorIndicator) -> SinkSendResult {
        SinkSendResult::delivered()
    }

    async fn flush(&self) -> std::result::Result<(), String> {
        self.pending_ids.lock().expect("lock buffered ids").clear();
        Ok(())
    }

    fn name(&self) -> &'static str {
        "buffered-count"
    }

    fn buffered_events(&self) -> usize {
        self.pending_ids.lock().expect("lock buffered ids").len()
    }

    fn buffered_event_ids(&self) -> Vec<String> {
        self.pending_ids
            .lock()
            .expect("lock buffered ids")
            .iter()
            .cloned()
            .collect()
    }
}

#[async_trait::async_trait]
impl EventSink for BufferedSink {
    async fn send(&self, event: &nettrap_core::NetworkBehaviorIndicator) -> SinkSendResult {
        self.pending_ids
            .lock()
            .expect("lock buffered ids")
            .insert(event.normalized_event_id());
        SinkSendResult::buffered(None)
    }

    async fn flush(&self) -> std::result::Result<(), String> {
        self.pending_ids.lock().expect("lock buffered ids").clear();
        Ok(())
    }

    fn name(&self) -> &'static str {
        "buffered"
    }

    fn buffered_events(&self) -> usize {
        self.pending_ids.lock().expect("lock buffered ids").len()
    }

    fn buffered_event_ids(&self) -> Vec<String> {
        self.pending_ids
            .lock()
            .expect("lock buffered ids")
            .iter()
            .cloned()
            .collect()
    }
}

#[async_trait::async_trait]
impl EventSink for UnknownSink {
    async fn send(&self, _event: &nettrap_core::NetworkBehaviorIndicator) -> SinkSendResult {
        SinkSendResult::unknown("test unknown delivery")
    }

    async fn flush(&self) -> std::result::Result<(), String> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "unknown"
    }
}

#[async_trait::async_trait]
impl EventSink for UnknownIdSink {
    async fn send(&self, _event: &nettrap_core::NetworkBehaviorIndicator) -> SinkSendResult {
        SinkSendResult::delivered()
    }

    async fn flush(&self) -> std::result::Result<(), String> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "unknown-id"
    }

    fn take_unknown_event_ids(&self) -> Vec<String> {
        self.unknown_ids
            .lock()
            .expect("lock unknown ids")
            .drain(..)
            .collect()
    }
}

#[async_trait::async_trait]
impl EventSink for ErrorSink {
    async fn send(&self, _event: &nettrap_core::NetworkBehaviorIndicator) -> SinkSendResult {
        SinkSendResult::lost("test failure")
    }

    async fn flush(&self) -> std::result::Result<(), String> {
        Ok(())
    }

    fn name(&self) -> &'static str {
        "error"
    }
}

fn test_node() -> NodeIdentity {
    NodeIdentity {
        node_id: "node-1".into(),
        hostname: "host-1".into(),
        region: "lab".into(),
        tags: vec![],
        started_at: "2026-04-03T00:00:00Z".into(),
    }
}

async fn spawn_heartbeat_server(statuses: Vec<u16>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let addr = listener.local_addr().expect("local addr");
    let statuses = Arc::new(Mutex::new(VecDeque::from(statuses)));
    let task = tokio::spawn({
        let statuses = Arc::clone(&statuses);
        async move {
            loop {
                let (mut stream, _) = listener.accept().await.expect("accept request");
                let statuses = Arc::clone(&statuses);
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let status = {
                        let mut statuses = statuses.lock().expect("lock statuses");
                        if statuses.len() > 1 {
                            statuses.pop_front().expect("status entry")
                        } else {
                            *statuses.front().unwrap_or(&200)
                        }
                    };
                    let reason = if status == 200 {
                        "OK"
                    } else {
                        "Internal Server Error"
                    };
                    let body = "{}";
                    let response = format!(
                        "HTTP/1.1 {} {}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                        status,
                        reason,
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        }
    });

    (format!("http://{}", addr), task)
}

async fn spawn_hanging_heartbeat_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let addr = listener.local_addr().expect("local addr");
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept request");
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).await;
        std::future::pending::<()>().await;
    });

    (format!("http://{}", addr), task)
}

async fn spawn_event_sink_server() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind event sink server");
    let addr = listener.local_addr().expect("local addr");
    let request_count = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
        let request_count = Arc::clone(&request_count);
        async move {
            loop {
                let (mut stream, _) = listener.accept().await.expect("accept request");
                let request_count = Arc::clone(&request_count);
                tokio::spawn(async move {
                    let _ = read_http_request(&mut stream).await;
                    request_count.fetch_add(1, Ordering::Relaxed);
                    let body = "{}";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
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

async fn spawn_partially_failing_event_sink_server(
    failing_src_port: u16,
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind partial failure event sink server");
    let addr = listener.local_addr().expect("local addr");
    let request_count = Arc::new(AtomicUsize::new(0));
    let failed_target_once = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let task = tokio::spawn({
        let request_count = Arc::clone(&request_count);
        let failed_target_once = Arc::clone(&failed_target_once);
        async move {
            loop {
                let (mut stream, _) = listener.accept().await.expect("accept request");
                let request_count = Arc::clone(&request_count);
                let failed_target_once = Arc::clone(&failed_target_once);
                tokio::spawn(async move {
                    let request = read_http_request(&mut stream).await;
                    request_count.fetch_add(1, Ordering::Relaxed);
                    let request = String::from_utf8_lossy(&request);
                    let target_port = format!("\"src_port\":{}", failing_src_port);
                    let should_fail = request.contains(&target_port)
                        && !failed_target_once.swap(true, Ordering::Relaxed);
                    let status = if should_fail {
                        "500 Internal Server Error"
                    } else {
                        "200 OK"
                    };
                    let body = "{}";
                    let response = format!(
                        "HTTP/1.1 {}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                        status,
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

async fn read_http_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    const MAX_HTTP_REQUEST_BYTES: usize = 64 * 1024;
    while let Ok(read) = stream.read(&mut chunk).await {
        if read == 0 {
            break;
        }
        let remaining = MAX_HTTP_REQUEST_BYTES.saturating_sub(request.len());
        if remaining == 0 {
            break;
        }
        let to_copy = read.min(remaining);
        request.extend_from_slice(&chunk[..to_copy]);
        if http_request_is_complete(&request) || request.len() >= MAX_HTTP_REQUEST_BYTES {
            break;
        }
    }
    request
}

fn http_request_is_complete(request: &[u8]) -> bool {
    let Some(header_end) = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
    else {
        return false;
    };

    let headers = String::from_utf8_lossy(&request[..header_end]);
    let mut content_length = None;
    for (line_index, line) in headers.split("\r\n").enumerate() {
        if line_index == 0 {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }

        let value = value.trim_matches([' ', '\t']);
        if value.is_empty()
            || value
                .chars()
                .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
        {
            return false;
        }

        let Ok(parsed) = value.parse::<usize>() else {
            return false;
        };
        content_length = Some(parsed);
        break;
    }

    let content_length = content_length.unwrap_or(0);
    header_end
        .checked_add(content_length)
        .is_some_and(|expected_len| request.len() >= expected_len)
}

async fn spawn_hanging_event_sink_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind hanging event sink server");
    let addr = listener.local_addr().expect("local addr");
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            });
        }
    });

    (format!("http://{}", addr), task)
}

async fn wait_for_request_count(request_count: &AtomicUsize, expected: usize, context: &str) {
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while request_count.load(Ordering::Relaxed) < expected {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;

    assert!(
        result.is_ok(),
        "{context}: expected at least {expected} requests, observed {}",
        request_count.load(Ordering::Relaxed)
    );
}

#[test]
fn distributed_health_uses_runtime_health_payload() {
    let node = test_node();
    let runtime_health = nettrap_api::RuntimeHealth::new();
    runtime_health.register_listener("dns", "udp", 53);
    runtime_health.mark_listener_failed("dns", "bind failed");

    let body = build_health_response(&node, &runtime_health);
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    assert_eq!(json["status"], "error");
    assert_eq!(json["fatal_error"], "bind failed");
    assert_eq!(json["listeners"][0]["name"], "dns");
    assert_eq!(json["node_id"], "node-1");
}

#[test]
fn distributed_ready_and_metrics_follow_runtime_health() {
    let node = test_node();
    let runtime_health = nettrap_api::RuntimeHealth::new();

    assert_eq!(build_ready_response(false), r#"{"ready":false}"#);
    assert!(build_metrics_response(&node, &runtime_health).contains("nettrap_up 0"));

    runtime_health.register_listener("dns", "udp", 53);
    runtime_health.mark_listener_running("dns", 53);
    runtime_health.mark_startup_complete();
    runtime_health.set_interceptor_disabled();
    runtime_health.set_api_disabled();

    assert_eq!(build_ready_response(true), r#"{"ready":true}"#);
    assert!(build_metrics_response(&node, &runtime_health).contains("nettrap_up 1"));
}

#[test]
fn http_request_is_complete_accepts_obs_text_bytes_in_header_values() {
    let request = b"GET /health HTTP/1.1\r\nX-Test: hello\xe2\x80\xa8world\r\n\r\n";

    assert!(http_request_is_complete(request));
}

#[test]
fn metrics_labels_escape_configured_identity_values() {
    let mut node = test_node();
    node.node_id = "node\"one\\two\nnettrap_up 99".to_string();
    node.hostname = "host\rname".to_string();
    node.region = "lab\"} 1\nnettrap_info{node_id=\"fake\"}".to_string();
    let runtime_health = nettrap_api::RuntimeHealth::new();

    let body = build_metrics_response(&node, &runtime_health);
    let info_lines = body
        .lines()
        .filter(|line| line.starts_with("nettrap_info{"))
        .collect::<Vec<_>>();

    assert_eq!(info_lines.len(), 1);
    assert!(info_lines[0].contains(r#"node_id="node\"one\\two\nnettrap_up 99""#));
    assert!(info_lines[0].contains(r#"hostname="host\nname""#));
    assert!(info_lines[0].contains(r#"region="lab\"} 1\nnettrap_info{node_id=\"fake\"}""#));
}

#[test]
fn ready_endpoint_uses_503_until_runtime_is_ready() {
    let node = test_node();
    let runtime_health = nettrap_api::RuntimeHealth::new();

    let (status, content_type, body) = route_probe_request(
        "GET /ready HTTP/1.1\r\n\r\n",
        &node,
        &runtime_health,
        ProbeServerKind::Health,
    );
    assert_eq!(status, "503 Service Unavailable");
    assert_eq!(content_type, "application/json");
    assert_eq!(body, r#"{"ready":false}"#);
}

#[test]
fn health_and_metrics_servers_expose_only_their_own_routes() {
    let node = test_node();
    let runtime_health = nettrap_api::RuntimeHealth::new();
    runtime_health.register_listener("dns", "udp", 53);
    runtime_health.mark_listener_running("dns", 53);
    runtime_health.mark_startup_complete();
    runtime_health.set_interceptor_disabled();
    runtime_health.set_api_disabled();

    let (status, content_type, body) = route_probe_request(
        "GET /metrics HTTP/1.1\r\n\r\n",
        &node,
        &runtime_health,
        ProbeServerKind::Health,
    );
    assert_eq!(status, "404 Not Found");
    assert_eq!(content_type, "text/plain");
    assert_eq!(body, "Not Found");

    let (status, content_type, body) = route_probe_request(
        "GET /metrics HTTP/1.1\r\n\r\n",
        &node,
        &runtime_health,
        ProbeServerKind::Metrics,
    );
    assert_eq!(status, "200 OK");
    assert_eq!(content_type, "text/plain; version=0.0.4");
    assert!(body.contains("nettrap_up 1"));

    let (status, _, _) = route_probe_request(
        "GET /health HTTP/1.1\r\n\r\n",
        &node,
        &runtime_health,
        ProbeServerKind::Metrics,
    );
    assert_eq!(status, "404 Not Found");
}

#[test]
fn probe_routing_matches_exact_paths_only() {
    let node = test_node();
    let runtime_health = nettrap_api::RuntimeHealth::new();

    let (status, _, _) = route_probe_request(
        "GET /healthz HTTP/1.1\r\n\r\n",
        &node,
        &runtime_health,
        ProbeServerKind::Health,
    );
    assert_eq!(status, "404 Not Found");

    let (status, _, _) = route_probe_request(
        "GET /readyz HTTP/1.1\r\n\r\n",
        &node,
        &runtime_health,
        ProbeServerKind::Health,
    );
    assert_eq!(status, "404 Not Found");

    let (status, _, _) = route_probe_request(
        "POST /health HTTP/1.1\r\n\r\n",
        &node,
        &runtime_health,
        ProbeServerKind::Health,
    );
    assert_eq!(status, "404 Not Found");
}

#[test]
fn http_request_is_complete_rejects_unicode_whitespace_padded_content_length() {
    let request = b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: \xC2\xA05\xE2\x80\x83\r\n\r\nhello";

    assert!(!http_request_is_complete(request));
}

#[test]
fn http_request_is_complete_accepts_requests_without_content_length() {
    let request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";

    assert!(http_request_is_complete(request));
}

#[test]
fn http_request_is_complete_rejects_overflowing_content_length() {
    let request = format!(
        "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
        usize::MAX
    );

    assert!(!http_request_is_complete(request.as_bytes()));
}

#[tokio::test]
async fn read_http_request_caps_buffer_growth_at_maximum_size() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept client");
        read_http_request(&mut stream).await.len()
    });

    let mut client = TcpStream::connect(addr).await.expect("connect client");
    let payload = vec![b'a'; 70 * 1024];
    client.write_all(&payload).await.expect("write payload");
    client.shutdown().await.expect("shutdown client");

    assert_eq!(server.await.expect("join server"), 64 * 1024);
}

#[test]
fn build_event_fanout_rejects_unknown_sink_types() {
    let mut config = DistributedConfig::default();
    config.event_sinks.push(nettrap_core::EventSinkConfig {
        sink_type: "bogus".to_string(),
        target: "127.0.0.1:1".to_string(),
        auth: None,
        batch_size: 1,
        flush_interval_ms: 1000,
        request_timeout_ms: 1000,
    });

    let err = match build_event_fanout(&config) {
        Ok(_) => panic!("unknown sink should fail"),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("Unknown distributed event sink type")
    );
}

#[test]
fn build_event_fanout_rejects_invalid_sink_targets() {
    for (sink_type, target, expected) in [
        ("http", "not-a-url", "Invalid distributed HTTP sink target"),
        ("tcp", " ", "Invalid distributed TCP sink target"),
        (
            "tcp",
            "collector.example:0",
            "Invalid distributed TCP sink target",
        ),
        ("tcp", "127.0.0.1:0", "Invalid distributed TCP sink target"),
        (
            "syslog",
            "collector.example:0",
            "Invalid distributed syslog sink target",
        ),
        (
            "syslog",
            "[::1]:0",
            "Invalid distributed syslog sink target",
        ),
    ] {
        let mut config = DistributedConfig::default();
        config.event_sinks.push(nettrap_core::EventSinkConfig {
            sink_type: sink_type.to_string(),
            target: target.to_string(),
            auth: None,
            batch_size: 1,
            flush_interval_ms: 1000,
            request_timeout_ms: 1000,
        });

        let err = match build_event_fanout(&config) {
            Ok(_) => panic!("invalid sink target should fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains(expected),
            "unexpected error for {sink_type} target {target:?}: {err}"
        );
    }
}

#[test]
fn build_event_fanout_rejects_unicode_whitespace_padded_sink_targets() {
    for (sink_type, target, expected) in [
        (
            "http",
            "\u{00a0}https://example.test/events",
            "Invalid distributed HTTP sink target",
        ),
        (
            "tcp",
            "\u{2003}127.0.0.1:9000",
            "Invalid distributed TCP sink target",
        ),
    ] {
        let mut config = DistributedConfig::default();
        config.event_sinks.push(nettrap_core::EventSinkConfig {
            sink_type: sink_type.to_string(),
            target: target.to_string(),
            auth: None,
            batch_size: 1,
            flush_interval_ms: 1000,
            request_timeout_ms: 1000,
        });

        let err = match build_event_fanout(&config) {
            Ok(_) => panic!("unicode-whitespace padded sink target should fail"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains(expected),
            "unexpected error for {sink_type} target {target:?}: {err}"
        );
    }
}

#[test]
fn attach_runtime_health_marks_configured_export_running() {
    let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
    let mut fanout = EventFanout::new();
    fanout.add_sink(Box::new(SyslogUdpSink::new("127.0.0.1:1")));

    fanout.attach_runtime_health(runtime_health.clone());

    assert_eq!(
        runtime_health.snapshot().distributed_export.state,
        nettrap_api::ComponentState::Running
    );
}

#[tokio::test]
async fn clear_runtime_health_resets_latched_failure_before_next_attachment() {
    let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
    let mut fanout = EventFanout::new();
    fanout.add_sink(Box::new(ErrorSink));
    fanout.attach_runtime_health(runtime_health);

    let event = raw_nbi("raw", "127.0.0.1", 12400, 8080, 4, "");
    let _ = fanout.send(&event).await;

    fanout.clear_runtime_health();

    let refreshed_health = Arc::new(nettrap_api::RuntimeHealth::new());
    fanout.attach_runtime_health(refreshed_health.clone());

    assert_eq!(
        refreshed_health.snapshot().distributed_export.state,
        nettrap_api::ComponentState::Running
    );
}

#[test]
fn pending_events_counts_logical_backlog_once_across_buffered_sinks() {
    let left = Arc::new(Mutex::new(HashSet::from([String::from("event-a")])));
    let right = Arc::new(Mutex::new(HashSet::from([String::from("event-a")])));
    let mut fanout = EventFanout::new();
    fanout.add_sink(Box::new(BufferedCountSink {
        pending_ids: Arc::clone(&left),
    }));
    fanout.add_sink(Box::new(BufferedCountSink {
        pending_ids: Arc::clone(&right),
    }));

    assert_eq!(fanout.pending_events(), 1);

    fanout.note_queued_record("event-b");
    assert_eq!(fanout.pending_events(), 2);
}

#[test]
fn pending_events_counts_union_of_distinct_buffered_subsets() {
    let left = Arc::new(Mutex::new(HashSet::from([String::from("event-a")])));
    let right = Arc::new(Mutex::new(HashSet::from([String::from("event-b")])));
    let mut fanout = EventFanout::new();
    fanout.add_sink(Box::new(BufferedCountSink {
        pending_ids: Arc::clone(&left),
    }));
    fanout.add_sink(Box::new(BufferedCountSink {
        pending_ids: Arc::clone(&right),
    }));

    assert_eq!(fanout.pending_events(), 2);
}

#[tokio::test]
async fn reported_unknown_send_record_is_pruned() {
    let mut fanout = EventFanout::new();
    fanout.add_sink(Box::new(UnknownSink));
    let event = raw_nbi("raw", "127.0.0.1", 12400, 8080, 4, "");
    let event_id = event.normalized_event_id();

    fanout.note_queued_record(&event_id);
    fanout.note_send_started(&event_id);
    let _ = fanout.send(&event).await;
    let completion = fanout.note_dequeued_record(&event_id);

    assert!(completion.became_unknown);
    assert!(!completion.final_loss);
    assert!(fanout.pending_records.lock().is_empty());
}

#[tokio::test]
async fn delivered_send_record_is_pruned_without_waiting_for_flush() {
    let pending_ids = Arc::new(Mutex::new(HashSet::new()));
    let mut fanout = EventFanout::new();
    fanout.add_sink(Box::new(BufferedCountSink {
        pending_ids: Arc::clone(&pending_ids),
    }));
    let event = raw_nbi("raw", "127.0.0.1", 12401, 8080, 4, "");

    let outcome = fanout.send(&event).await;

    assert_eq!(outcome.error, None);
    assert!(fanout.pending_records.lock().is_empty());
}

#[tokio::test]
async fn unknown_sink_does_not_clear_other_buffered_sinks() {
    let pending_ids = Arc::new(Mutex::new(HashSet::new()));
    let mut fanout = EventFanout::new();
    fanout.add_sink(Box::new(BufferedSink {
        pending_ids: Arc::clone(&pending_ids),
    }));
    fanout.add_sink(Box::new(UnknownSink));
    let event = raw_nbi("raw", "127.0.0.1", 12402, 8080, 4, "");
    let event_id = event.normalized_event_id();

    let outcome = fanout.send(&event).await;

    assert!(outcome.error.is_some());
    assert!(fanout.has_pending_event(&event_id));
    assert_eq!(fanout.pending_events(), 1);
    assert_eq!(fanout.pending_records.lock().len(), 1);
    assert!(
        pending_ids
            .lock()
            .expect("lock buffered ids")
            .contains(&event_id)
    );
}

#[test]
fn reported_inflight_unknown_record_is_pruned() {
    let fanout = EventFanout::new();
    fanout.note_queued_record("event-a");
    fanout.note_send_started("event-a");

    assert_eq!(fanout.mark_inflight_unknown(), 1);

    assert!(fanout.pending_records.lock().is_empty());
}

#[test]
fn reported_unknown_sink_event_is_pruned() {
    let unknown_ids = Arc::new(Mutex::new(vec![String::from("event-a")]));
    let mut fanout = EventFanout::new();
    fanout.add_sink(Box::new(UnknownIdSink {
        unknown_ids: Arc::clone(&unknown_ids),
    }));

    assert_eq!(fanout.consume_unknown_sink_events(), 1);

    assert!(fanout.pending_records.lock().is_empty());
}

#[tokio::test]
async fn http_sink_flushes_stale_batch_by_time() {
    let (url, request_count, server) = spawn_event_sink_server().await;
    let sink = HttpSink::new(url, None, 10, 25, 1_000);
    let event = raw_nbi("raw", "127.0.0.1", 12345, 8080, 4, "");

    let result = sink.send(&event).await;
    assert_eq!(result.state, SinkDeliveryState::Buffered);
    assert_eq!(result.error, None);
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    assert!(
        sink.flush_stale()
            .await
            .expect("stale flush should succeed")
    );

    wait_for_request_count(&request_count, 1, "HTTP sink should flush stale batch").await;
    assert_eq!(sink.buffered_events(), 0);

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn http_sink_retries_only_failed_events_after_partial_batch_failure() {
    let (url, request_count, server) = spawn_partially_failing_event_sink_server(12009).await;
    let sink = HttpSink::new(url, None, 10, 1_000, 1_000);

    for idx in 0..9 {
        let event = raw_nbi("raw", "127.0.0.1", 12000 + idx, 8080, 4, "");
        let result = sink.send(&event).await;
        assert_eq!(result.state, SinkDeliveryState::Buffered);
        assert_eq!(result.error, None);
    }

    let failing_event = raw_nbi("raw", "127.0.0.1", 12009, 8080, 4, "");
    let result = sink.send(&failing_event).await;
    assert!(
        result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("responded with 500")
    );

    wait_for_request_count(
        &request_count,
        10,
        "HTTP sink should attempt the full initial batch",
    )
    .await;
    assert_eq!(sink.buffered_events(), 1);

    sink.flush()
        .await
        .expect("retry should send only the failed event");
    wait_for_request_count(
        &request_count,
        11,
        "HTTP sink should retry only the failed event",
    )
    .await;
    assert_eq!(sink.buffered_events(), 0);

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn http_sink_request_timeout_marks_delivery_unknown() {
    let (url, server) = spawn_hanging_event_sink_server().await;
    let sink = HttpSink::new(url, None, 1, 1_000, 25);
    let event = raw_nbi("raw", "127.0.0.1", 12500, 8080, 4, "");
    let event_id = event.normalized_event_id();

    let result = sink.send(&event).await;

    assert_eq!(result.state, SinkDeliveryState::Unknown);
    assert_eq!(sink.buffered_events(), 0);
    assert!(
        sink.take_unknown_event_ids().is_empty(),
        "direct Unknown result should consume {event_id} to avoid duplicate reporting"
    );

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn http_sink_rejects_new_events_when_failure_buffer_is_full() {
    let sink = HttpSink::new("http://127.0.0.1:1", None, 10, 1_000, 1_000);
    let buffered_ids = (0..HTTP_SINK_MAX_BUFFERED_EVENTS)
        .map(|idx| format!("buffered-{idx}"))
        .collect::<Vec<_>>();
    {
        let mut state = sink.state.lock();
        state.batch = buffered_ids
            .iter()
            .enumerate()
            .map(|(sequence, event_id)| BufferedHttpEvent {
                sequence: sequence as u64,
                event_id: event_id.clone(),
                json: "{}".to_string(),
                enqueued_at: tokio::time::Instant::now(),
            })
            .collect();
        state.oldest_event_at = Some(tokio::time::Instant::now());
        sink.pending.store(state.batch.len(), Ordering::Relaxed);
        *sink.pending_event_ids.write() = buffered_ids.into_iter().collect();
    }
    let event = raw_nbi("raw", "127.0.0.1", 12600, 8080, 4, "");
    let event_id = event.normalized_event_id();

    let result = sink.send(&event).await;

    assert_eq!(result.state, SinkDeliveryState::Lost);
    assert!(
        result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("buffer full")
    );
    assert_eq!(sink.buffered_events(), HTTP_SINK_MAX_BUFFERED_EVENTS);
    assert!(!sink.buffered_event_ids().contains(&event_id));
}

#[tokio::test]
async fn http_sink_rejects_oversized_events_before_buffering() {
    let sink = HttpSink::new("http://127.0.0.1:1", None, 10, 1_000, 1_000);
    let mut event = raw_nbi("raw", "127.0.0.1", 12601, 8080, 4, "");
    event.indicators.insert(
        "payload".to_string(),
        "a".repeat(HTTP_SINK_MAX_EVENT_BYTES + 1),
    );

    let result = sink.send(&event).await;

    assert_eq!(result.state, SinkDeliveryState::Lost);
    assert!(
        result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("event payload too large")
    );
    assert_eq!(sink.buffered_events(), 0);
    assert!(sink.buffered_event_ids().is_empty());
}

#[tokio::test]
async fn tcp_sink_rejects_oversized_events_before_connecting() {
    let sink = TcpSink::new("127.0.0.1:1");
    let mut event = raw_nbi("raw", "127.0.0.1", 12602, 5044, 4, "");
    event.indicators.insert(
        "payload".to_string(),
        "a".repeat(TCP_SINK_MAX_EVENT_BYTES + 1),
    );

    let result = sink.send(&event).await;

    assert_eq!(result.state, SinkDeliveryState::Lost);
    assert!(
        result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("TCP sink event payload too large")
    );
}

#[tokio::test]
async fn syslog_udp_sink_rejects_oversized_datagrams_before_send() {
    let sink = SyslogUdpSink::new("127.0.0.1:1");
    let mut event = raw_nbi("raw", "127.0.0.1", 12603, 514, 4, "");
    event.indicators.insert(
        "payload".to_string(),
        "a".repeat(SYSLOG_UDP_MAX_DATAGRAM_BYTES + 1),
    );

    let result = sink.send(&event).await;

    assert_eq!(result.state, SinkDeliveryState::Lost);
    assert!(
        result
            .error
            .as_deref()
            .unwrap_or_default()
            .contains("Syslog UDP event payload too large")
    );
}

#[test]
fn transient_probe_accept_errors_are_retryable_until_limit() {
    let err = std::io::Error::from(std::io::ErrorKind::WouldBlock);
    assert!(is_transient_accept_error(&err));

    let err = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
    assert!(!is_transient_accept_error(&err));
}

#[test]
fn heartbeat_payload_uses_the_injected_clock() {
    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant")
    }

    let node = test_node();
    let payload = heartbeat_payload(&node, fixed_now);

    assert_eq!(payload["timestamp"], "2024-01-01T00:00:00+00:00");
    assert_eq!(payload["node_id"], "node-1");
    assert_eq!(payload["hostname"], "host-1");
}

#[tokio::test]
async fn heartbeat_returns_error_after_three_consecutive_failures() {
    let (control_url, server) = spawn_heartbeat_server(vec![500, 500, 500]).await;
    let node = Arc::new(test_node());

    let err = run_heartbeat_with_interval(
        control_url,
        None,
        node,
        std::time::Duration::from_millis(10),
        HEARTBEAT_FAILURE_LIMIT,
        std::time::Duration::from_secs(1),
        chrono::Utc::now,
    )
    .await
    .expect_err("heartbeat should fail after three misses");

    assert!(err.to_string().contains("3 consecutive"));

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn heartbeat_resets_failure_counter_after_success() {
    let (control_url, server) = spawn_heartbeat_server(vec![500, 500, 200, 200]).await;
    let node = Arc::new(test_node());

    let result = tokio::time::timeout(
        std::time::Duration::from_millis(80),
        run_heartbeat_with_interval(
            control_url,
            None,
            node,
            std::time::Duration::from_millis(10),
            HEARTBEAT_FAILURE_LIMIT,
            std::time::Duration::from_secs(1),
            chrono::Utc::now,
        ),
    )
    .await;

    assert!(
        result.is_err(),
        "heartbeat should keep running after a reset"
    );

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn heartbeat_returns_error_when_control_plane_stalls() {
    let (control_url, server) = spawn_hanging_heartbeat_server().await;
    let node = Arc::new(test_node());

    let err = run_heartbeat_with_interval(
        control_url,
        None,
        node,
        std::time::Duration::from_millis(10),
        1,
        std::time::Duration::from_millis(10),
        chrono::Utc::now,
    )
    .await
    .expect_err("stalled heartbeat request should fail after timeout");

    assert!(err.to_string().contains("request timed out"));

    server.abort();
    let _ = server.await;
}
