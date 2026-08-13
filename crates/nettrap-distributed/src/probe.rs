//! Probe servers (health, readiness, and Prometheus metrics HTTP endpoints).

use crate::{Error, NodeIdentity, Result};
use nettrap_core::health::{HealthSink, HealthStatus, runtime_health_payload};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeServerKind {
    Health,
    Metrics,
}

const PROBE_ACCEPT_RETRY_LIMIT: u32 = 3;
const PROBE_ACCEPT_RETRY_DELAY_MS: u64 = 250;
const PROBE_CONNECTION_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const PROBE_CONNECTION_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const PROBE_REQUEST_BUFFER_BYTES: usize = 1024;

pub(crate) fn build_health_response(
    node: &NodeIdentity,
    runtime_health: &dyn HealthSink,
) -> String {
    let snapshot = runtime_health.snapshot();
    let mut payload = runtime_health_payload(&snapshot);
    if let Some(object) = payload.as_object_mut() {
        object.insert("node_id".to_string(), serde_json::json!(node.node_id));
        object.insert("hostname".to_string(), serde_json::json!(node.hostname));
        object.insert("region".to_string(), serde_json::json!(node.region));
        object.insert(
            "uptime_since".to_string(),
            serde_json::json!(node.started_at),
        );
    }
    payload.to_string()
}

pub(crate) fn build_metrics_response(
    node: &NodeIdentity,
    runtime_health: &dyn HealthSink,
) -> String {
    let snapshot = runtime_health.snapshot();
    let up = u8::from(matches!(snapshot.status, HealthStatus::Ok));
    let node_id = prometheus_label_value(&node.node_id);
    let hostname = prometheus_label_value(&node.hostname);
    let region = prometheus_label_value(&node.region);
    format!(
        "# HELP nettrap_up Whether NetTrap is operational\n\
         # TYPE nettrap_up gauge\n\
         nettrap_up {}\n\
         # HELP nettrap_info Node information\n\
         # TYPE nettrap_info gauge\n\
         nettrap_info{{node_id=\"{}\",hostname=\"{}\",region=\"{}\"}} 1\n",
        up, node_id, hostname, region
    )
}

fn prometheus_label_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' | '\r' => escaped.push_str("\\n"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

pub(crate) fn build_ready_response(ready: bool) -> String {
    serde_json::json!({
        "ready": ready
    })
    .to_string()
}

fn parse_request_path(request: &str) -> Option<(&str, &str)> {
    let request_line = request.split_once("\r\n")?.0;
    if request_line
        .chars()
        .any(|ch| matches!(ch, '\u{0085}' | '\u{2028}' | '\u{2029}'))
    {
        return None;
    }
    let mut parts = request_line.split(' ');
    let method = parts.next()?;
    let path = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || version != "HTTP/1.1" {
        return None;
    }
    Some((method, path))
}

fn route_probe_request_bytes(
    request: &[u8],
    node: &NodeIdentity,
    runtime_health: &dyn HealthSink,
    server_kind: ProbeServerKind,
) -> (&'static str, &'static str, String) {
    let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        return ("400 Bad Request", "text/plain", "Bad Request".to_string());
    };
    let headers = &request[..header_end];
    if has_invalid_http_line_endings(headers) {
        return ("400 Bad Request", "text/plain", "Bad Request".to_string());
    }

    let Ok(request) = std::str::from_utf8(request) else {
        return ("400 Bad Request", "text/plain", "Bad Request".to_string());
    };

    route_probe_request(request, node, runtime_health, server_kind)
}

pub(crate) fn route_probe_request(
    request: &str,
    node: &NodeIdentity,
    runtime_health: &dyn HealthSink,
    server_kind: ProbeServerKind,
) -> (&'static str, &'static str, String) {
    let request_path = parse_request_path(request);

    match server_kind {
        ProbeServerKind::Health => {
            if request_path == Some(("GET", "/health")) {
                (
                    "200 OK",
                    "application/json",
                    build_health_response(node, runtime_health),
                )
            } else if request_path == Some(("GET", "/ready")) {
                let snapshot = runtime_health.snapshot();
                let ready = matches!(snapshot.status, HealthStatus::Ok);
                (
                    if ready {
                        "200 OK"
                    } else {
                        "503 Service Unavailable"
                    },
                    "application/json",
                    build_ready_response(ready),
                )
            } else {
                ("404 Not Found", "text/plain", "Not Found".to_string())
            }
        }
        ProbeServerKind::Metrics => {
            if request_path == Some(("GET", "/metrics")) {
                (
                    "200 OK",
                    "text/plain; version=0.0.4",
                    build_metrics_response(node, runtime_health),
                )
            } else {
                ("404 Not Found", "text/plain", "Not Found".to_string())
            }
        }
    }
}

fn probe_server_name(server_kind: ProbeServerKind) -> &'static str {
    match server_kind {
        ProbeServerKind::Health => "health/readiness",
        ProbeServerKind::Metrics => "metrics",
    }
}

fn has_invalid_http_line_endings(data: &[u8]) -> bool {
    data.iter().enumerate().any(|(idx, &byte)| {
        byte == b'\n' && (idx == 0 || data[idx - 1] != b'\r')
            || byte == b'\r' && idx + 1 < data.len() && data[idx + 1] != b'\n'
    })
}

pub(crate) fn is_transient_accept_error(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    if matches!(
        err.kind(),
        ErrorKind::ConnectionAborted | ErrorKind::Interrupted | ErrorKind::WouldBlock
    ) {
        return true;
    }

    #[cfg(unix)]
    {
        matches!(err.raw_os_error(), Some(12 | 23 | 24 | 105))
    }

    #[cfg(not(unix))]
    {
        false
    }
}

fn bind_probe_server(
    bind: &str,
    server_kind: ProbeServerKind,
) -> Result<(tokio::net::TcpListener, std::net::SocketAddr)> {
    let addr = canonicalize_socket_addr_bind(bind, server_kind)?;
    let listener = std::net::TcpListener::bind(addr).map_err(|err| {
        Error::Other(format!(
            "Failed to bind {} server on {}: {}",
            probe_server_name(server_kind),
            bind,
            err
        ))
    })?;
    listener.set_nonblocking(true).map_err(|err| {
        Error::Other(format!(
            "Failed to configure {} server on {} as non-blocking: {}",
            probe_server_name(server_kind),
            bind,
            err
        ))
    })?;
    let local_addr = listener.local_addr().map_err(Error::Io)?;
    let listener = tokio::net::TcpListener::from_std(listener).map_err(Error::Io)?;

    Ok((listener, local_addr))
}

fn canonicalize_socket_addr_bind(
    bind: &str,
    server_kind: ProbeServerKind,
) -> Result<std::net::SocketAddr> {
    let addr = bind.parse::<std::net::SocketAddr>().map_err(|err| {
        Error::Config(format!(
            "Invalid {} bind '{}': {}",
            probe_server_name(server_kind),
            bind,
            err
        ))
    })?;

    Ok(match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            std::net::SocketAddr::new(std::net::IpAddr::V4(ip), addr.port())
        }
        std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(addr, |mapped| {
            std::net::SocketAddr::new(std::net::IpAddr::V4(mapped), addr.port())
        }),
    })
}

async fn handle_probe_connection<S>(
    mut stream: S,
    node: Arc<NodeIdentity>,
    runtime_health: Arc<dyn HealthSink>,
    server_kind: ProbeServerKind,
    read_timeout: std::time::Duration,
    write_timeout: std::time::Duration,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; PROBE_REQUEST_BUFFER_BYTES];
    let read = match tokio::time::timeout(read_timeout, stream.read(&mut buf)).await {
        Err(_) => {
            tracing::debug!(
                "{} server request read timed out",
                probe_server_name(server_kind)
            );
            return;
        }
        Ok(Ok(0)) => return,
        Ok(Ok(read)) => read,
        Ok(Err(err)) => {
            tracing::debug!(
                "{} server request read failed: {}",
                probe_server_name(server_kind),
                err
            );
            return;
        }
    };

    let (status, content_type, body) =
        route_probe_request_bytes(&buf[..read], &node, runtime_health.as_ref(), server_kind);

    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n{}",
        status,
        content_type,
        body.len(),
        body
    );
    match tokio::time::timeout(write_timeout, stream.write_all(response.as_bytes())).await {
        Err(_) => tracing::debug!(
            "{} server response write timed out",
            probe_server_name(server_kind)
        ),
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::debug!(
            "{} server response write failed: {}",
            probe_server_name(server_kind),
            err
        ),
    }
}

async fn run_probe_server(
    listener: tokio::net::TcpListener,
    node: Arc<NodeIdentity>,
    runtime_health: Arc<dyn HealthSink>,
    server_kind: ProbeServerKind,
) -> Result<()> {
    let mut consecutive_accept_failures = 0u32;
    let mut connection_tasks = JoinSet::new();

    loop {
        while let Some(result) = connection_tasks.try_join_next() {
            if let Err(err) = result
                && !err.is_cancelled()
            {
                tracing::warn!(
                    "{} probe connection task failed: {}",
                    probe_server_name(server_kind),
                    err
                );
            }
        }

        let (stream, _) = match listener.accept().await {
            Ok(connection) => {
                consecutive_accept_failures = 0;
                connection
            }
            Err(err) if is_transient_accept_error(&err) => {
                consecutive_accept_failures += 1;
                let server_name = probe_server_name(server_kind);
                tracing::warn!(
                    "{} server transient accept error ({}/{}): {}",
                    server_name,
                    consecutive_accept_failures,
                    PROBE_ACCEPT_RETRY_LIMIT,
                    err
                );
                if consecutive_accept_failures >= PROBE_ACCEPT_RETRY_LIMIT {
                    return Err(Error::Other(format!(
                        "{} server accept failed {} consecutive times: {}",
                        server_name, PROBE_ACCEPT_RETRY_LIMIT, err
                    )));
                }
                tokio::time::sleep(std::time::Duration::from_millis(
                    PROBE_ACCEPT_RETRY_DELAY_MS,
                ))
                .await;
                continue;
            }
            Err(err) => {
                return Err(Error::Other(format!(
                    "{} server accept error: {}",
                    probe_server_name(server_kind),
                    err
                )));
            }
        };
        let node = Arc::clone(&node);
        let runtime_health = Arc::clone(&runtime_health);
        connection_tasks.spawn(async move {
            handle_probe_connection(
                stream,
                node,
                runtime_health,
                server_kind,
                PROBE_CONNECTION_READ_TIMEOUT,
                PROBE_CONNECTION_WRITE_TIMEOUT,
            )
            .await;
        });
    }
}

pub fn bind_health_server(bind: &str) -> Result<(tokio::net::TcpListener, std::net::SocketAddr)> {
    bind_probe_server(bind, ProbeServerKind::Health)
}

pub fn bind_metrics_server(bind: &str) -> Result<(tokio::net::TcpListener, std::net::SocketAddr)> {
    bind_probe_server(bind, ProbeServerKind::Metrics)
}

pub async fn serve_health_server(
    listener: tokio::net::TcpListener,
    node: Arc<NodeIdentity>,
    runtime_health: Arc<dyn HealthSink>,
) -> Result<()> {
    run_probe_server(listener, node, runtime_health, ProbeServerKind::Health).await
}

pub async fn serve_metrics_server(
    listener: tokio::net::TcpListener,
    node: Arc<NodeIdentity>,
    runtime_health: Arc<dyn HealthSink>,
) -> Result<()> {
    run_probe_server(listener, node, runtime_health, ProbeServerKind::Metrics).await
}

pub async fn run_health_server(
    bind: String,
    node: Arc<NodeIdentity>,
    runtime_health: Arc<dyn HealthSink>,
) -> Result<()> {
    let (listener, local_addr) = bind_health_server(&bind)?;
    tracing::info!(
        "{} server on {}",
        probe_server_name(ProbeServerKind::Health),
        local_addr
    );
    serve_health_server(listener, node, runtime_health).await
}

pub async fn run_metrics_server(
    bind: String,
    node: Arc<NodeIdentity>,
    runtime_health: Arc<dyn HealthSink>,
) -> Result<()> {
    let (listener, local_addr) = bind_metrics_server(&bind)?;
    tracing::info!(
        "{} server on {}",
        probe_server_name(ProbeServerKind::Metrics),
        local_addr
    );
    serve_metrics_server(listener, node, runtime_health).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node() -> NodeIdentity {
        NodeIdentity {
            node_id: "node-1".to_string(),
            hostname: "host-1".to_string(),
            region: "lab".to_string(),
            tags: Vec::new(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn canonicalize_socket_addr_bind_canonicalizes_ipv4_mapped_addresses() {
        let addr =
            canonicalize_socket_addr_bind("[::ffff:127.0.0.1]:18888", ProbeServerKind::Health)
                .expect("mapped socket addr should parse");

        assert_eq!(
            addr,
            "127.0.0.1:18888"
                .parse::<std::net::SocketAddr>()
                .expect("valid IPv4 socket addr")
        );
    }

    #[test]
    fn route_probe_request_bytes_rejects_invalid_utf8() {
        let node = test_node();
        let health = nettrap_api::RuntimeHealth::new();

        let (status, content_type, body) = route_probe_request_bytes(
            b"GET /health HTTP/1.1\r\nX-Test: \xff\r\n\r\n",
            &node,
            &health,
            ProbeServerKind::Health,
        );

        assert_eq!(status, "400 Bad Request");
        assert_eq!(content_type, "text/plain");
        assert_eq!(body, "Bad Request");
    }

    #[test]
    fn route_probe_request_bytes_rejects_incomplete_headers() {
        let node = test_node();
        let health = nettrap_api::RuntimeHealth::new();

        let (status, content_type, body) = route_probe_request_bytes(
            b"GET /health HTTP/1.1\r\nHost: localhost\r\n",
            &node,
            &health,
            ProbeServerKind::Health,
        );

        assert_eq!(status, "400 Bad Request");
        assert_eq!(content_type, "text/plain");
        assert_eq!(body, "Bad Request");
    }

    #[test]
    fn route_probe_request_bytes_rejects_bare_lf_line_endings() {
        let node = test_node();
        let health = nettrap_api::RuntimeHealth::new();

        let (status, content_type, body) = route_probe_request_bytes(
            b"GET /health HTTP/1.1\nHost: localhost\r\n\r\n",
            &node,
            &health,
            ProbeServerKind::Health,
        );

        assert_eq!(status, "400 Bad Request");
        assert_eq!(content_type, "text/plain");
        assert_eq!(body, "Bad Request");
    }

    #[test]
    fn route_probe_request_rejects_extra_request_line_fields() {
        let node = test_node();
        let health = nettrap_api::RuntimeHealth::new();

        let (status, content_type, body) = route_probe_request(
            "GET /health HTTP/1.1 extra\r\n",
            &node,
            &health,
            ProbeServerKind::Health,
        );

        assert_eq!(status, "404 Not Found");
        assert_eq!(content_type, "text/plain");
        assert_eq!(body, "Not Found");
    }

    #[test]
    fn route_probe_request_rejects_tab_separated_request_line() {
        let node = test_node();
        let health = nettrap_api::RuntimeHealth::new();

        let (status, content_type, body) = route_probe_request(
            "GET\t/health\tHTTP/1.1\r\n",
            &node,
            &health,
            ProbeServerKind::Health,
        );

        assert_eq!(status, "404 Not Found");
        assert_eq!(content_type, "text/plain");
        assert_eq!(body, "Not Found");
    }

    #[test]
    fn route_probe_request_rejects_bare_lf_request_line() {
        let node = test_node();
        let health = nettrap_api::RuntimeHealth::new();

        let (status, content_type, body) = route_probe_request(
            "GET /health HTTP/1.1\n",
            &node,
            &health,
            ProbeServerKind::Health,
        );

        assert_eq!(status, "404 Not Found");
        assert_eq!(content_type, "text/plain");
        assert_eq!(body, "Not Found");
    }

    #[test]
    fn route_probe_request_rejects_unicode_line_separators_in_request_line() {
        let node = test_node();
        let health = nettrap_api::RuntimeHealth::new();

        let (status, content_type, body) = route_probe_request(
            "GET /health\u{2028}HTTP/1.1\r\n",
            &node,
            &health,
            ProbeServerKind::Health,
        );

        assert_eq!(status, "404 Not Found");
        assert_eq!(content_type, "text/plain");
        assert_eq!(body, "Not Found");
    }

    #[tokio::test]
    async fn handle_probe_connection_times_out_slow_client_reads() {
        let (_client, server) = tokio::io::duplex(64);
        let node = Arc::new(test_node());
        let health = Arc::new(nettrap_api::RuntimeHealth::new());

        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            handle_probe_connection(
                server,
                node,
                health,
                ProbeServerKind::Health,
                std::time::Duration::from_millis(10),
                std::time::Duration::from_millis(10),
            ),
        )
        .await
        .expect("slow probe client should be dropped after read timeout");
    }
}
