//! Event-sink implementations for the distributed subsystem.
//!
//! Behaviour-preserving relocation of the HTTP, TCP, and syslog-UDP sinks from
//! `lib.rs`. Public paths (`nettrap_distributed::HttpSink`, `TcpSink`,
//! `SyslogUdpSink`) are unchanged via the re-export in `lib.rs`.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{
    EventSink, HTTP_SINK_MAX_BUFFERED_EVENTS, HTTP_SINK_MAX_EVENT_BYTES,
    SYSLOG_UDP_MAX_DATAGRAM_BYTES, SinkDeliveryState, SinkSendResult, TCP_SINK_MAX_EVENT_BYTES,
};

const HTTP_SINK_ERROR_BODY_PREVIEW_BYTES: usize = 1024;
const TCP_SINK_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

// ─── Webhook/HTTP Sink ───────────────────────────────────────────────────────

/// Ships events to an HTTP endpoint (webhooks, Elasticsearch, Splunk HEC, etc.)
pub struct HttpSink {
    url: String,
    auth_header: Option<String>,
    client: reqwest::Client,
    pub(crate) state: parking_lot::Mutex<HttpSinkState>,
    pub(crate) pending: AtomicUsize,
    next_sequence: AtomicU64,
    pending_sequences: parking_lot::RwLock<HashSet<u64>>,
    pub(crate) pending_event_ids: parking_lot::RwLock<HashSet<String>>,
    unknown_event_ids: parking_lot::Mutex<HashSet<String>>,
    unknown_event_sequences: parking_lot::Mutex<HashSet<u64>>,
    batch_size: usize,
    flush_interval: std::time::Duration,
    request_timeout: std::time::Duration,
}

#[derive(Clone)]
pub(crate) struct BufferedHttpEvent {
    pub(crate) sequence: u64,
    pub(crate) event_id: String,
    pub(crate) json: String,
    pub(crate) enqueued_at: tokio::time::Instant,
}

pub(crate) struct HttpSinkState {
    pub(crate) batch: Vec<BufferedHttpEvent>,
    pub(crate) oldest_event_at: Option<tokio::time::Instant>,
    flushing: bool,
}

struct HttpBatchSendOutcome {
    failed_events: Vec<BufferedHttpEvent>,
    unknown_event_ids: HashSet<String>,
    unknown_event_sequences: HashSet<u64>,
    error: Option<String>,
}

impl HttpSink {
    pub fn new(
        url: impl Into<String>,
        auth: Option<String>,
        batch_size: usize,
        flush_interval_ms: u64,
        request_timeout_ms: u64,
    ) -> Self {
        Self {
            url: url.into(),
            auth_header: auth,
            client: reqwest::Client::new(),
            state: parking_lot::Mutex::new(HttpSinkState {
                batch: Vec::new(),
                oldest_event_at: None,
                flushing: false,
            }),
            pending: AtomicUsize::new(0),
            next_sequence: AtomicU64::new(0),
            pending_sequences: parking_lot::RwLock::new(HashSet::new()),
            pending_event_ids: parking_lot::RwLock::new(HashSet::new()),
            unknown_event_ids: parking_lot::Mutex::new(HashSet::new()),
            unknown_event_sequences: parking_lot::Mutex::new(HashSet::new()),
            batch_size: if batch_size == 0 {
                100
            } else {
                batch_size.min(HTTP_SINK_MAX_BUFFERED_EVENTS)
            },
            flush_interval: std::time::Duration::from_millis(if flush_interval_ms == 0 {
                1000
            } else {
                flush_interval_ms
            }),
            request_timeout: std::time::Duration::from_millis(if request_timeout_ms == 0 {
                5000
            } else {
                request_timeout_ms
            }),
        }
    }

    async fn send_batch(&self, events: Vec<BufferedHttpEvent>) -> HttpBatchSendOutcome {
        let client = &self.client;
        let mut errors = Vec::new();
        let mut failed_events = Vec::new();
        let mut unknown_event_ids = HashSet::new();
        let mut unknown_event_sequences = HashSet::new();
        for event in events {
            let mut req = client
                .post(&self.url)
                .header("Content-Type", "application/json")
                .body(event.json.clone());
            if let Some(ref auth) = self.auth_header {
                req = req.header("Authorization", auth.clone());
            }
            match tokio::time::timeout(self.request_timeout, req.send()).await {
                Err(_) => {
                    tracing::warn!("HTTP sink {} request timed out", self.url);
                    errors.push(format!("HTTP {} request timed out", self.url));
                    unknown_event_ids.insert(event.event_id);
                    unknown_event_sequences.insert(event.sequence);
                }
                Ok(Ok(resp)) if !resp.status().is_success() => {
                    let status = resp.status();
                    let body = match tokio::time::timeout(
                        self.request_timeout,
                        limited_response_text(resp, HTTP_SINK_ERROR_BODY_PREVIEW_BYTES),
                    )
                    .await
                    {
                        Err(_) => {
                            tracing::warn!(
                                "HTTP sink {} timed out reading error response body",
                                self.url
                            );
                            String::new()
                        }
                        Ok(Ok(body)) => body,
                        Ok(Err(err)) => {
                            tracing::warn!(
                                "HTTP sink {} failed to read error response body: {}",
                                self.url,
                                err
                            );
                            String::new()
                        }
                    };
                    tracing::warn!(
                        "HTTP sink {} response: {} — {}",
                        self.url,
                        status,
                        body.chars().take(200).collect::<String>()
                    );
                    errors.push(format!("HTTP {} responded with {}", self.url, status));
                    failed_events.push(event);
                }
                Ok(Err(e)) => {
                    tracing::warn!("HTTP sink send error: {}", e);
                    errors.push(format!("HTTP {} send error: {}", self.url, e));
                    unknown_event_ids.insert(event.event_id);
                    unknown_event_sequences.insert(event.sequence);
                }
                _ => {}
            }
        }
        HttpBatchSendOutcome {
            failed_events,
            unknown_event_ids,
            unknown_event_sequences,
            error: (!errors.is_empty()).then(|| errors.join("; ")),
        }
    }

    async fn flush_due_to(&self, stale_only: bool) -> std::result::Result<bool, String> {
        let events = {
            let mut state = self.state.lock();
            if state.flushing || state.batch.is_empty() {
                return Ok(false);
            }

            if stale_only {
                let Some(oldest_event_at) = state.oldest_event_at else {
                    return Ok(false);
                };
                if oldest_event_at.elapsed() < self.flush_interval {
                    return Ok(false);
                }
            }

            state.flushing = true;
            state.batch.clone()
        };

        let sent_event_sequences = events
            .iter()
            .map(|event| event.sequence)
            .collect::<HashSet<_>>();
        let outcome = self.send_batch(events).await;

        let mut state = self.state.lock();
        state.flushing = false;
        let still_buffered_ids = state
            .batch
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<HashSet<_>>();
        let still_buffered_sequences = state
            .batch
            .iter()
            .map(|event| event.sequence)
            .collect::<HashSet<_>>();
        let remaining_batch = state
            .batch
            .iter()
            .filter(|event| !sent_event_sequences.contains(&event.sequence))
            .cloned()
            .collect::<Vec<_>>();
        state.batch = outcome
            .failed_events
            .into_iter()
            .filter(|event| still_buffered_sequences.contains(&event.sequence))
            .collect();
        state.batch.extend(remaining_batch);
        self.pending.store(state.batch.len(), Ordering::Relaxed);
        *self.pending_sequences.write() = state.batch.iter().map(|event| event.sequence).collect();
        let pending_ids = state
            .batch
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<HashSet<_>>();
        *self.pending_event_ids.write() = pending_ids;
        self.unknown_event_ids.lock().extend(
            outcome
                .unknown_event_ids
                .into_iter()
                .filter(|event_id| still_buffered_ids.contains(event_id)),
        );
        self.unknown_event_sequences.lock().extend(
            outcome
                .unknown_event_sequences
                .into_iter()
                .filter(|sequence| still_buffered_sequences.contains(sequence)),
        );
        *self.pending_sequences.write() = state.batch.iter().map(|event| event.sequence).collect();
        state.oldest_event_at = Self::oldest_event_at(&state.batch);

        match outcome.error {
            Some(error) => Err(error),
            None => Ok(true),
        }
    }

    fn oldest_event_at(batch: &[BufferedHttpEvent]) -> Option<tokio::time::Instant> {
        batch.iter().map(|event| event.enqueued_at).min()
    }
}

#[async_trait::async_trait]
impl EventSink for HttpSink {
    async fn send(&self, event: &nettrap_core::NetworkBehaviorIndicator) -> SinkSendResult {
        let json = match serde_json::to_string(event) {
            Ok(json) => json,
            Err(err) => return SinkSendResult::lost(err.to_string()),
        };
        if json.len() > HTTP_SINK_MAX_EVENT_BYTES {
            return SinkSendResult::lost(format!(
                "HTTP sink {} event payload too large ({} > {} bytes)",
                self.url,
                json.len(),
                HTTP_SINK_MAX_EVENT_BYTES
            ));
        }
        let event_id = event.normalized_event_id();
        let sequence = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        let enqueued_at = tokio::time::Instant::now();
        let should_flush = {
            let mut state = self.state.lock();
            if state.batch.len() >= HTTP_SINK_MAX_BUFFERED_EVENTS {
                return SinkSendResult::lost(format!(
                    "HTTP sink {} buffer full at {} events",
                    self.url, HTTP_SINK_MAX_BUFFERED_EVENTS
                ));
            }
            if state.batch.is_empty() {
                state.oldest_event_at = Some(enqueued_at);
            }
            state.batch.push(BufferedHttpEvent {
                sequence,
                event_id: event_id.clone(),
                json,
                enqueued_at,
            });
            self.pending.fetch_add(1, Ordering::Relaxed);
            self.pending_sequences.write().insert(sequence);
            self.pending_event_ids.write().insert(event_id.clone());
            !state.flushing
                && (state.batch.len() >= self.batch_size
                    || state
                        .oldest_event_at
                        .is_some_and(|oldest| oldest.elapsed() >= self.flush_interval))
        };
        let mut flush_error = None;
        if should_flush && let Err(err) = self.flush_due_to(false).await {
            flush_error = Some(err);
        }
        let still_buffered = self.pending_sequences.read().contains(&sequence);
        let is_unknown = self.unknown_event_sequences.lock().remove(&sequence);
        if still_buffered {
            SinkSendResult::buffered(flush_error)
        } else if is_unknown {
            let _ = self.unknown_event_ids.lock().remove(&event_id);
            SinkSendResult::unknown(
                flush_error.unwrap_or_else(|| format!("HTTP {} request timed out", self.url)),
            )
        } else {
            match flush_error {
                Some(error) => SinkSendResult {
                    state: SinkDeliveryState::Delivered,
                    error: Some(error),
                },
                None => SinkSendResult::delivered(),
            }
        }
    }

    async fn flush(&self) -> std::result::Result<(), String> {
        let _ = self.flush_due_to(false).await?;
        Ok(())
    }

    async fn flush_stale(&self) -> std::result::Result<bool, String> {
        self.flush_due_to(true).await
    }

    fn name(&self) -> &'static str {
        "http"
    }

    fn buffered_events(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }

    fn buffered_event_ids(&self) -> Vec<String> {
        self.pending_event_ids.read().iter().cloned().collect()
    }

    fn drop_buffered_events(&self, event_ids: &HashSet<String>) -> usize {
        if event_ids.is_empty() {
            return 0;
        }

        let mut state = self.state.lock();
        let before = state.batch.len();
        state
            .batch
            .retain(|event| !event_ids.contains(&event.event_id));
        let dropped = before.saturating_sub(state.batch.len());
        self.pending.store(state.batch.len(), Ordering::Relaxed);
        *self.pending_sequences.write() = state.batch.iter().map(|event| event.sequence).collect();
        *self.pending_event_ids.write() = state
            .batch
            .iter()
            .map(|event| event.event_id.clone())
            .collect();
        state.oldest_event_at = Self::oldest_event_at(&state.batch);
        self.unknown_event_ids
            .lock()
            .retain(|event_id| !event_ids.contains(event_id));
        self.unknown_event_sequences
            .lock()
            .retain(|sequence| state.batch.iter().any(|event| event.sequence == *sequence));
        dropped
    }

    fn take_unknown_event_ids(&self) -> Vec<String> {
        let mut unknown_event_ids = self.unknown_event_ids.lock();
        unknown_event_ids.drain().collect()
    }
}

async fn limited_response_text(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<String, reqwest::Error> {
    let mut body = Vec::new();
    while body.len() < max_bytes {
        let Some(chunk) = response.chunk().await? else {
            break;
        };
        let remaining = max_bytes - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
    Ok(limited_response_preview(&body))
}

fn limited_response_preview(body: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(body) {
        return nettrap_core::sanitize::single_line(text);
    }

    use std::fmt::Write as _;

    let mut rendered = String::from("hex:");
    for byte in body {
        let _ = write!(&mut rendered, "{:02x}", byte);
    }
    rendered
}

// ─── TCP Socket Sink (for NATS/Kafka/Logstash/Fluentd) ──────────────────────

/// Ships events as newline-delimited JSON over a TCP socket.
/// Compatible with: Logstash tcp input, Fluentd, NATS, custom collectors.
pub struct TcpSink {
    addr: String,
    connection: tokio::sync::Mutex<Option<tokio::net::TcpStream>>,
}

impl TcpSink {
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            connection: tokio::sync::Mutex::new(None),
        }
    }
}

fn tcp_sink_write_error(err: &std::io::Error) -> String {
    format!("TCP sink write failed, will reconnect: {err}")
}

async fn tcp_sink_write_all_with_timeout<W>(
    writer: &mut W,
    bytes: &[u8],
    timeout: std::time::Duration,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match tokio::time::timeout(timeout, writer.write_all(bytes)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "TCP sink write timed out",
        )),
    }
}

async fn tcp_sink_flush_with_timeout<W>(
    writer: &mut W,
    timeout: std::time::Duration,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match tokio::time::timeout(timeout, writer.flush()).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "TCP sink flush timed out",
        )),
    }
}

#[async_trait::async_trait]
impl EventSink for TcpSink {
    async fn send(&self, event: &nettrap_core::NetworkBehaviorIndicator) -> SinkSendResult {
        let json = match serde_json::to_string(event) {
            Ok(json) => json,
            Err(err) => return SinkSendResult::lost(err.to_string()),
        };
        if json.len() > TCP_SINK_MAX_EVENT_BYTES {
            return SinkSendResult::lost(format!(
                "TCP sink event payload too large ({} > {} bytes)",
                json.len(),
                TCP_SINK_MAX_EVENT_BYTES
            ));
        }
        let line = format!("{}\n", json);

        let mut conn = self.connection.lock().await;
        // Ensure connected with timeout to avoid hanging
        if conn.is_none() {
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                tokio::net::TcpStream::connect(&self.addr),
            )
            .await
            {
                Ok(Ok(stream)) => *conn = Some(stream),
                Ok(Err(e)) => {
                    return SinkSendResult::lost(format!("TCP sink connect error: {}", e));
                }
                Err(_) => {
                    return SinkSendResult::lost("TCP sink connect timed out");
                }
            }
        }
        if let Some(ref mut stream) = *conn
            && let Err(err) =
                tcp_sink_write_all_with_timeout(stream, line.as_bytes(), TCP_SINK_IO_TIMEOUT).await
        {
            *conn = None;
            return SinkSendResult::unknown(tcp_sink_write_error(&err));
        }
        SinkSendResult::delivered()
    }

    async fn flush(&self) -> std::result::Result<(), String> {
        let mut conn = self.connection.lock().await;
        if let Some(ref mut stream) = *conn
            && let Err(err) = tcp_sink_flush_with_timeout(stream, TCP_SINK_IO_TIMEOUT).await
        {
            *conn = None;
            return Err(format!("TCP sink flush error: {}", err));
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "tcp"
    }
}

// ─── Syslog UDP Sink ─────────────────────────────────────────────────────────

/// Ships events as syslog-formatted UDP datagrams (RFC 5424)
pub struct SyslogUdpSink {
    addr: String,
    socket: tokio::sync::Mutex<Option<tokio::net::UdpSocket>>,
    facility: u8, // LOG_LOCAL0 = 16
}

impl SyslogUdpSink {
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            socket: tokio::sync::Mutex::new(None),
            facility: 16, // LOCAL0
        }
    }
}

async fn resolve_syslog_udp_addr(addr: &str) -> std::result::Result<SocketAddr, String> {
    tokio::net::lookup_host(addr)
        .await
        .map_err(|err| format!("Syslog UDP resolve error: {err}"))?
        .next()
        .ok_or_else(|| format!("Syslog UDP resolve error: no addresses for {addr}"))
}

#[async_trait::async_trait]
impl EventSink for SyslogUdpSink {
    async fn send(&self, event: &nettrap_core::NetworkBehaviorIndicator) -> SinkSendResult {
        let severity = 6u8; // INFO
        let priority = (self.facility * 8) + severity;
        let timestamp = &event.timestamp;
        let hostname = syslog_hostname_field(hostname::get().ok().as_deref());
        let msg = match serde_json::to_string(event) {
            Ok(msg) => msg,
            Err(err) => return SinkSendResult::lost(err.to_string()),
        };
        let syslog_msg = format!(
            "<{}>1 {} {} NetTrap - - - {}",
            priority, timestamp, hostname, msg
        );
        if syslog_msg.len() > SYSLOG_UDP_MAX_DATAGRAM_BYTES {
            return SinkSendResult::lost(format!(
                "Syslog UDP event payload too large ({} > {} bytes)",
                syslog_msg.len(),
                SYSLOG_UDP_MAX_DATAGRAM_BYTES
            ));
        }

        let mut sock = self.socket.lock().await;
        if sock.is_none() {
            let remote = match resolve_syslog_udp_addr(&self.addr).await {
                Ok(addr) => addr,
                Err(err) => return SinkSendResult::lost(err),
            };
            let bind_addr = if remote.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let s = tokio::net::UdpSocket::bind(bind_addr)
                .await
                .map_err(|e| format!("Syslog UDP bind error: {}", e));
            let s = match s {
                Ok(socket) => socket,
                Err(err) => return SinkSendResult::lost(err),
            };
            let s = match s.connect(remote).await {
                Ok(()) => s,
                Err(err) => {
                    return SinkSendResult::lost(format!("Syslog UDP connect error: {}", err));
                }
            };
            *sock = Some(s);
        }
        if let Some(ref socket) = *sock
            && let Err(err) = socket.send(syslog_msg.as_bytes()).await
        {
            *sock = None;
            return SinkSendResult::lost(format!("Syslog send error: {}", err));
        }
        SinkSendResult::delivered()
    }

    async fn flush(&self) -> std::result::Result<(), String> {
        Ok(())
    }
    fn name(&self) -> &'static str {
        "syslog"
    }
}

fn syslog_hostname_label(hostname: &OsStr) -> String {
    hostname
        .to_str()
        .map(|value| {
            let value = value.trim_matches([' ', '\t']);
            let value = if let Some(value) = value.strip_suffix('.') {
                if value.is_empty() || value.ends_with('.') {
                    return String::new();
                }
                value
            } else {
                value
            };
            if value.is_empty()
                || value.len() > 253
                || value
                    .chars()
                    .any(|ch| ch.is_whitespace() || ch.is_control())
                || !nettrap_core::sanitize::has_valid_domain_labels(value)
                || nettrap_core::sanitize::has_numeric_domain_labels(value)
            {
                String::new()
            } else {
                value.to_ascii_lowercase()
            }
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
}

fn syslog_hostname_field(hostname: Option<&OsStr>) -> String {
    hostname
        .map(syslog_hostname_label)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "-".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        HTTP_SINK_ERROR_BODY_PREVIEW_BYTES, HttpSink, SyslogUdpSink, limited_response_text,
        syslog_hostname_field, syslog_hostname_label, tcp_sink_flush_with_timeout,
        tcp_sink_write_all_with_timeout, tcp_sink_write_error,
    };
    use crate::{EventSink, SinkDeliveryState};
    use std::collections::HashSet;
    use std::ffi::OsStr;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    #[cfg(unix)]
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn syslog_hostname_label_trims_ascii_hostname() {
        assert_eq!(
            syslog_hostname_label(OsStr::new(" host.example ")),
            "host.example"
        );
    }

    #[test]
    fn syslog_hostname_label_canonicalizes_hostname_case() {
        assert_eq!(
            syslog_hostname_label(OsStr::new("HOST.EXAMPLE.")),
            syslog_hostname_label(OsStr::new("host.example"))
        );
    }

    #[test]
    fn syslog_hostname_label_rejects_overlong_host_labels() {
        let hostname = format!("{}.example.test", "a".repeat(64));

        assert_eq!(syslog_hostname_label(OsStr::new(&hostname)), "");
    }

    #[test]
    fn syslog_hostname_label_rejects_c1_controls() {
        assert_eq!(
            syslog_hostname_label(OsStr::new("syslog\u{009f}.example")),
            ""
        );
    }

    #[cfg(unix)]
    #[test]
    fn syslog_hostname_label_rejects_non_utf8_hostname() {
        let hostname = OsString::from_vec(b"host-\xff".to_vec());

        assert_eq!(syslog_hostname_label(&hostname), "");
    }

    #[test]
    fn syslog_hostname_label_rejects_multiple_trailing_dots() {
        assert_eq!(syslog_hostname_label(OsStr::new("host.example...")), "");
    }

    #[test]
    fn syslog_hostname_field_uses_nilvalue_for_invalid_hostname() {
        assert_eq!(syslog_hostname_field(Some(OsStr::new(" "))), "-");
        assert_eq!(syslog_hostname_field(None), "-");
    }

    #[test]
    fn tcp_sink_write_error_includes_source_error() {
        let err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "synthetic broken pipe");

        let message = tcp_sink_write_error(&err);

        assert_eq!(
            message,
            "TCP sink write failed, will reconnect: synthetic broken pipe"
        );
    }

    #[tokio::test]
    async fn tcp_sink_write_times_out_under_backpressure() {
        let (mut writer, _reader) = tokio::io::duplex(64);
        let payload = vec![b'x'; 1024 * 1024];

        let err = tcp_sink_write_all_with_timeout(
            &mut writer,
            &payload,
            std::time::Duration::from_millis(10),
        )
        .await
        .expect_err("unread peer should trigger write timeout");

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    struct PendingFlushWriter;

    impl tokio::io::AsyncWrite for PendingFlushWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn tcp_sink_flush_times_out_when_writer_stalls() {
        let mut writer = PendingFlushWriter;

        let err = tcp_sink_flush_with_timeout(&mut writer, std::time::Duration::from_millis(10))
            .await
            .expect_err("stalled flush should time out");

        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn limited_response_text_truncates_large_error_body() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut request = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
            let body = "x".repeat(HTTP_SINK_ERROR_BODY_PREVIEW_BYTES + 128);
            let response = format!(
                "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
        });

        let response = reqwest::get(format!("http://{addr}"))
            .await
            .expect("request should complete");
        let body = limited_response_text(response, HTTP_SINK_ERROR_BODY_PREVIEW_BYTES)
            .await
            .expect("response body preview should read");

        assert_eq!(
            body,
            "x".repeat(nettrap_core::sanitize::SINGLE_LINE_MAX_CHARS)
        );
        task.await.expect("server task should finish");
    }

    #[tokio::test]
    async fn limited_response_text_preserves_binary_error_body_as_hex() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut request = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
            let body = [0xff, 0x00, b'A'];
            let response = format!(
                "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, &body).await;
        });

        let response = reqwest::get(format!("http://{addr}"))
            .await
            .expect("request should complete");
        let body = limited_response_text(response, HTTP_SINK_ERROR_BODY_PREVIEW_BYTES)
            .await
            .expect("response body preview should read");

        assert_eq!(body, "hex:ff0041");
        task.await.expect("server task should finish");
    }

    #[tokio::test]
    async fn http_sink_error_body_preview_timeout_does_not_block_flush() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut request = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
            let response = format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\r\npartial",
                HTTP_SINK_ERROR_BODY_PREVIEW_BYTES + 128
            );
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
            std::future::pending::<()>().await;
        });

        let sink = HttpSink::new(format!("http://{addr}"), None, 1, 1000, 250);
        let event = nettrap_core::NetworkBehaviorIndicator::new(
            "test-listener",
            "RAW",
            "127.0.0.1",
            42424,
            "127.0.0.1",
            8080,
        );
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), sink.send(&event))
            .await
            .expect("HTTP sink send should return after response body timeout");

        assert_eq!(result.state, SinkDeliveryState::Buffered);
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|error| error.contains("responded with 500"))
        );

        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn http_sink_transport_error_marks_delivery_unknown() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("test listener address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("server should accept request");
            drop(stream);
        });

        let sink = HttpSink::new(format!("http://{addr}"), None, 1, 1000, 1000);
        let event = nettrap_core::NetworkBehaviorIndicator::new(
            "test-listener",
            "RAW",
            "127.0.0.1",
            42423,
            "127.0.0.1",
            8080,
        );
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), sink.send(&event))
            .await
            .expect("HTTP sink send should finish after transport close");

        assert_eq!(result.state, SinkDeliveryState::Unknown);
        server.await.expect("server task should finish");
    }

    #[tokio::test]
    async fn http_sink_flush_does_not_rebuffer_events_dropped_during_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let (request_started_tx, request_started_rx) = tokio::sync::oneshot::channel();
        let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut request = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
            let _ = request_started_tx.send(());
            let _ = respond_rx.await;
            let response = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
        });

        let sink = Arc::new(HttpSink::new(
            format!("http://{addr}"),
            None,
            10,
            1000,
            1000,
        ));
        let event = nettrap_core::NetworkBehaviorIndicator::new(
            "test-listener",
            "RAW",
            "127.0.0.1",
            42425,
            "127.0.0.1",
            8080,
        );
        let event_id = event.normalized_event_id();
        let send_result = sink.send(&event).await;
        assert_eq!(send_result.state, SinkDeliveryState::Buffered);

        let flushing_sink = Arc::clone(&sink);
        let flush_task = tokio::spawn(async move { flushing_sink.flush().await });
        request_started_rx
            .await
            .expect("server should receive flush request");

        let dropped = sink.drop_buffered_events(&HashSet::from([event_id.clone()]));
        assert_eq!(dropped, 1);
        assert_eq!(sink.buffered_events(), 0);

        respond_tx
            .send(())
            .expect("server response should be unblocked");
        let flush_result = flush_task.await.expect("flush task should finish");
        let flush_error = flush_result.expect_err("server 500 should surface as a flush error");
        assert!(flush_error.contains("responded with 500"));
        assert_eq!(sink.buffered_events(), 0);
        assert!(!sink.buffered_event_ids().contains(&event_id));

        server.await.expect("server task should finish");
    }

    #[tokio::test]
    async fn http_sink_drop_buffered_events_recomputes_remaining_batch_age() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let request_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server = tokio::spawn({
            let request_count = Arc::clone(&request_count);
            async move {
                let (mut stream, _) = listener.accept().await.expect("accept request");
                let mut request = [0u8; 1024];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
                request_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let response = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
            }
        });

        let url = format!("http://{addr}");
        let sink = Arc::new(HttpSink::new(url, None, 10, 50, 1_000));
        let first = nettrap_core::NetworkBehaviorIndicator::new(
            "test-listener",
            "RAW",
            "127.0.0.1",
            42426,
            "127.0.0.1",
            8080,
        );
        let second = nettrap_core::NetworkBehaviorIndicator::new(
            "test-listener",
            "RAW",
            "127.0.0.1",
            42427,
            "127.0.0.1",
            8080,
        );
        let first_id = first.normalized_event_id();
        let second_id = second.normalized_event_id();
        assert_eq!(sink.send(&first).await.state, SinkDeliveryState::Buffered);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(sink.send(&second).await.state, SinkDeliveryState::Buffered);

        let dropped = sink.drop_buffered_events(&HashSet::from([first_id]));
        assert_eq!(dropped, 1);
        assert_eq!(sink.buffered_event_ids(), vec![second_id]);
        assert!(
            !sink
                .flush_stale()
                .await
                .expect("fresh remainder should not flush")
        );
        assert_eq!(request_count.load(std::sync::atomic::Ordering::Relaxed), 0);
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        assert!(
            sink.flush_stale()
                .await
                .expect("remaining event should flush once stale")
        );
        assert_eq!(sink.buffered_events(), 0);
        assert_eq!(request_count.load(std::sync::atomic::Ordering::Relaxed), 1);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn http_sink_flush_keeps_events_added_during_an_inflight_flush() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let (request_started_tx, request_started_rx) = tokio::sync::oneshot::channel();
        let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut request = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
            let _ = request_started_tx.send(());
            let _ = respond_rx.await;
            let response = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
        });

        let sink = Arc::new(HttpSink::new(format!("http://{addr}"), None, 1, 1000, 1000));
        let first = nettrap_core::NetworkBehaviorIndicator::new(
            "test-listener",
            "RAW",
            "127.0.0.1",
            42428,
            "127.0.0.1",
            8080,
        );
        let second = nettrap_core::NetworkBehaviorIndicator::new(
            "test-listener",
            "RAW",
            "127.0.0.1",
            42429,
            "127.0.0.1",
            8080,
        );
        let first_id = first.normalized_event_id();
        let second_id = second.normalized_event_id();

        let first_sink = Arc::clone(&sink);
        let first_send_task = tokio::spawn(async move { first_sink.send(&first).await });
        request_started_rx
            .await
            .expect("server should receive the flush request");

        assert_eq!(sink.drop_buffered_events(&HashSet::from([first_id])), 1);
        assert_eq!(sink.send(&second).await.state, SinkDeliveryState::Buffered);

        respond_tx
            .send(())
            .expect("server response should be unblocked");
        let first_send_result =
            tokio::time::timeout(std::time::Duration::from_secs(1), first_send_task)
                .await
                .expect("flush should complete")
                .expect("first send task should finish");
        assert_eq!(first_send_result.state, SinkDeliveryState::Delivered);

        assert_eq!(sink.buffered_events(), 1);
        assert_eq!(sink.buffered_event_ids(), vec![second_id]);

        server.await.expect("server task should finish");
    }

    #[tokio::test]
    async fn http_sink_timeout_reports_unknown_even_when_duplicate_event_id_remains_buffered() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let (request_started_tx, request_started_rx) = tokio::sync::oneshot::channel();
        let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut request = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
            let _ = request_started_tx.send(());
            let _ = respond_rx.await;
            let response = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
        });

        let sink = Arc::new(HttpSink::new(format!("http://{addr}"), None, 1, 1000, 100));
        let mut first = nettrap_core::NetworkBehaviorIndicator::new(
            "test-listener",
            "RAW",
            "127.0.0.1",
            42432,
            "127.0.0.1",
            8080,
        );
        let mut second = nettrap_core::NetworkBehaviorIndicator::new(
            "test-listener",
            "RAW",
            "127.0.0.1",
            42433,
            "127.0.0.1",
            8080,
        );
        first.event_id = "duplicate-event-id".to_string();
        second.event_id = "duplicate-event-id".to_string();

        let first_sink = Arc::clone(&sink);
        let first_send_task = tokio::spawn(async move { first_sink.send(&first).await });
        request_started_rx
            .await
            .expect("server should receive the first request");

        assert_eq!(sink.send(&second).await.state, SinkDeliveryState::Buffered);

        let first_send_result =
            tokio::time::timeout(std::time::Duration::from_secs(1), first_send_task)
                .await
                .expect("timed flush should complete")
                .expect("first send task should finish");
        assert_eq!(first_send_result.state, SinkDeliveryState::Unknown);

        respond_tx
            .send(())
            .expect("server response should be unblocked");
        server.await.expect("server task should finish");
    }

    #[tokio::test]
    async fn http_sink_flush_keeps_distinct_entries_with_matching_event_ids() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let (request_started_tx, request_started_rx) = tokio::sync::oneshot::channel();
        let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut request = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
            let _ = request_started_tx.send(());
            let _ = respond_rx.await;
            let response = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
        });

        let sink = Arc::new(HttpSink::new(format!("http://{addr}"), None, 1, 1000, 1000));
        let mut first = nettrap_core::NetworkBehaviorIndicator::new(
            "test-listener",
            "RAW",
            "127.0.0.1",
            42430,
            "127.0.0.1",
            8080,
        );
        let mut second = nettrap_core::NetworkBehaviorIndicator::new(
            "test-listener",
            "RAW",
            "127.0.0.1",
            42431,
            "127.0.0.1",
            8080,
        );
        first.event_id = "duplicate-event-id".to_string();
        second.event_id = "duplicate-event-id".to_string();

        let first_id = first.normalized_event_id();
        let second_id = second.normalized_event_id();
        assert_eq!(first_id, second_id);

        let first_sink = Arc::clone(&sink);
        let first_send_task = tokio::spawn(async move { first_sink.send(&first).await });
        request_started_rx
            .await
            .expect("server should receive the flush request");

        assert_eq!(
            sink.drop_buffered_events(&HashSet::from([first_id.clone()])),
            1
        );
        assert_eq!(sink.send(&second).await.state, SinkDeliveryState::Buffered);

        respond_tx
            .send(())
            .expect("server response should be unblocked");
        let first_send_result =
            tokio::time::timeout(std::time::Duration::from_secs(1), first_send_task)
                .await
                .expect("flush should complete")
                .expect("first send task should finish");
        assert_eq!(first_send_result.state, SinkDeliveryState::Delivered);

        assert_eq!(sink.buffered_events(), 1);
        assert_eq!(sink.buffered_event_ids(), vec![second_id]);

        server.await.expect("server task should finish");
    }

    #[tokio::test]
    async fn syslog_udp_sink_sends_to_ipv6_destination() {
        let receiver = match tokio::net::UdpSocket::bind("[::1]:0").await {
            Ok(receiver) => receiver,
            Err(_) => return,
        };
        let addr = receiver.local_addr().expect("receiver local addr");
        let sink = SyslogUdpSink::new(addr.to_string());
        let event = nettrap_core::NetworkBehaviorIndicator::new(
            "raw",
            "RAW",
            "127.0.0.1",
            12604,
            "::1",
            514,
        );

        let result = sink.send(&event).await;

        assert_eq!(result.state, SinkDeliveryState::Delivered);
        let mut buf = [0u8; 2048];
        let received = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            receiver.recv(&mut buf),
        )
        .await
        .expect("syslog datagram should arrive")
        .expect("receive syslog datagram");
        assert!(received > 0);
    }

    #[tokio::test]
    async fn http_sink_failed_flush_keeps_remaining_entries_by_sequence_not_event_id() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let (request_started_tx, request_started_rx) = tokio::sync::oneshot::channel();
        let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut request = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
            let _ = request_started_tx.send(());
            let _ = respond_rx.await;
            let response = "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
        });

        let sink = Arc::new(HttpSink::new(format!("http://{addr}"), None, 1, 1000, 1000));
        let mut first = nettrap_core::NetworkBehaviorIndicator::new(
            "test-listener",
            "RAW",
            "127.0.0.1",
            42434,
            "127.0.0.1",
            8080,
        );
        let mut second = nettrap_core::NetworkBehaviorIndicator::new(
            "test-listener",
            "RAW",
            "127.0.0.1",
            42435,
            "127.0.0.1",
            8080,
        );
        first.event_id = "duplicate-event-id".to_string();
        second.event_id = "duplicate-event-id".to_string();

        let first_id = first.normalized_event_id();
        let second_id = second.normalized_event_id();
        assert_eq!(first_id, second_id);

        let first_sink = Arc::clone(&sink);
        let first_send_task = tokio::spawn(async move { first_sink.send(&first).await });
        request_started_rx
            .await
            .expect("server should receive the request");

        assert_eq!(
            sink.drop_buffered_events(&HashSet::from([first_id.clone()])),
            1
        );
        assert_eq!(sink.send(&second).await.state, SinkDeliveryState::Buffered);

        respond_tx
            .send(())
            .expect("server response should be unblocked");
        let first_send_result =
            tokio::time::timeout(std::time::Duration::from_secs(1), first_send_task)
                .await
                .expect("flush should complete")
                .expect("first send task should finish");
        assert_eq!(first_send_result.state, SinkDeliveryState::Delivered);

        assert_eq!(sink.buffered_events(), 1);
        assert_eq!(sink.buffered_event_ids(), vec![second_id]);
        {
            let state = sink.state.lock();
            assert_eq!(state.batch.len(), 1);
            assert_eq!(state.batch[0].sequence, 1);
        }

        server.await.expect("server task should finish");
    }
}
