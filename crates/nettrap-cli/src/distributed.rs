//! Distributed deployment support for NetTrap.
//! All features are optional — standalone mode requires zero distributed config.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::DistributedConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeServerKind {
    Health,
    Metrics,
}

const PROBE_ACCEPT_RETRY_LIMIT: u32 = 3;
const PROBE_ACCEPT_RETRY_DELAY_MS: u64 = 250;
const HEARTBEAT_FAILURE_LIMIT: u32 = 3;
const DISTRIBUTED_EXPORT_FAILURE_LIMIT: u32 = 3;

// ─── Node Identity ───────────────────────────────────────────────────────────

/// Unique identity for this NetTrap node in a distributed fleet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub node_id: String,
    pub hostname: String,
    pub region: String,
    pub tags: Vec<String>,
    pub started_at: String,
}

impl NodeIdentity {
    pub fn generate(node_id: Option<String>, region: Option<String>, tags: Vec<String>) -> Self {
        let hostname = hostname::get()
            .ok()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let effective_node_id = resolve_node_id(node_id, Some(hostname.as_str()));
        Self {
            node_id: effective_node_id,
            hostname,
            region: region.unwrap_or_else(|| "default".to_string()),
            tags,
            started_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

fn resolve_node_id(configured: Option<String>, hostname: Option<&str>) -> String {
    if let Some(configured) = configured.filter(|value| !value.trim().is_empty()) {
        return configured;
    }

    if let Some(hostname) = hostname
        .map(str::trim)
        .filter(|hostname| !hostname.is_empty() && *hostname != "unknown")
    {
        return hostname.to_string();
    }

    stable_machine_fingerprint()
}

fn stable_machine_fingerprint() -> String {
    let mut candidates = Vec::new();

    for key in [
        "COMPUTERNAME",
        "HOSTNAME",
        "USER",
        "USERNAME",
        "HOME",
        "USERPROFILE",
    ] {
        if let Ok(value) = std::env::var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                candidates.push(format!("{key}={trimmed}"));
            }
        }
    }

    for path in [
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
        "/sys/class/dmi/id/product_uuid",
    ] {
        if let Ok(value) = std::fs::read_to_string(path) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                candidates.push(format!("{path}={trimmed}"));
            }
        }
    }

    if candidates.is_empty() {
        if let Ok(exe) = std::env::current_exe() {
            candidates.push(format!("exe={}", exe.display()));
        }
    }

    let seed = if candidates.is_empty() {
        "nettrap-fallback-machine-fingerprint".to_string()
    } else {
        candidates.join("|")
    };

    let mut hash = 0xcbf29ce484222325u64;
    for byte in seed.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }

    format!("node-{hash:016x}")
}

// ─── Event Sink Trait ────────────────────────────────────────────────────────

/// Trait for shipping events to external systems
#[async_trait::async_trait]
pub trait EventSink: Send + Sync {
    async fn send(&self, event: &crate::nbi::NetworkBehaviorIndicator) -> SinkSendResult;
    async fn flush(&self) -> Result<(), String>;
    async fn flush_stale(&self) -> Result<bool, String> {
        Ok(false)
    }
    fn name(&self) -> &'static str;
    fn buffered_events(&self) -> usize {
        0
    }

    fn buffered_event_ids(&self) -> Vec<String> {
        Vec::new()
    }

    fn drop_buffered_events(&self, _event_ids: &HashSet<String>) -> usize {
        0
    }

    fn take_unknown_event_ids(&self) -> Vec<String> {
        Vec::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkDeliveryState {
    Delivered,
    Buffered,
    Lost,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct SinkSendResult {
    pub state: SinkDeliveryState,
    pub error: Option<String>,
}

impl SinkSendResult {
    pub(crate) fn delivered() -> Self {
        Self {
            state: SinkDeliveryState::Delivered,
            error: None,
        }
    }

    pub(crate) fn buffered(error: Option<String>) -> Self {
        Self {
            state: SinkDeliveryState::Buffered,
            error,
        }
    }

    pub(crate) fn lost(error: impl Into<String>) -> Self {
        Self {
            state: SinkDeliveryState::Lost,
            error: Some(error.into()),
        }
    }

    pub(crate) fn unknown(error: impl Into<String>) -> Self {
        Self {
            state: SinkDeliveryState::Unknown,
            error: Some(error.into()),
        }
    }
}

// ─── Webhook/HTTP Sink ───────────────────────────────────────────────────────

/// Ships events to an HTTP endpoint (webhooks, Elasticsearch, Splunk HEC, etc.)
pub struct HttpSink {
    url: String,
    auth_header: Option<String>,
    client: reqwest::Client,
    state: parking_lot::Mutex<HttpSinkState>,
    pending: AtomicUsize,
    pending_event_ids: parking_lot::RwLock<HashSet<String>>,
    unknown_event_ids: parking_lot::Mutex<HashSet<String>>,
    batch_size: usize,
    flush_interval: std::time::Duration,
    request_timeout: std::time::Duration,
}

#[derive(Clone)]
struct BufferedHttpEvent {
    event_id: String,
    json: String,
}

struct HttpSinkState {
    batch: Vec<BufferedHttpEvent>,
    oldest_event_at: Option<tokio::time::Instant>,
    flushing: bool,
}

struct HttpBatchSendOutcome {
    failed_events: Vec<BufferedHttpEvent>,
    unknown_event_ids: HashSet<String>,
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
            pending_event_ids: parking_lot::RwLock::new(HashSet::new()),
            unknown_event_ids: parking_lot::Mutex::new(HashSet::new()),
            batch_size: if batch_size == 0 { 100 } else { batch_size },
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
        // Send each event individually for maximum compatibility
        // (ES _doc, Splunk HEC, generic webhooks all expect single objects)
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
                }
                Ok(Ok(resp)) if !resp.status().is_success() => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
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
                    failed_events.push(event);
                }
                _ => {}
            }
        }
        HttpBatchSendOutcome {
            failed_events,
            unknown_event_ids,
            error: (!errors.is_empty()).then(|| errors.join("; ")),
        }
    }

    async fn flush_due_to(&self, stale_only: bool) -> Result<bool, String> {
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

        let sent_len = events.len();
        let outcome = self.send_batch(events).await;

        let mut state = self.state.lock();
        state.flushing = false;
        let drain_len = sent_len.min(state.batch.len());
        let remaining_batch = if state.batch.len() > drain_len {
            state.batch.split_off(drain_len)
        } else {
            Vec::new()
        };
        state.batch = outcome.failed_events;
        state.batch.extend(remaining_batch);
        self.pending.store(state.batch.len(), Ordering::Relaxed);
        let pending_ids = state
            .batch
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<HashSet<_>>();
        *self.pending_event_ids.write() = pending_ids;
        self.unknown_event_ids
            .lock()
            .extend(outcome.unknown_event_ids);
        state.oldest_event_at = if state.batch.is_empty() {
            None
        } else {
            Some(tokio::time::Instant::now())
        };

        match outcome.error {
            Some(error) => Err(error),
            None => Ok(true),
        }
    }
}

#[async_trait::async_trait]
impl EventSink for HttpSink {
    async fn send(&self, event: &crate::nbi::NetworkBehaviorIndicator) -> SinkSendResult {
        let json = match serde_json::to_string(event) {
            Ok(json) => json,
            Err(err) => return SinkSendResult::lost(err.to_string()),
        };
        let event_id = event.normalized_event_id();
        let should_flush = {
            let mut state = self.state.lock();
            if state.batch.is_empty() {
                state.oldest_event_at = Some(tokio::time::Instant::now());
            }
            state.batch.push(BufferedHttpEvent {
                event_id: event_id.clone(),
                json,
            });
            self.pending.fetch_add(1, Ordering::Relaxed);
            self.pending_event_ids.write().insert(event_id.clone());
            !state.flushing
                && (state.batch.len() >= self.batch_size
                    || state
                        .oldest_event_at
                        .is_some_and(|oldest| oldest.elapsed() >= self.flush_interval))
        };
        let mut flush_error = None;
        if should_flush {
            if let Err(err) = self.flush_due_to(false).await {
                flush_error = Some(err);
            }
        }
        let still_buffered = self.pending_event_ids.read().contains(&event_id);
        let is_unknown = self.unknown_event_ids.lock().contains(&event_id);
        if still_buffered {
            SinkSendResult::buffered(flush_error)
        } else if is_unknown {
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

    async fn flush(&self) -> Result<(), String> {
        let _ = self.flush_due_to(false).await?;
        Ok(())
    }

    async fn flush_stale(&self) -> Result<bool, String> {
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
        *self.pending_event_ids.write() = state
            .batch
            .iter()
            .map(|event| event.event_id.clone())
            .collect();
        if state.batch.is_empty() {
            state.oldest_event_at = None;
        }
        self.unknown_event_ids
            .lock()
            .retain(|event_id| !event_ids.contains(event_id));
        dropped
    }

    fn take_unknown_event_ids(&self) -> Vec<String> {
        let mut unknown_event_ids = self.unknown_event_ids.lock();
        unknown_event_ids.drain().collect()
    }
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

#[async_trait::async_trait]
impl EventSink for TcpSink {
    async fn send(&self, event: &crate::nbi::NetworkBehaviorIndicator) -> SinkSendResult {
        let json = match serde_json::to_string(event) {
            Ok(json) => json,
            Err(err) => return SinkSendResult::lost(err.to_string()),
        };
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
        if let Some(ref mut stream) = *conn {
            if stream.write_all(line.as_bytes()).await.is_err() {
                // Connection lost, drop it so next send reconnects
                *conn = None;
                return SinkSendResult::lost("TCP sink write failed, will reconnect");
            }
        }
        SinkSendResult::delivered()
    }

    async fn flush(&self) -> Result<(), String> {
        let mut conn = self.connection.lock().await;
        if let Some(ref mut stream) = *conn {
            stream
                .flush()
                .await
                .map_err(|e| format!("TCP sink flush error: {}", e))?;
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

#[async_trait::async_trait]
impl EventSink for SyslogUdpSink {
    async fn send(&self, event: &crate::nbi::NetworkBehaviorIndicator) -> SinkSendResult {
        let severity = 6u8; // INFO
        let priority = (self.facility * 8) + severity;
        let timestamp = &event.timestamp;
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_default();
        let msg = match serde_json::to_string(event) {
            Ok(msg) => msg,
            Err(err) => return SinkSendResult::lost(err.to_string()),
        };
        let syslog_msg = format!(
            "<{}>1 {} {} NetTrap - - - {}",
            priority, timestamp, hostname, msg
        );

        let mut sock = self.socket.lock().await;
        if sock.is_none() {
            let s = tokio::net::UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("Syslog UDP bind error: {}", e));
            let s = match s {
                Ok(socket) => socket,
                Err(err) => return SinkSendResult::lost(err),
            };
            let s = match s.connect(&self.addr).await {
                Ok(()) => s,
                Err(err) => {
                    return SinkSendResult::lost(format!("Syslog UDP connect error: {}", err));
                }
            };
            *sock = Some(s);
        }
        if let Some(ref socket) = *sock {
            if let Err(err) = socket.send(syslog_msg.as_bytes()).await {
                *sock = None;
                return SinkSendResult::lost(format!("Syslog send error: {}", err));
            }
        }
        SinkSendResult::delivered()
    }

    async fn flush(&self) -> Result<(), String> {
        Ok(())
    }
    fn name(&self) -> &'static str {
        "syslog"
    }
}

// ─── Multi-Sink Fanout ───────────────────────────────────────────────────────

/// Sends events to multiple sinks simultaneously
pub struct EventFanout {
    sinks: Vec<Box<dyn EventSink>>,
    runtime_health: RwLock<FanoutRuntimeHealth>,
    consecutive_failures: AtomicU32,
    pending_records: parking_lot::Mutex<HashMap<String, EventDeliveryTracker>>,
    terminally_dropped_event_ids: parking_lot::Mutex<HashSet<String>>,
    last_observed_error: RwLock<Option<String>>,
}

#[derive(Debug, Default)]
struct EventDeliveryTracker {
    queued: bool,
    in_flight: bool,
    buffered_by: HashSet<usize>,
    delivered: bool,
    unknown: bool,
    unknown_reported: bool,
}

#[derive(Clone, Default)]
enum FanoutRuntimeHealth {
    #[default]
    None,
    Active(Arc<nettrap_api::RuntimeHealth>),
    Retired(Arc<nettrap_api::RuntimeHealth>),
}

impl EventFanout {
    pub fn new() -> Self {
        Self {
            sinks: Vec::new(),
            runtime_health: RwLock::new(FanoutRuntimeHealth::None),
            consecutive_failures: AtomicU32::new(0),
            pending_records: parking_lot::Mutex::new(HashMap::new()),
            terminally_dropped_event_ids: parking_lot::Mutex::new(HashSet::new()),
            last_observed_error: RwLock::new(None),
        }
    }

    pub fn add_sink(&mut self, sink: Box<dyn EventSink>) {
        tracing::info!("Event sink registered: {}", sink.name());
        self.sinks.push(sink);
    }

    pub fn attach_runtime_health(&self, runtime_health: Arc<nettrap_api::RuntimeHealth>) {
        *self.runtime_health.write() = FanoutRuntimeHealth::Active(Arc::clone(&runtime_health));
        if let Some(error) = self.last_observed_error.read().clone() {
            runtime_health.set_distributed_export_degraded(format!(
                "distributed export previously failed before runtime health attachment: {}",
                error
            ));
        } else if self.has_sinks() {
            runtime_health.set_distributed_export_running();
        } else {
            runtime_health.set_distributed_export_disabled();
        }
    }

    pub fn attach_retired_runtime_health(&self, runtime_health: Arc<nettrap_api::RuntimeHealth>) {
        *self.runtime_health.write() = FanoutRuntimeHealth::Retired(runtime_health);
        if let Some(error) = self.last_observed_error.read().clone() {
            if let FanoutRuntimeHealth::Retired(runtime_health) = self.runtime_health.read().clone()
            {
                runtime_health.set_distributed_export_degraded(format!(
                    "retired distributed export failed while draining backlog: {}",
                    error
                ));
            }
        }
    }

    pub fn clear_runtime_health(&self) {
        *self.runtime_health.write() = FanoutRuntimeHealth::None;
    }

    pub fn retire_runtime_health(&self) {
        let mut binding = self.runtime_health.write();
        if let FanoutRuntimeHealth::Active(runtime_health) = &*binding {
            *binding = FanoutRuntimeHealth::Retired(Arc::clone(runtime_health));
        }
    }

    pub fn has_sinks(&self) -> bool {
        !self.sinks.is_empty()
    }

    pub fn pending_events(&self) -> usize {
        self.pending_event_ids().len()
    }

    pub fn note_queued_record(&self, event_id: &str) {
        self.terminally_dropped_event_ids.lock().remove(event_id);
        let mut pending = self.pending_records.lock();
        let tracker = pending.entry(event_id.to_string()).or_default();
        tracker.queued = true;
        tracker.in_flight = false;
        tracker.buffered_by.clear();
        tracker.delivered = false;
        tracker.unknown = false;
        tracker.unknown_reported = false;
    }

    pub fn note_send_started(&self, event_id: &str) {
        let mut pending = self.pending_records.lock();
        let tracker = pending.entry(event_id.to_string()).or_default();
        tracker.queued = false;
        tracker.in_flight = true;
    }

    pub fn note_dequeued_record(&self, event_id: &str) -> SendCompletion {
        let mut pending = self.pending_records.lock();
        let Some(tracker) = pending.get_mut(event_id) else {
            return SendCompletion::default();
        };
        tracker.queued = false;
        tracker.in_flight = false;
        let became_unknown = if tracker.unknown && !tracker.unknown_reported {
            tracker.unknown_reported = true;
            true
        } else {
            false
        };
        let final_loss = Self::finalize_tracker_if_resolved(&mut pending, event_id);
        SendCompletion {
            final_loss,
            became_unknown,
        }
    }

    pub fn mark_inflight_unknown(&self) -> usize {
        let mut pending = self.pending_records.lock();
        let mut newly_unknown = 0;
        for tracker in pending.values_mut() {
            if tracker.in_flight {
                tracker.in_flight = false;
                tracker.unknown = true;
                tracker.buffered_by.clear();
                if !tracker.unknown_reported {
                    tracker.unknown_reported = true;
                    newly_unknown += 1;
                }
            }
        }
        newly_unknown
    }

    pub fn consume_unknown_sink_events(&self) -> usize {
        let mut unknown_ids = HashSet::new();
        for sink in &self.sinks {
            unknown_ids.extend(sink.take_unknown_event_ids());
        }
        if unknown_ids.is_empty() {
            return 0;
        }

        let current_buffered = self.current_sink_buffered_event_ids();
        let terminally_dropped = self.terminally_dropped_event_ids.lock().clone();
        let mut pending = self.pending_records.lock();
        Self::sync_pending_records_with_buffers(
            &mut pending,
            &current_buffered,
            &terminally_dropped,
        );

        let mut newly_unknown = 0;
        for event_id in unknown_ids {
            if terminally_dropped.contains(&event_id) {
                continue;
            }
            let tracker = pending.entry(event_id).or_default();
            tracker.queued = false;
            tracker.in_flight = false;
            tracker.unknown = true;
            tracker.buffered_by.clear();
            if !tracker.unknown_reported {
                tracker.unknown_reported = true;
                newly_unknown += 1;
            }
        }
        newly_unknown
    }

    pub fn drop_queued_records(&self) -> usize {
        let current_buffered = self.current_sink_buffered_event_ids();
        let mut terminally_dropped = self.terminally_dropped_event_ids.lock();
        let mut pending = self.pending_records.lock();
        Self::sync_pending_records_with_buffers(
            &mut pending,
            &current_buffered,
            &terminally_dropped,
        );
        let queued_ids = pending
            .iter()
            .filter_map(|(event_id, tracker)| tracker.queued.then_some(event_id.clone()))
            .collect::<HashSet<_>>();
        let mut lost = 0;
        for event_id in &queued_ids {
            terminally_dropped.insert(event_id.clone());
            if let Some(tracker) = pending.get_mut(event_id) {
                tracker.queued = false;
                tracker.buffered_by.clear();
            }
            lost += usize::from(Self::finalize_tracker_if_resolved(&mut pending, event_id));
        }
        drop(pending);
        drop(terminally_dropped);
        self.purge_buffered_events(&queued_ids);
        lost
    }

    pub fn drop_pending_records(&self) -> usize {
        let current_buffered = self.current_sink_buffered_event_ids();
        let mut terminally_dropped = self.terminally_dropped_event_ids.lock();
        let mut pending = self.pending_records.lock();
        Self::sync_pending_records_with_buffers(
            &mut pending,
            &current_buffered,
            &terminally_dropped,
        );
        let all_ids = pending.keys().cloned().collect::<HashSet<_>>();
        let mut lost = 0;
        for event_id in &all_ids {
            let count_as_loss = pending.get(event_id).is_some_and(|tracker| {
                !tracker.in_flight
                    && !tracker.unknown
                    && (tracker.queued || !tracker.buffered_by.is_empty())
            });
            if count_as_loss {
                terminally_dropped.insert(event_id.clone());
            }
            if let Some(tracker) = pending.remove(event_id) {
                if count_as_loss && !tracker.delivered {
                    lost += 1;
                }
            }
        }
        drop(pending);
        drop(terminally_dropped);
        self.purge_buffered_events(&all_ids);
        lost
    }

    fn pending_event_ids(&self) -> HashSet<String> {
        let current_buffered = self.current_sink_buffered_event_ids();
        let terminally_dropped = self.terminally_dropped_event_ids.lock().clone();
        let mut pending = self.pending_records.lock();
        Self::sync_pending_records_with_buffers(
            &mut pending,
            &current_buffered,
            &terminally_dropped,
        );
        let resolved_ids = pending
            .keys()
            .filter(|event_id| {
                pending.get(*event_id).is_some_and(|tracker| {
                    !tracker.queued
                        && !tracker.in_flight
                        && !tracker.unknown
                        && tracker.buffered_by.is_empty()
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        for event_id in resolved_ids {
            let _ = Self::finalize_tracker_if_resolved(&mut pending, &event_id);
        }
        pending
            .iter()
            .filter_map(|(event_id, tracker)| {
                (tracker.queued || tracker.in_flight || !tracker.buffered_by.is_empty())
                    .then_some(event_id.clone())
            })
            .collect()
    }

    pub fn has_pending_event(&self, event_id: &str) -> bool {
        self.pending_event_ids().contains(event_id)
    }

    pub async fn send(&self, event: &crate::nbi::NetworkBehaviorIndicator) -> FanoutSendOutcome {
        let mut errors = Vec::new();
        let event_id = event.normalized_event_id();
        let mut sink_states = Vec::with_capacity(self.sinks.len());

        for (sink_idx, sink) in self.sinks.iter().enumerate() {
            let result = sink.send(event).await;
            if let Some(error) = result.error {
                let error = format!("Event sink '{}' error: {}", sink.name(), error);
                tracing::warn!("{}", error);
                errors.push(error);
            }
            sink_states.push((sink_idx, result.state));
        }

        {
            let mut pending = self.pending_records.lock();
            let tracker = pending.entry(event_id).or_default();
            for (sink_idx, state) in sink_states {
                match state {
                    SinkDeliveryState::Delivered => {
                        tracker.delivered = true;
                        tracker.buffered_by.remove(&sink_idx);
                    }
                    SinkDeliveryState::Buffered => {
                        tracker.buffered_by.insert(sink_idx);
                    }
                    SinkDeliveryState::Lost => {
                        tracker.buffered_by.remove(&sink_idx);
                    }
                    SinkDeliveryState::Unknown => {
                        tracker.unknown = true;
                        tracker.buffered_by.remove(&sink_idx);
                    }
                }
            }
        }

        let error = (!errors.is_empty()).then(|| errors.join("; "));
        self.update_runtime_health(error.clone());
        FanoutSendOutcome { error }
    }

    pub async fn flush_all(&self) -> Result<(), String> {
        let mut errors = Vec::new();

        for sink in &self.sinks {
            if let Err(e) = sink.flush().await {
                tracing::warn!("Event sink '{}' flush error: {}", sink.name(), e);
                errors.push(format!("Event sink '{}' flush error: {}", sink.name(), e));
            }
        }

        self.consume_unknown_sink_events();
        let result = if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        };
        self.refresh_pending_records_from_buffers();
        self.update_runtime_health(result.clone().err());
        result
    }

    pub async fn flush_stale_batches(&self) -> Result<bool, String> {
        let mut errors = Vec::new();
        let mut attempted = false;

        for sink in &self.sinks {
            match sink.flush_stale().await {
                Ok(flushed) => attempted |= flushed,
                Err(err) => {
                    tracing::warn!("Event sink '{}' stale flush error: {}", sink.name(), err);
                    errors.push(format!(
                        "Event sink '{}' stale flush error: {}",
                        sink.name(),
                        err
                    ));
                }
            }
        }

        self.consume_unknown_sink_events();
        if errors.is_empty() {
            if attempted {
                self.refresh_pending_records_from_buffers();
                self.update_runtime_health(None);
            }
            Ok(attempted)
        } else {
            let joined = errors.join("; ");
            self.refresh_pending_records_from_buffers();
            self.update_runtime_health(Some(joined.clone()));
            Err(joined)
        }
    }

    fn current_sink_buffered_event_ids(&self) -> Vec<HashSet<String>> {
        self.sinks
            .iter()
            .map(|sink| sink.buffered_event_ids().into_iter().collect())
            .collect()
    }

    fn refresh_pending_records_from_buffers(&self) {
        let current_buffered = self.current_sink_buffered_event_ids();
        let terminally_dropped = self.terminally_dropped_event_ids.lock().clone();
        let mut pending = self.pending_records.lock();
        Self::sync_pending_records_with_buffers(
            &mut pending,
            &current_buffered,
            &terminally_dropped,
        );
        let resolved_ids = pending
            .keys()
            .filter(|event_id| {
                pending.get(*event_id).is_some_and(|tracker| {
                    !tracker.queued
                        && !tracker.in_flight
                        && !tracker.unknown
                        && tracker.buffered_by.is_empty()
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        for event_id in resolved_ids {
            let _ = Self::finalize_tracker_if_resolved(&mut pending, &event_id);
        }
    }

    fn sync_pending_records_with_buffers(
        pending: &mut HashMap<String, EventDeliveryTracker>,
        current_buffered: &[HashSet<String>],
        terminally_dropped: &HashSet<String>,
    ) {
        pending.retain(|event_id, _| !terminally_dropped.contains(event_id));

        for (sink_idx, event_ids) in current_buffered.iter().enumerate() {
            for event_id in event_ids {
                if terminally_dropped.contains(event_id) {
                    continue;
                }
                pending
                    .entry(event_id.clone())
                    .or_default()
                    .buffered_by
                    .insert(sink_idx);
            }
        }

        let event_ids = pending.keys().cloned().collect::<Vec<_>>();
        for event_id in event_ids {
            if terminally_dropped.contains(&event_id) {
                pending.remove(&event_id);
                continue;
            }
            let Some(tracker) = pending.get_mut(&event_id) else {
                continue;
            };

            let previous_buffered = tracker.buffered_by.clone();
            tracker.buffered_by.retain(|sink_idx| {
                current_buffered
                    .get(*sink_idx)
                    .is_some_and(|event_ids| event_ids.contains(&event_id))
            });
            if previous_buffered
                .iter()
                .any(|sink_idx| !tracker.buffered_by.contains(sink_idx))
            {
                tracker.delivered = true;
            }
        }
    }

    fn finalize_tracker_if_resolved(
        pending: &mut HashMap<String, EventDeliveryTracker>,
        event_id: &str,
    ) -> bool {
        let should_remove = pending.get(event_id).is_some_and(|tracker| {
            !tracker.queued
                && !tracker.in_flight
                && !tracker.unknown
                && tracker.buffered_by.is_empty()
        });
        if !should_remove {
            return false;
        }

        pending
            .remove(event_id)
            .is_some_and(|tracker| !tracker.delivered)
    }

    fn purge_buffered_events(&self, event_ids: &HashSet<String>) {
        if event_ids.is_empty() {
            return;
        }

        for sink in &self.sinks {
            let _ = sink.drop_buffered_events(event_ids);
        }
    }

    fn update_runtime_health(&self, error: Option<String>) {
        match (self.runtime_health.read().clone(), error) {
            (FanoutRuntimeHealth::None, Some(error)) => {
                *self.last_observed_error.write() = Some(error);
            }
            (FanoutRuntimeHealth::None, None) => {
                *self.last_observed_error.write() = None;
            }
            (FanoutRuntimeHealth::Retired(runtime_health), Some(error)) => {
                *self.last_observed_error.write() = Some(error.clone());
                if self.pending_events() > 0 {
                    runtime_health.set_distributed_export_degraded(format!(
                        "retired distributed export failed while draining backlog: {}",
                        error
                    ));
                }
            }
            (FanoutRuntimeHealth::Retired(_), None) => {
                *self.last_observed_error.write() = None;
            }
            (FanoutRuntimeHealth::Active(runtime_health), Some(error)) => {
                *self.last_observed_error.write() = Some(error.clone());
                let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
                if failures >= DISTRIBUTED_EXPORT_FAILURE_LIMIT {
                    runtime_health.set_distributed_export_degraded(format!(
                        "distributed export failed {} consecutive times: {}",
                        DISTRIBUTED_EXPORT_FAILURE_LIMIT, error
                    ));
                }
            }
            (FanoutRuntimeHealth::Active(runtime_health), None) => {
                *self.last_observed_error.write() = None;
                self.consecutive_failures.store(0, Ordering::Relaxed);
                if self.has_sinks() {
                    runtime_health.set_distributed_export_running();
                } else {
                    runtime_health.set_distributed_export_disabled();
                }
            }
        }
    }
}

impl Default for EventFanout {
    fn default() -> Self {
        Self::new()
    }
}

pub struct FanoutSendOutcome {
    pub error: Option<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SendCompletion {
    pub final_loss: bool,
    pub became_unknown: bool,
}

// ─── Build Fanout from Config ────────────────────────────────────────────────

/// Build event fanout from config
pub fn build_event_fanout(config: &DistributedConfig) -> crate::Result<EventFanout> {
    let mut fanout = EventFanout::new();

    for sink_cfg in &config.event_sinks {
        match sink_cfg.sink_type.as_str() {
            "http" | "webhook" | "elasticsearch" | "splunk" => {
                fanout.add_sink(Box::new(HttpSink::new(
                    &sink_cfg.target,
                    sink_cfg.auth.clone(),
                    sink_cfg.batch_size,
                    sink_cfg.flush_interval_ms,
                    sink_cfg.request_timeout_ms,
                )));
            }
            "tcp" | "nats" | "logstash" | "fluentd" => {
                fanout.add_sink(Box::new(TcpSink::new(&sink_cfg.target)));
            }
            "syslog" | "syslog_udp" => {
                fanout.add_sink(Box::new(SyslogUdpSink::new(&sink_cfg.target)));
            }
            other => {
                return Err(crate::Error::Config(format!(
                    "Unknown distributed event sink type: {}",
                    other
                )));
            }
        }
    }

    Ok(fanout)
}

// ─── Health Check Server ─────────────────────────────────────────────────────

fn build_health_response(
    node: &NodeIdentity,
    runtime_health: &nettrap_api::RuntimeHealth,
) -> String {
    let snapshot = runtime_health.snapshot();
    let mut payload = nettrap_api::runtime_health_payload(&snapshot);
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

fn build_metrics_response(
    node: &NodeIdentity,
    runtime_health: &nettrap_api::RuntimeHealth,
) -> String {
    let snapshot = runtime_health.snapshot();
    let up = u8::from(matches!(snapshot.status, nettrap_api::HealthStatus::Ok));
    format!(
        "# HELP nettrap_up Whether NetTrap is operational\n\
         # TYPE nettrap_up gauge\n\
         nettrap_up {}\n\
         # HELP nettrap_info Node information\n\
         # TYPE nettrap_info gauge\n\
         nettrap_info{{node_id=\"{}\",hostname=\"{}\",region=\"{}\"}} 1\n",
        up, node.node_id, node.hostname, node.region
    )
}

fn build_ready_response(ready: bool) -> String {
    serde_json::json!({
        "ready": ready
    })
    .to_string()
}

fn parse_request_path(request: &str) -> Option<(&str, &str)> {
    let request_line = request.lines().next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    Some((method, path))
}

fn route_probe_request(
    request: &str,
    node: &NodeIdentity,
    runtime_health: &nettrap_api::RuntimeHealth,
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
                let ready = matches!(snapshot.status, nettrap_api::HealthStatus::Ok);
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

fn is_transient_accept_error(err: &std::io::Error) -> bool {
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
) -> crate::Result<(tokio::net::TcpListener, std::net::SocketAddr)> {
    let addr = bind.parse::<std::net::SocketAddr>().map_err(|err| {
        crate::Error::Config(format!(
            "Invalid {} bind '{}': {}",
            probe_server_name(server_kind),
            bind,
            err
        ))
    })?;
    let listener = std::net::TcpListener::bind(addr).map_err(|err| {
        crate::Error::Other(format!(
            "Failed to bind {} server on {}: {}",
            probe_server_name(server_kind),
            bind,
            err
        ))
    })?;
    listener.set_nonblocking(true).map_err(|err| {
        crate::Error::Other(format!(
            "Failed to configure {} server on {} as non-blocking: {}",
            probe_server_name(server_kind),
            bind,
            err
        ))
    })?;
    let local_addr = listener.local_addr().map_err(crate::Error::Io)?;
    let listener = tokio::net::TcpListener::from_std(listener).map_err(crate::Error::Io)?;

    Ok((listener, local_addr))
}

async fn run_probe_server(
    listener: tokio::net::TcpListener,
    node: Arc<NodeIdentity>,
    runtime_health: Arc<nettrap_api::RuntimeHealth>,
    server_kind: ProbeServerKind,
) -> crate::Result<()> {
    let mut consecutive_accept_failures = 0u32;

    loop {
        let (mut stream, _) = match listener.accept().await {
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
                    return Err(crate::Error::Other(format!(
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
                return Err(crate::Error::Other(format!(
                    "{} server accept error: {}",
                    probe_server_name(server_kind),
                    err
                )));
            }
        };
        let node = Arc::clone(&node);
        let runtime_health = Arc::clone(&runtime_health);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let request = String::from_utf8_lossy(&buf);
            let (status, content_type, body) =
                route_probe_request(&request, &node, &runtime_health, server_kind);

            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n{}",
                status,
                content_type,
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

pub(crate) fn bind_health_server(
    bind: &str,
) -> crate::Result<(tokio::net::TcpListener, std::net::SocketAddr)> {
    bind_probe_server(bind, ProbeServerKind::Health)
}

pub(crate) fn bind_metrics_server(
    bind: &str,
) -> crate::Result<(tokio::net::TcpListener, std::net::SocketAddr)> {
    bind_probe_server(bind, ProbeServerKind::Metrics)
}

pub async fn serve_health_server(
    listener: tokio::net::TcpListener,
    node: Arc<NodeIdentity>,
    runtime_health: Arc<nettrap_api::RuntimeHealth>,
) -> crate::Result<()> {
    run_probe_server(listener, node, runtime_health, ProbeServerKind::Health).await
}

pub async fn serve_metrics_server(
    listener: tokio::net::TcpListener,
    node: Arc<NodeIdentity>,
    runtime_health: Arc<nettrap_api::RuntimeHealth>,
) -> crate::Result<()> {
    run_probe_server(listener, node, runtime_health, ProbeServerKind::Metrics).await
}

pub async fn run_health_server(
    bind: String,
    node: Arc<NodeIdentity>,
    runtime_health: Arc<nettrap_api::RuntimeHealth>,
) -> crate::Result<()> {
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
    runtime_health: Arc<nettrap_api::RuntimeHealth>,
) -> crate::Result<()> {
    let (listener, local_addr) = bind_metrics_server(&bind)?;
    tracing::info!(
        "{} server on {}",
        probe_server_name(ProbeServerKind::Metrics),
        local_addr
    );
    serve_metrics_server(listener, node, runtime_health).await
}

// ─── Heartbeat ───────────────────────────────────────────────────────────────

/// Periodically sends heartbeat to control plane
pub async fn run_heartbeat(
    control_url: String,
    token: Option<String>,
    node: Arc<NodeIdentity>,
    interval_secs: u64,
) -> crate::Result<()> {
    if interval_secs == 0 {
        return Ok(());
    }

    run_heartbeat_with_interval(
        control_url,
        token,
        node,
        std::time::Duration::from_secs(interval_secs),
        HEARTBEAT_FAILURE_LIMIT,
    )
    .await
}

async fn run_heartbeat_with_interval(
    control_url: String,
    token: Option<String>,
    node: Arc<NodeIdentity>,
    interval: std::time::Duration,
    failure_limit: u32,
) -> crate::Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/heartbeat", control_url);
    let mut consecutive_failures = 0u32;

    loop {
        let payload = serde_json::json!({
            "node_id": node.node_id,
            "hostname": node.hostname,
            "region": node.region,
            "tags": node.tags,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let mut req = client.post(&url).json(&payload);
        if let Some(ref t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }

        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                consecutive_failures = 0;
                tracing::debug!("Heartbeat sent to control plane");
            }
            Ok(resp) => {
                consecutive_failures += 1;
                let message = format!(
                    "Control plane heartbeat rejected ({}/{}): {}",
                    consecutive_failures,
                    failure_limit,
                    resp.status()
                );
                tracing::warn!("{}", message);
                if consecutive_failures >= failure_limit {
                    return Err(crate::Error::Other(format!(
                        "Control plane heartbeat failed {} consecutive times: {}",
                        failure_limit,
                        resp.status()
                    )));
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                let message = format!(
                    "Control plane heartbeat failed ({}/{}): {}",
                    consecutive_failures, failure_limit, e
                );
                tracing::warn!("{}", message);
                if consecutive_failures >= failure_limit {
                    return Err(crate::Error::Other(format!(
                        "Control plane heartbeat failed {} consecutive times: {}",
                        failure_limit, e
                    )));
                }
            }
        }

        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashSet, VecDeque};
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    struct BufferedCountSink {
        pending_ids: Arc<Mutex<HashSet<String>>>,
    }

    #[async_trait::async_trait]
    impl EventSink for BufferedCountSink {
        async fn send(&self, _event: &crate::nbi::NetworkBehaviorIndicator) -> SinkSendResult {
            SinkSendResult::delivered()
        }

        async fn flush(&self) -> Result<(), String> {
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
                            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n\r\n{}",
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

    async fn spawn_partially_failing_event_sink_server(
        failing_request: usize,
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind partial failure event sink server");
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
                        let request_number = request_count.fetch_add(1, Ordering::Relaxed) + 1;
                        let status = if request_number == failing_request {
                            "500 Internal Server Error"
                        } else {
                            "200 OK"
                        };
                        let body = "{}";
                        let response = format!(
                            "HTTP/1.1 {}\r\nContent-Length: {}\r\n\r\n{}",
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
    fn build_event_fanout_rejects_unknown_sink_types() {
        let mut config = DistributedConfig::default();
        config.event_sinks.push(crate::config::EventSinkConfig {
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
    fn attach_runtime_health_marks_configured_export_running() {
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        let mut fanout = EventFanout::new();
        fanout.add_sink(Box::new(SyslogUdpSink::new("127.0.0.1:1")));

        fanout.attach_runtime_health(Arc::clone(&runtime_health));

        assert_eq!(
            runtime_health.snapshot().distributed_export.state,
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
    async fn http_sink_flushes_stale_batch_by_time() {
        let (url, request_count, server) = spawn_event_sink_server().await;
        let sink = HttpSink::new(url, None, 10, 25, 1_000);
        let event = crate::nbi::raw_nbi(
            "raw",
            "127.0.0.1",
            12345,
            &crate::session::SessionDestination::unknown(8080),
            4,
            "",
        );

        let result = sink.send(&event).await;
        assert_eq!(result.state, SinkDeliveryState::Buffered);
        assert_eq!(result.error, None);
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        assert!(
            sink.flush_stale()
                .await
                .expect("stale flush should succeed")
        );

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while request_count.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("HTTP sink should flush stale batch");
        assert_eq!(sink.buffered_events(), 0);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn http_sink_retries_only_failed_events_after_partial_batch_failure() {
        let (url, request_count, server) = spawn_partially_failing_event_sink_server(10).await;
        let sink = HttpSink::new(url, None, 10, 1_000, 1_000);

        for idx in 0..9 {
            let event = crate::nbi::raw_nbi(
                "raw",
                "127.0.0.1",
                12000 + idx,
                &crate::session::SessionDestination::unknown(8080),
                4,
                "",
            );
            let result = sink.send(&event).await;
            assert_eq!(result.state, SinkDeliveryState::Buffered);
            assert_eq!(result.error, None);
        }

        let failing_event = crate::nbi::raw_nbi(
            "raw",
            "127.0.0.1",
            12009,
            &crate::session::SessionDestination::unknown(8080),
            4,
            "",
        );
        let result = sink.send(&failing_event).await;
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("responded with 500")
        );

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while request_count.load(Ordering::Relaxed) < 10 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("HTTP sink should attempt the full initial batch");
        assert_eq!(sink.buffered_events(), 1);

        sink.flush()
            .await
            .expect("retry should send only the failed event");
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while request_count.load(Ordering::Relaxed) < 11 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("HTTP sink should retry only the failed event");
        assert_eq!(sink.buffered_events(), 0);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn http_sink_request_timeout_marks_delivery_unknown() {
        let (url, server) = spawn_hanging_event_sink_server().await;
        let sink = HttpSink::new(url, None, 1, 1_000, 25);
        let event = crate::nbi::raw_nbi(
            "raw",
            "127.0.0.1",
            12500,
            &crate::session::SessionDestination::unknown(8080),
            4,
            "",
        );
        let event_id = event.normalized_event_id();

        let result = sink.send(&event).await;

        assert_eq!(result.state, SinkDeliveryState::Unknown);
        assert_eq!(sink.buffered_events(), 0);
        assert_eq!(sink.take_unknown_event_ids(), vec![event_id]);

        server.abort();
        let _ = server.await;
    }

    #[test]
    fn transient_probe_accept_errors_are_retryable_until_limit() {
        let err = std::io::Error::from(std::io::ErrorKind::WouldBlock);
        assert!(is_transient_accept_error(&err));

        let err = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert!(!is_transient_accept_error(&err));
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
}
