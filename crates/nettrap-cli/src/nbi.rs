use crate::session::SessionDestination;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

fn default_unknown_dst_ip() -> String {
    "0.0.0.0".to_string()
}

fn default_empty_event_id() -> String {
    String::new()
}

fn should_normalize_legacy_event_id(event_id: &str) -> bool {
    let event_id = event_id.trim();
    event_id.is_empty() || event_id.starts_with("legacy-db-")
}

fn legacy_event_id_from_fingerprint(content_fingerprint: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in content_fingerprint.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("legacy-{hash:016x}")
}

const NBI_LOCAL_QUEUE_CAPACITY: usize = 1024;
const NBI_EXPORT_QUEUE_CAPACITY: usize = 1024;
const NBI_WORKER_SUPERVISOR_INTERVAL_MS: u64 = 250;
#[cfg(not(test))]
const NBI_EXPORT_OPERATION_TIMEOUT_MS: u64 = 5000;
#[cfg(test)]
const NBI_EXPORT_OPERATION_TIMEOUT_MS: u64 = 100;

enum LocalWorkerCommand {
    Record(NetworkBehaviorIndicator),
    Flush(tokio::sync::oneshot::Sender<()>),
}

enum ExportWorkerCommand {
    Record(
        NetworkBehaviorIndicator,
        Arc<crate::distributed::EventFanout>,
    ),
    Flush(
        Option<Arc<crate::distributed::EventFanout>>,
        tokio::sync::oneshot::Sender<Result<(), String>>,
    ),
    Shutdown(tokio::sync::oneshot::Sender<()>),
}

struct LocalPersistOutcome {
    file_configured: bool,
    db_configured: bool,
    file_persisted: bool,
    db_persisted: bool,
    file_error: Option<String>,
    db_error: Option<String>,
}

impl LocalPersistOutcome {
    fn any_target_configured(&self) -> bool {
        self.file_configured || self.db_configured
    }

    fn any_success(&self) -> bool {
        self.file_persisted || self.db_persisted
    }

    fn is_total_failure(&self) -> bool {
        self.any_target_configured() && !self.any_success()
    }

    fn error_summary(&self) -> Option<String> {
        let mut errors = Vec::new();
        if let Some(error) = &self.file_error {
            errors.push(error.clone());
        }
        if let Some(error) = &self.db_error {
            errors.push(error.clone());
        }

        if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        }
    }
}

struct WorkerSlot<C> {
    tx: parking_lot::RwLock<tokio::sync::mpsc::Sender<C>>,
    rx: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<C>>>,
    handle: Arc<parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    queued: Arc<AtomicUsize>,
    dropped: Arc<AtomicU64>,
}

impl<C> WorkerSlot<C> {
    fn new(capacity: usize) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        Self {
            tx: parking_lot::RwLock::new(tx),
            rx: std::sync::Mutex::new(Some(rx)),
            handle: Arc::new(parking_lot::Mutex::new(None)),
            queued: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    fn sender(&self) -> tokio::sync::mpsc::Sender<C> {
        self.tx.read().clone()
    }

    fn ensure_receiver(&self, capacity: usize) -> Option<tokio::sync::mpsc::Receiver<C>> {
        let mut guard = self.rx.lock().expect("worker rx lock poisoned");
        if guard.is_none() {
            let (tx, rx) = tokio::sync::mpsc::channel(capacity);
            *self.tx.write() = tx;
            *guard = Some(rx);
        }
        guard.take()
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct ExportWorkerInterruption {
    dropped: u64,
    unknown: u64,
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Network Behavior Indicator - structured per-protocol telemetry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBehaviorIndicator {
    #[serde(default = "default_empty_event_id")]
    pub event_id: String,
    pub timestamp: String,
    pub listener: String,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: u16,
    #[serde(default = "default_unknown_dst_ip")]
    pub dst_ip: String,
    pub dst_port: u16,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub indicators: HashMap<String, String>,
}

impl NetworkBehaviorIndicator {
    pub fn new(
        listener: &str,
        protocol: &str,
        src_ip: &str,
        src_port: u16,
        destination: &SessionDestination,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            listener: listener.to_string(),
            protocol: protocol.to_string(),
            src_ip: src_ip.to_string(),
            src_port,
            dst_ip: destination.ip.clone(),
            dst_port: destination.port,
            process_name: None,
            process_pid: None,
            indicators: HashMap::new(),
        }
    }

    pub fn with_process(mut self, name: Option<String>, pid: Option<u32>) -> Self {
        self.process_name = name;
        self.process_pid = pid;
        self
    }

    pub fn add(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.indicators.insert(key.into(), value.into());
    }

    pub fn with_fresh_event_id(mut self) -> Self {
        self.event_id = uuid::Uuid::new_v4().to_string();
        self
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn content_fingerprint(&self) -> String {
        let mut indicators: Vec<_> = self.indicators.iter().collect();
        indicators
            .sort_unstable_by(|left, right| left.0.cmp(right.0).then_with(|| left.1.cmp(right.1)));

        serde_json::to_string(&(
            &self.timestamp,
            &self.listener,
            &self.protocol,
            &self.src_ip,
            self.src_port,
            &self.dst_ip,
            self.dst_port,
            &self.process_name,
            self.process_pid,
            indicators,
        ))
        .unwrap_or_default()
    }

    pub fn normalized_event_id(&self) -> String {
        if should_normalize_legacy_event_id(&self.event_id) {
            legacy_event_id_from_fingerprint(&self.content_fingerprint())
        } else {
            self.event_id.clone()
        }
    }
}

/// Build NBI for DNS query
pub fn dns_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    domain: &str,
    query_type: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "DNS", src_ip, src_port, destination);
    nbi.add("query_type", query_type);
    nbi.add("domain", domain);
    nbi
}

/// Build NBI for HTTP request
pub fn http_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    method: &str,
    uri: &str,
    host: &str,
    user_agent: &str,
    body_len: usize,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "HTTP", src_ip, src_port, destination);
    nbi.add("method", method);
    nbi.add("uri", uri);
    nbi.add("host", host);
    nbi.add("user_agent", user_agent);
    if body_len > 0 {
        nbi.add("body_length", body_len.to_string());
    }
    nbi
}

/// Build NBI for SMTP command
pub fn smtp_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    command: &str,
    args: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "SMTP", src_ip, src_port, destination);
    nbi.add("command", command);
    if !args.is_empty() {
        nbi.add("args", args);
    }
    nbi
}

/// Build NBI for FTP command
pub fn ftp_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    command: &str,
    args: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "FTP", src_ip, src_port, destination);
    nbi.add("command", command);
    if !args.is_empty() {
        nbi.add("args", args);
    }
    nbi
}

/// Build NBI for POP3 command
pub fn pop3_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    command: &str,
    args: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "POP3", src_ip, src_port, destination);
    nbi.add("command", command);
    if !args.is_empty() {
        nbi.add("args", args);
    }
    nbi
}

/// Build NBI for IRC command
pub fn irc_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    nick: &str,
    command: &str,
    args: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "IRC", src_ip, src_port, destination);
    nbi.add("nick", nick);
    nbi.add("command", command);
    if !args.is_empty() {
        nbi.add("args", args);
    }
    nbi
}

/// Build NBI for TFTP request
pub fn tftp_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    operation: &str,
    filename: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "TFTP", src_ip, src_port, destination);
    nbi.add("operation", operation);
    if !filename.is_empty() {
        nbi.add("filename", filename);
    }
    nbi
}

/// Build NBI for raw/unknown data
pub fn raw_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    data_len: usize,
    hexdump_preview: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "RAW", src_ip, src_port, destination);
    nbi.add("data_length", data_len.to_string());
    if !hexdump_preview.is_empty() {
        nbi.add("hexdump", hexdump_preview);
    }
    nbi
}

/// Build NBI for TLS connection
pub fn tls_nbi(
    listener: &str,
    src_ip: &str,
    src_port: u16,
    destination: &SessionDestination,
    sni: &str,
) -> NetworkBehaviorIndicator {
    let mut nbi = NetworkBehaviorIndicator::new(listener, "TLS", src_ip, src_port, destination);
    if !sni.is_empty() {
        nbi.add("sni", sni);
    }
    nbi
}

/// Print NBI summary to console
pub fn print_summary(nbi_jsonl_path: &std::path::Path) {
    let content = match std::fs::read_to_string(nbi_jsonl_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    let nbis: Vec<NetworkBehaviorIndicator> = content
        .lines()
        .filter_map(|line| serde_json::from_str::<NetworkBehaviorIndicator>(line).ok())
        .collect();
    print_summary_from_events(&nbis);
}

pub fn print_summary_from_events(nbis: &[NetworkBehaviorIndicator]) {
    let mut protocol_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut unique_ips: std::collections::HashSet<String> = std::collections::HashSet::new();

    for nbi in nbis {
        *protocol_counts.entry(nbi.protocol.clone()).or_insert(0) += 1;
        unique_ips.insert(nbi.src_ip.clone());
    }

    if nbis.is_empty() {
        return;
    }

    println!("\n=== NetTrap NBI Summary ===");
    println!("Total events:    {}", nbis.len());
    println!("Unique sources:  {}", unique_ips.len());
    println!("Protocols:");
    let mut sorted: Vec<_> = protocol_counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (proto, count) in sorted {
        println!("  {:<10} {}", proto, count);
    }
    println!("===========================\n");
}

/// NBI collector that writes to JSONL file and optionally fans out to distributed sinks
pub struct NbiCollector {
    path: Option<PathBuf>,
    fanout: Arc<parking_lot::RwLock<Option<Arc<crate::distributed::EventFanout>>>>,
    retired_fanouts: Arc<parking_lot::RwLock<Vec<Arc<crate::distributed::EventFanout>>>>,
    runtime_health: Arc<parking_lot::RwLock<Option<Arc<nettrap_api::RuntimeHealth>>>>,
    database: Arc<parking_lot::RwLock<Option<Arc<crate::database::DatabaseBackend>>>>,
    session_tracker: Arc<parking_lot::RwLock<Option<Arc<crate::session::SessionTracker>>>>,
    listener_protocols: Arc<
        parking_lot::RwLock<std::collections::HashMap<String, nettrap_core::prelude::Protocol>>,
    >,
    local_worker: WorkerSlot<LocalWorkerCommand>,
    export_worker: WorkerSlot<ExportWorkerCommand>,
    export_rejected: Arc<AtomicU64>,
    export_unknown: Arc<AtomicU64>,
    worker_restarts: Arc<AtomicU64>,
    last_worker_error: Arc<parking_lot::RwLock<Option<String>>>,
    local_persist_failures: Arc<AtomicU64>,
    last_local_persist_error: Arc<parking_lot::RwLock<Option<String>>>,
    supervisor_handle: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NbiCollectorSnapshot {
    pub local_queue_depth: usize,
    pub export_queue_depth: usize,
    pub local_dropped: u64,
    pub export_dropped: u64,
    pub export_rejected: u64,
    pub export_unknown: u64,
    pub local_persist_failures: u64,
    pub worker_restarts: u64,
    pub last_worker_error: Option<String>,
    pub last_local_persist_error: Option<String>,
}

impl NbiCollector {
    pub fn new(path: Option<PathBuf>) -> Self {
        let collector = Self {
            path,
            fanout: Arc::new(parking_lot::RwLock::new(None)),
            retired_fanouts: Arc::new(parking_lot::RwLock::new(Vec::new())),
            runtime_health: Arc::new(parking_lot::RwLock::new(None)),
            database: Arc::new(parking_lot::RwLock::new(None)),
            session_tracker: Arc::new(parking_lot::RwLock::new(None)),
            listener_protocols: Arc::new(
                parking_lot::RwLock::new(std::collections::HashMap::new()),
            ),
            local_worker: WorkerSlot::new(NBI_LOCAL_QUEUE_CAPACITY),
            export_worker: WorkerSlot::new(NBI_EXPORT_QUEUE_CAPACITY),
            export_rejected: Arc::new(AtomicU64::new(0)),
            export_unknown: Arc::new(AtomicU64::new(0)),
            worker_restarts: Arc::new(AtomicU64::new(0)),
            last_worker_error: Arc::new(parking_lot::RwLock::new(None)),
            local_persist_failures: Arc::new(AtomicU64::new(0)),
            last_local_persist_error: Arc::new(parking_lot::RwLock::new(None)),
            supervisor_handle: parking_lot::Mutex::new(None),
        };
        if collector.has_local_persistence_target() {
            let _ = collector.ensure_local_worker_started();
        }
        collector.ensure_supervisor_started();
        collector
    }

    /// Attach a distributed event fanout (only stored if it has active sinks)
    pub fn with_fanout(self, fanout: std::sync::Arc<crate::distributed::EventFanout>) -> Self {
        self.attach_fanout(fanout);
        self
    }

    /// Attach or replace a distributed event fanout on a shared collector.
    pub fn attach_fanout(&self, fanout: std::sync::Arc<crate::distributed::EventFanout>) {
        let previous_fanout = self.fanout.read().clone();
        if fanout.has_sinks() {
            if previous_fanout
                .as_ref()
                .is_some_and(|existing| Arc::ptr_eq(existing, &fanout))
            {
                if let Some(runtime_health) = self.runtime_health.read().clone() {
                    fanout.attach_runtime_health(runtime_health);
                }
                self.ensure_supervisor_started();
                return;
            }

            let retiring_backlog = previous_fanout
                .as_ref()
                .map(|existing| self.pending_export_backlog(existing))
                .unwrap_or(0);

            if let Some(previous_fanout) = previous_fanout.as_ref() {
                previous_fanout.retire_runtime_health();
                if retiring_backlog > 0 {
                    self.register_retired_fanout(Arc::clone(previous_fanout));
                }
            }
            if let Some(runtime_health) = self.runtime_health.read().clone() {
                fanout.attach_runtime_health(runtime_health);
            }
            *self.fanout.write() = Some(fanout);
            if retiring_backlog > 0 {
                tracing::info!(
                    "Retired distributed fanout with {} accepted export events still draining",
                    retiring_backlog
                );
            }
        } else {
            let retiring_backlog = previous_fanout
                .as_ref()
                .map(|existing| self.pending_export_backlog(existing))
                .unwrap_or(0);
            if let Some(previous_fanout) = previous_fanout {
                previous_fanout.retire_runtime_health();
                *self.fanout.write() = None;
                if retiring_backlog > 0 {
                    self.register_retired_fanout(Arc::clone(&previous_fanout));
                    if !self.ensure_export_worker_started() {
                        let retiring_loss = previous_fanout.drop_pending_records() as u64;
                        self.record_retired_export_loss(
                            retiring_loss,
                            "fanout detached before accepted export events could be drained",
                        );
                        self.retired_fanouts
                            .write()
                            .retain(|existing| !Arc::ptr_eq(existing, &previous_fanout));
                        let worker_loss = self.stop_export_worker();
                        self.record_retired_export_loss(
                            worker_loss.dropped,
                            "export worker stopped while retiring sinkless fanout",
                        );
                        Self::note_export_delivery_unknown_shared(
                            &self.runtime_health,
                            &self.local_worker.dropped,
                            &self.export_worker.dropped,
                            &self.export_rejected,
                            &self.export_unknown,
                            &self.local_persist_failures,
                            &self.worker_restarts,
                            &self.last_worker_error,
                            &self.last_local_persist_error,
                            worker_loss.unknown,
                            "export worker stopped while retiring sinkless fanout",
                        );
                    }
                    let _ = self.ensure_export_worker_started();
                } else {
                    self.prune_retired_fanouts(None);
                    let worker_loss = self.stop_export_worker();
                    self.record_retired_export_loss(
                        worker_loss.dropped,
                        "export worker stopped while detaching sinkless fanout",
                    );
                    Self::note_export_delivery_unknown_shared(
                        &self.runtime_health,
                        &self.local_worker.dropped,
                        &self.export_worker.dropped,
                        &self.export_rejected,
                        &self.export_unknown,
                        &self.local_persist_failures,
                        &self.worker_restarts,
                        &self.last_worker_error,
                        &self.last_local_persist_error,
                        worker_loss.unknown,
                        "export worker stopped while detaching sinkless fanout",
                    );
                    if self
                        .retired_fanouts
                        .read()
                        .iter()
                        .any(|fanout| fanout.pending_events() > 0)
                    {
                        self.ensure_supervisor_started();
                    } else if let Some(runtime_health) = self.runtime_health.read().clone() {
                        runtime_health.set_distributed_export_disabled();
                    }
                }
            } else if let Some(runtime_health) = self.runtime_health.read().clone() {
                *self.fanout.write() = None;
                let worker_loss = self.stop_export_worker();
                self.record_retired_export_loss(
                    worker_loss.dropped,
                    "export worker stopped while detaching sinkless fanout",
                );
                Self::note_export_delivery_unknown_shared(
                    &self.runtime_health,
                    &self.local_worker.dropped,
                    &self.export_worker.dropped,
                    &self.export_rejected,
                    &self.export_unknown,
                    &self.local_persist_failures,
                    &self.worker_restarts,
                    &self.last_worker_error,
                    &self.last_local_persist_error,
                    worker_loss.unknown,
                    "export worker stopped while detaching sinkless fanout",
                );
                if self
                    .retired_fanouts
                    .read()
                    .iter()
                    .any(|fanout| fanout.pending_events() > 0)
                {
                    self.ensure_supervisor_started();
                } else {
                    runtime_health.set_distributed_export_disabled();
                }
            }
        }
        self.ensure_supervisor_started();
    }

    fn register_retired_fanout(&self, fanout: Arc<crate::distributed::EventFanout>) {
        let mut retired_fanouts = self.retired_fanouts.write();
        if retired_fanouts
            .iter()
            .any(|existing| Arc::ptr_eq(existing, &fanout))
        {
            return;
        }
        retired_fanouts.push(fanout);
    }

    fn collect_draining_fanouts(
        active_fanout: Option<Arc<crate::distributed::EventFanout>>,
        retired_fanouts: &Arc<parking_lot::RwLock<Vec<Arc<crate::distributed::EventFanout>>>>,
    ) -> Vec<Arc<crate::distributed::EventFanout>> {
        let mut draining = Vec::new();
        if let Some(active_fanout) = active_fanout {
            draining.push(active_fanout);
        }
        for fanout in retired_fanouts.read().iter() {
            if draining
                .iter()
                .all(|existing| !Arc::ptr_eq(existing, fanout))
            {
                draining.push(Arc::clone(fanout));
            }
        }
        draining
    }

    fn prune_retired_fanouts(&self, active_fanout: Option<Arc<crate::distributed::EventFanout>>) {
        Self::prune_retired_fanouts_shared(
            &self.retired_fanouts,
            active_fanout,
            &self.runtime_health,
        );
    }

    fn prune_retired_fanouts_shared(
        retired_fanouts: &Arc<parking_lot::RwLock<Vec<Arc<crate::distributed::EventFanout>>>>,
        active_fanout: Option<Arc<crate::distributed::EventFanout>>,
        runtime_health_ref: &Arc<parking_lot::RwLock<Option<Arc<nettrap_api::RuntimeHealth>>>>,
    ) {
        let active_ref = active_fanout.as_ref();
        let registry_empty = {
            let mut retired_fanouts = retired_fanouts.write();
            retired_fanouts.retain(|fanout| {
                active_ref.is_some_and(|active| Arc::ptr_eq(active, fanout))
                    || fanout.pending_events() > 0
            });
            retired_fanouts.is_empty()
        };

        if active_fanout.is_none() && registry_empty {
            if let Some(runtime_health) = runtime_health_ref.read().clone() {
                if !runtime_health.distributed_export_loss_latched() {
                    runtime_health.set_distributed_export_disabled();
                }
            }
        }
    }

    fn pending_export_backlog(&self, fanout: &Arc<crate::distributed::EventFanout>) -> u64 {
        fanout.pending_events() as u64
    }

    fn record_retired_export_loss(&self, dropped: u64, reason: &str) {
        if dropped == 0 {
            return;
        }

        self.export_worker
            .dropped
            .fetch_add(dropped, Ordering::Relaxed);
        let reason = format!(
            "distributed export lost {} accepted events while retiring fanout: {}",
            dropped, reason
        );
        *self.last_worker_error.write() = Some(reason.clone());
        self.publish_runtime_health();
        if let Some(runtime_health) = self.runtime_health.read().clone() {
            runtime_health.set_distributed_export_loss(reason);
        }
    }

    fn record_shutdown_export_loss(&self, dropped: u64) {
        if dropped == 0 {
            return;
        }

        self.export_worker
            .dropped
            .fetch_add(dropped, Ordering::Relaxed);
        let reason = format!(
            "distributed export lost {} accepted events during shutdown finalization",
            dropped
        );
        *self.last_worker_error.write() = Some(reason.clone());
        self.publish_runtime_health();
        if let Some(runtime_health) = self.runtime_health.read().clone() {
            runtime_health.set_distributed_export_loss(reason);
        }
    }

    fn stop_export_worker(&self) -> ExportWorkerInterruption {
        if let Some(handle) = self.export_worker.handle.lock().take() {
            handle.abort();
        }
        self.reconcile_export_worker_interruption()
    }

    pub fn attach_runtime_health(&self, runtime_health: Arc<nettrap_api::RuntimeHealth>) {
        *self.runtime_health.write() = Some(Arc::clone(&runtime_health));
        self.sync_local_persistence_health(&runtime_health);
        let active_fanout = self.fanout.read().clone();
        let retired_fanouts: Vec<_> = self.retired_fanouts.read().iter().cloned().collect();
        if let Some(fanout) = active_fanout {
            fanout.attach_runtime_health(Arc::clone(&runtime_health));
        }
        let mut has_draining_export = false;
        for fanout in retired_fanouts {
            if fanout.pending_events() > 0 {
                fanout.attach_retired_runtime_health(Arc::clone(&runtime_health));
                has_draining_export = true;
            }
        }
        let snapshot = self.current_health_snapshot();
        if snapshot.export_dropped > 0 {
            let loss_reason = snapshot
                .last_worker_error
                .clone()
                .filter(|error| error.contains("distributed export"))
                .unwrap_or_else(|| {
                    format!(
                        "distributed export previously lost {} accepted events before runtime health attachment",
                        snapshot.export_dropped
                    )
            });
            runtime_health.set_distributed_export_loss(loss_reason);
        } else if snapshot.export_unknown > 0 {
            let unknown_reason = snapshot
                .last_worker_error
                .clone()
                .filter(|error| error.contains("delivery state is unknown"))
                .unwrap_or_else(|| {
                    format!(
                        "distributed export previously left {} events in unknown delivery state before runtime health attachment",
                        snapshot.export_unknown
                    )
                });
            runtime_health.set_distributed_export_degraded(unknown_reason);
        } else if snapshot.export_rejected > 0 {
            let rejection_reason = snapshot
                .last_worker_error
                .clone()
                .filter(|error| error.contains("distributed export rejected"))
                .unwrap_or_else(|| {
                    format!(
                        "distributed export previously rejected {} events before runtime health attachment",
                        snapshot.export_rejected
                    )
                });
            runtime_health.set_distributed_export_degraded(rejection_reason);
        } else if self.fanout.read().is_none() && !has_draining_export {
            runtime_health.set_distributed_export_disabled();
        }
        self.publish_runtime_health();
        self.ensure_supervisor_started();
    }

    /// Attach a database backend for persistent storage
    pub fn with_database(self, db: std::sync::Arc<crate::database::DatabaseBackend>) -> Self {
        self.attach_database(db);
        self
    }

    /// Attach or replace a database backend on a shared collector.
    pub fn attach_database(&self, db: std::sync::Arc<crate::database::DatabaseBackend>) {
        *self.database.write() = Some(db);
        if let Some(runtime_health) = self.runtime_health.read().clone() {
            self.sync_local_persistence_health(&runtime_health);
        }
    }

    /// Attach session state so NBIs can inherit process attribution metadata.
    pub fn attach_session_tracker(&self, tracker: std::sync::Arc<crate::session::SessionTracker>) {
        *self.session_tracker.write() = Some(tracker);
    }

    /// Register the transport protocol used by each listener name.
    pub fn attach_listener_protocols(
        &self,
        protocols: std::collections::HashMap<String, nettrap_core::prelude::Protocol>,
    ) {
        *self.listener_protocols.write() = protocols
            .into_iter()
            .map(|(listener, protocol)| (listener.to_ascii_lowercase(), protocol))
            .collect();
    }

    #[cfg(test)]
    pub(crate) fn listener_protocol_count(&self) -> usize {
        self.listener_protocols.read().len()
    }

    fn note_worker_restart(
        &self,
        worker_name: &str,
        queued: &Arc<AtomicUsize>,
        dropped: &Arc<AtomicU64>,
        reason: impl Into<String>,
    ) {
        Self::record_worker_exit_shared(
            &self.runtime_health,
            &self.local_worker.dropped,
            &self.export_worker.dropped,
            &self.export_rejected,
            &self.export_unknown,
            &self.local_persist_failures,
            &self.worker_restarts,
            &self.last_worker_error,
            &self.last_local_persist_error,
            worker_name,
            queued,
            dropped,
            reason.into(),
        );
    }

    fn reconcile_export_worker_interruption(&self) -> ExportWorkerInterruption {
        let lost_from_queue = self.export_worker.queued.swap(0, Ordering::Relaxed) as u64;
        let lost_from_fanouts =
            Self::collect_draining_fanouts(self.fanout.read().clone(), &self.retired_fanouts)
                .into_iter()
                .map(|fanout| fanout.drop_queued_records() as u64)
                .sum::<u64>();
        let unknown =
            Self::collect_draining_fanouts(self.fanout.read().clone(), &self.retired_fanouts)
                .into_iter()
                .map(|fanout| fanout.mark_inflight_unknown() as u64)
                .sum::<u64>();
        ExportWorkerInterruption {
            dropped: lost_from_queue.max(lost_from_fanouts),
            unknown,
        }
    }

    fn note_export_worker_restart(&self, reason: impl Into<String>) {
        let interruption = self.reconcile_export_worker_interruption();
        if interruption.dropped > 0 {
            self.export_worker
                .dropped
                .fetch_add(interruption.dropped, Ordering::Relaxed);
        }
        if interruption.unknown > 0 {
            self.export_unknown
                .fetch_add(interruption.unknown, Ordering::Relaxed);
        }
        self.worker_restarts.fetch_add(1, Ordering::Relaxed);
        let reason = reason.into();
        let reason = if interruption.dropped > 0 {
            format!(
                "NBI export worker {} (dropped {} queued events)",
                reason, interruption.dropped
            )
        } else if interruption.unknown > 0 {
            format!(
                "NBI export worker {} ({} deliveries left in unknown state)",
                reason, interruption.unknown
            )
        } else {
            format!("NBI export worker {}", reason)
        };
        *self.last_worker_error.write() = Some(reason.clone());
        self.publish_runtime_health();
        if let Some(runtime_health) = self.runtime_health.read().clone() {
            if interruption.dropped > 0 {
                runtime_health.set_distributed_export_loss(reason);
            } else if interruption.unknown > 0 {
                runtime_health.set_distributed_export_degraded(reason);
            } else {
                runtime_health.set_distributed_export_degraded(reason);
            }
        }
        self.prune_retired_fanouts(self.fanout.read().clone());
        tracing::warn!(
            "{}",
            self.last_worker_error.read().clone().unwrap_or_default()
        );
    }

    fn note_export_delivery_loss_shared(
        runtime_health_ref: &Arc<parking_lot::RwLock<Option<Arc<nettrap_api::RuntimeHealth>>>>,
        local_dropped: &Arc<AtomicU64>,
        export_dropped: &Arc<AtomicU64>,
        export_rejected: &Arc<AtomicU64>,
        export_unknown: &Arc<AtomicU64>,
        local_persist_failures: &Arc<AtomicU64>,
        worker_restarts: &Arc<AtomicU64>,
        last_worker_error: &Arc<parking_lot::RwLock<Option<String>>>,
        last_local_persist_error: &Arc<parking_lot::RwLock<Option<String>>>,
        reason: impl Into<String>,
    ) {
        let reason = format!("distributed export lost accepted event: {}", reason.into());
        export_dropped.fetch_add(1, Ordering::Relaxed);
        *last_worker_error.write() = Some(reason.clone());
        if let Some(runtime_health) = runtime_health_ref.read().clone() {
            runtime_health.update_nbi_collector(Self::build_health_snapshot(
                local_dropped,
                export_dropped,
                export_rejected,
                export_unknown,
                local_persist_failures,
                worker_restarts,
                last_worker_error,
                last_local_persist_error,
            ));
            runtime_health.set_distributed_export_loss(reason.clone());
        }
        tracing::warn!("{}", reason);
    }

    fn note_export_delivery_unknown_shared(
        runtime_health_ref: &Arc<parking_lot::RwLock<Option<Arc<nettrap_api::RuntimeHealth>>>>,
        local_dropped: &Arc<AtomicU64>,
        export_dropped: &Arc<AtomicU64>,
        export_rejected: &Arc<AtomicU64>,
        export_unknown: &Arc<AtomicU64>,
        local_persist_failures: &Arc<AtomicU64>,
        worker_restarts: &Arc<AtomicU64>,
        last_worker_error: &Arc<parking_lot::RwLock<Option<String>>>,
        last_local_persist_error: &Arc<parking_lot::RwLock<Option<String>>>,
        count: u64,
        reason: impl Into<String>,
    ) {
        if count == 0 {
            return;
        }

        let reason = format!(
            "distributed export has {} events whose delivery state is unknown: {}",
            count,
            reason.into()
        );
        export_unknown.fetch_add(count, Ordering::Relaxed);
        *last_worker_error.write() = Some(reason.clone());
        if let Some(runtime_health) = runtime_health_ref.read().clone() {
            runtime_health.update_nbi_collector(Self::build_health_snapshot(
                local_dropped,
                export_dropped,
                export_rejected,
                export_unknown,
                local_persist_failures,
                worker_restarts,
                last_worker_error,
                last_local_persist_error,
            ));
            runtime_health.set_distributed_export_degraded(reason.clone());
        }
        tracing::warn!("{}", reason);
    }

    fn build_health_snapshot(
        local_dropped: &Arc<AtomicU64>,
        export_dropped: &Arc<AtomicU64>,
        export_rejected: &Arc<AtomicU64>,
        export_unknown: &Arc<AtomicU64>,
        local_persist_failures: &Arc<AtomicU64>,
        worker_restarts: &Arc<AtomicU64>,
        last_worker_error: &Arc<parking_lot::RwLock<Option<String>>>,
        last_local_persist_error: &Arc<parking_lot::RwLock<Option<String>>>,
    ) -> nettrap_api::NbiCollectorHealth {
        // Use Acquire ordering for consistent snapshot across counters
        nettrap_api::NbiCollectorHealth {
            local_dropped: local_dropped.load(Ordering::Acquire),
            export_dropped: export_dropped.load(Ordering::Acquire),
            export_rejected: export_rejected.load(Ordering::Acquire),
            export_unknown: export_unknown.load(Ordering::Acquire),
            local_persist_failures: local_persist_failures.load(Ordering::Acquire),
            worker_restarts: worker_restarts.load(Ordering::Acquire),
            last_worker_error: last_worker_error.read().clone(),
            last_local_persist_error: last_local_persist_error.read().clone(),
        }
    }

    fn current_health_snapshot(&self) -> nettrap_api::NbiCollectorHealth {
        Self::build_health_snapshot(
            &self.local_worker.dropped,
            &self.export_worker.dropped,
            &self.export_rejected,
            &self.export_unknown,
            &self.local_persist_failures,
            &self.worker_restarts,
            &self.last_worker_error,
            &self.last_local_persist_error,
        )
    }

    fn publish_runtime_health(&self) {
        if let Some(runtime_health) = self.runtime_health.read().clone() {
            runtime_health.update_nbi_collector(self.current_health_snapshot());
        }
    }

    fn has_local_persistence_target(&self) -> bool {
        self.path.is_some() || self.database.read().is_some()
    }

    fn sync_local_persistence_health(&self, runtime_health: &nettrap_api::RuntimeHealth) {
        if self.has_local_persistence_target() {
            runtime_health.set_nbi_pipeline_running();
        } else {
            runtime_health.set_nbi_pipeline_disabled();
        }
    }

    fn note_local_persist_issue_shared(
        runtime_health_ref: &Arc<parking_lot::RwLock<Option<Arc<nettrap_api::RuntimeHealth>>>>,
        local_dropped: &Arc<AtomicU64>,
        export_dropped: &Arc<AtomicU64>,
        export_rejected: &Arc<AtomicU64>,
        export_unknown: &Arc<AtomicU64>,
        local_persist_failures: &Arc<AtomicU64>,
        worker_restarts: &Arc<AtomicU64>,
        last_worker_error: &Arc<parking_lot::RwLock<Option<String>>>,
        last_local_persist_error: &Arc<parking_lot::RwLock<Option<String>>>,
        reason: impl Into<String>,
        total_loss: bool,
    ) {
        let reason = reason.into();
        local_persist_failures.fetch_add(1, Ordering::Relaxed);
        *last_local_persist_error.write() = Some(reason.clone());
        if let Some(runtime_health) = runtime_health_ref.read().clone() {
            runtime_health.update_nbi_collector(Self::build_health_snapshot(
                local_dropped,
                export_dropped,
                export_rejected,
                export_unknown,
                local_persist_failures,
                worker_restarts,
                last_worker_error,
                last_local_persist_error,
            ));
            if total_loss {
                runtime_health
                    .set_nbi_pipeline_loss(format!("local NBI persistence failure: {}", reason));
            } else {
                runtime_health.set_nbi_pipeline_degraded(format!(
                    "local NBI persistence failure: {}",
                    reason
                ));
            }
        }
        tracing::warn!("Local NBI persistence failure: {}", reason);
    }

    fn record_worker_exit_shared(
        runtime_health_ref: &Arc<parking_lot::RwLock<Option<Arc<nettrap_api::RuntimeHealth>>>>,
        local_dropped: &Arc<AtomicU64>,
        export_dropped: &Arc<AtomicU64>,
        export_rejected: &Arc<AtomicU64>,
        export_unknown: &Arc<AtomicU64>,
        local_persist_failures: &Arc<AtomicU64>,
        worker_restarts: &Arc<AtomicU64>,
        last_worker_error: &Arc<parking_lot::RwLock<Option<String>>>,
        last_local_persist_error: &Arc<parking_lot::RwLock<Option<String>>>,
        worker_name: &str,
        queued: &Arc<AtomicUsize>,
        dropped: &Arc<AtomicU64>,
        reason: String,
    ) {
        let lost = queued.swap(0, Ordering::Relaxed) as u64;
        if lost > 0 {
            dropped.fetch_add(lost, Ordering::Relaxed);
        }
        worker_restarts.fetch_add(1, Ordering::Relaxed);
        let reason = if lost > 0 {
            format!(
                "{} worker {} (dropped {} queued events)",
                worker_name, reason, lost
            )
        } else {
            format!("{} worker {}", worker_name, reason)
        };
        *last_worker_error.write() = Some(reason.clone());
        if let Some(runtime_health) = runtime_health_ref.read().clone() {
            runtime_health.update_nbi_collector(Self::build_health_snapshot(
                local_dropped,
                export_dropped,
                export_rejected,
                export_unknown,
                local_persist_failures,
                worker_restarts,
                last_worker_error,
                last_local_persist_error,
            ));
            if worker_name.contains("local") {
                if lost > 0 {
                    runtime_health.set_nbi_pipeline_loss(reason.clone());
                } else {
                    runtime_health.set_nbi_pipeline_degraded(reason.clone());
                }
            } else if lost > 0 {
                runtime_health.set_distributed_export_loss(reason.clone());
            } else {
                runtime_health.set_distributed_export_degraded(reason.clone());
            }
        }
        tracing::warn!("{}", reason);
    }

    fn ensure_supervisor_started(&self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };

        let mut handle = self.supervisor_handle.lock();
        if let Some(existing) = handle.as_ref() {
            if existing.is_finished() {
                handle.take();
            } else {
                return;
            }
        }

        let runtime_health = Arc::clone(&self.runtime_health);
        let fanout = Arc::clone(&self.fanout);
        let retired_fanouts = Arc::clone(&self.retired_fanouts);
        let local_handle = Arc::clone(&self.local_worker.handle);
        let local_queued = Arc::clone(&self.local_worker.queued);
        let local_dropped = Arc::clone(&self.local_worker.dropped);
        let export_handle = Arc::clone(&self.export_worker.handle);
        let export_queued = Arc::clone(&self.export_worker.queued);
        let export_dropped = Arc::clone(&self.export_worker.dropped);
        let export_rejected = Arc::clone(&self.export_rejected);
        let export_unknown = Arc::clone(&self.export_unknown);
        let local_persist_failures = Arc::clone(&self.local_persist_failures);
        let worker_restarts = Arc::clone(&self.worker_restarts);
        let last_worker_error = Arc::clone(&self.last_worker_error);
        let last_local_persist_error = Arc::clone(&self.last_local_persist_error);

        *handle = Some(runtime.spawn(async move {
            NbiCollector::run_worker_supervisor(
                runtime_health,
                fanout,
                retired_fanouts,
                local_handle,
                local_queued,
                local_dropped,
                export_handle,
                export_queued,
                export_dropped,
                export_rejected,
                export_unknown,
                local_persist_failures,
                worker_restarts,
                last_worker_error,
                last_local_persist_error,
            )
            .await;
        }));
    }

    async fn run_worker_supervisor(
        runtime_health: Arc<parking_lot::RwLock<Option<Arc<nettrap_api::RuntimeHealth>>>>,
        fanout: Arc<parking_lot::RwLock<Option<Arc<crate::distributed::EventFanout>>>>,
        retired_fanouts: Arc<parking_lot::RwLock<Vec<Arc<crate::distributed::EventFanout>>>>,
        local_handle: Arc<parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>>,
        local_queued: Arc<AtomicUsize>,
        local_dropped: Arc<AtomicU64>,
        export_handle: Arc<parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>>,
        export_queued: Arc<AtomicUsize>,
        export_dropped: Arc<AtomicU64>,
        export_rejected: Arc<AtomicU64>,
        export_unknown: Arc<AtomicU64>,
        local_persist_failures: Arc<AtomicU64>,
        worker_restarts: Arc<AtomicU64>,
        last_worker_error: Arc<parking_lot::RwLock<Option<String>>>,
        last_local_persist_error: Arc<parking_lot::RwLock<Option<String>>>,
    ) {
        let interval = std::time::Duration::from_millis(NBI_WORKER_SUPERVISOR_INTERVAL_MS);
        loop {
            tokio::time::sleep(interval).await;

            NbiCollector::check_worker_exit(
                &runtime_health,
                &local_dropped,
                &export_dropped,
                &export_rejected,
                &export_unknown,
                &local_persist_failures,
                &worker_restarts,
                &last_worker_error,
                &last_local_persist_error,
                "NBI local",
                &local_handle,
                &local_queued,
                &local_dropped,
            )
            .await;

            let active_fanout = { fanout.read().clone() };
            let draining_fanouts =
                NbiCollector::collect_draining_fanouts(active_fanout.clone(), &retired_fanouts);
            let supervise_export = !draining_fanouts.is_empty()
                || export_handle.lock().as_ref().is_some()
                || export_queued.load(Ordering::Relaxed) > 0;
            if supervise_export {
                NbiCollector::check_export_worker_exit(
                    &runtime_health,
                    &local_dropped,
                    &export_dropped,
                    &export_rejected,
                    &export_unknown,
                    &local_persist_failures,
                    &worker_restarts,
                    &last_worker_error,
                    &last_local_persist_error,
                    &active_fanout,
                    &retired_fanouts,
                    &export_handle,
                    &export_queued,
                    &export_dropped,
                )
                .await;
                for draining_fanout in &draining_fanouts {
                    let _ = draining_fanout.flush_stale_batches().await;
                    let unknown = draining_fanout.consume_unknown_sink_events() as u64;
                    NbiCollector::note_export_delivery_unknown_shared(
                        &runtime_health,
                        &local_dropped,
                        &export_dropped,
                        &export_rejected,
                        &export_unknown,
                        &local_persist_failures,
                        &worker_restarts,
                        &last_worker_error,
                        &last_local_persist_error,
                        unknown,
                        "distributed export stale flush left delivery state unknown",
                    );
                }
                NbiCollector::prune_retired_fanouts_shared(
                    &retired_fanouts,
                    active_fanout,
                    &runtime_health,
                );
            }
        }
    }

    async fn check_worker_exit(
        runtime_health: &Arc<parking_lot::RwLock<Option<Arc<nettrap_api::RuntimeHealth>>>>,
        local_dropped: &Arc<AtomicU64>,
        export_dropped: &Arc<AtomicU64>,
        export_rejected: &Arc<AtomicU64>,
        export_unknown: &Arc<AtomicU64>,
        local_persist_failures: &Arc<AtomicU64>,
        worker_restarts: &Arc<AtomicU64>,
        last_worker_error: &Arc<parking_lot::RwLock<Option<String>>>,
        last_local_persist_error: &Arc<parking_lot::RwLock<Option<String>>>,
        worker_name: &str,
        handle: &Arc<parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>>,
        queued: &Arc<AtomicUsize>,
        dropped: &Arc<AtomicU64>,
    ) {
        let finished = {
            let mut guard = handle.lock();
            if guard.as_ref().is_some_and(|worker| worker.is_finished()) {
                guard.take()
            } else {
                None
            }
        };

        if let Some(worker) = finished {
            let reason = match worker.await {
                Ok(()) => "exited unexpectedly while idle".to_string(),
                Err(err) if err.is_cancelled() => "aborted unexpectedly while idle".to_string(),
                Err(err) => format!("panicked unexpectedly while idle: {}", err),
            };
            Self::record_worker_exit_shared(
                runtime_health,
                local_dropped,
                export_dropped,
                export_rejected,
                export_unknown,
                local_persist_failures,
                worker_restarts,
                last_worker_error,
                last_local_persist_error,
                worker_name,
                queued,
                dropped,
                reason,
            );
        }
    }

    async fn check_export_worker_exit(
        runtime_health: &Arc<parking_lot::RwLock<Option<Arc<nettrap_api::RuntimeHealth>>>>,
        local_dropped: &Arc<AtomicU64>,
        export_dropped: &Arc<AtomicU64>,
        export_rejected: &Arc<AtomicU64>,
        export_unknown: &Arc<AtomicU64>,
        local_persist_failures: &Arc<AtomicU64>,
        worker_restarts: &Arc<AtomicU64>,
        last_worker_error: &Arc<parking_lot::RwLock<Option<String>>>,
        last_local_persist_error: &Arc<parking_lot::RwLock<Option<String>>>,
        active_fanout: &Option<Arc<crate::distributed::EventFanout>>,
        retired_fanouts: &Arc<parking_lot::RwLock<Vec<Arc<crate::distributed::EventFanout>>>>,
        handle: &Arc<parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>>,
        queued: &Arc<AtomicUsize>,
        dropped: &Arc<AtomicU64>,
    ) {
        let finished = {
            let mut guard = handle.lock();
            if guard.as_ref().is_some_and(|worker| worker.is_finished()) {
                guard.take()
            } else {
                None
            }
        };

        if let Some(worker) = finished {
            let reason = match worker.await {
                Ok(()) => "exited unexpectedly while idle".to_string(),
                Err(err) if err.is_cancelled() => "aborted unexpectedly while idle".to_string(),
                Err(err) => format!("panicked unexpectedly while idle: {}", err),
            };
            let lost_from_queue = queued.swap(0, Ordering::Relaxed) as u64;
            let lost_from_fanouts =
                Self::collect_draining_fanouts(active_fanout.clone(), retired_fanouts)
                    .into_iter()
                    .map(|fanout| fanout.drop_queued_records() as u64)
                    .sum::<u64>();
            let unknown = Self::collect_draining_fanouts(active_fanout.clone(), retired_fanouts)
                .into_iter()
                .map(|fanout| fanout.mark_inflight_unknown() as u64)
                .sum::<u64>();
            let lost = lost_from_queue.max(lost_from_fanouts);
            if lost > 0 {
                dropped.fetch_add(lost, Ordering::Relaxed);
            }
            if unknown > 0 {
                export_unknown.fetch_add(unknown, Ordering::Relaxed);
            }
            worker_restarts.fetch_add(1, Ordering::Relaxed);
            let reason = if lost > 0 {
                format!(
                    "NBI export worker {} (dropped {} queued events)",
                    reason, lost
                )
            } else if unknown > 0 {
                format!(
                    "NBI export worker {} ({} deliveries left in unknown state)",
                    reason, unknown
                )
            } else {
                format!("NBI export worker {}", reason)
            };
            *last_worker_error.write() = Some(reason.clone());
            if let Some(runtime_health) = runtime_health.read().clone() {
                runtime_health.update_nbi_collector(Self::build_health_snapshot(
                    local_dropped,
                    export_dropped,
                    export_rejected,
                    export_unknown,
                    local_persist_failures,
                    worker_restarts,
                    last_worker_error,
                    last_local_persist_error,
                ));
                if lost > 0 {
                    runtime_health.set_distributed_export_loss(reason.clone());
                } else if unknown > 0 {
                    runtime_health.set_distributed_export_degraded(reason.clone());
                } else {
                    runtime_health.set_distributed_export_degraded(reason.clone());
                }
            }
            tracing::warn!("{}", reason);
            Self::prune_retired_fanouts_shared(
                retired_fanouts,
                active_fanout.clone(),
                runtime_health,
            );
        }
    }

    fn ensure_local_worker_started(&self) -> bool {
        if !self.has_local_persistence_target() {
            if let Some(runtime_health) = self.runtime_health.read().clone() {
                self.sync_local_persistence_health(&runtime_health);
            }
            return false;
        }

        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return false;
        };

        let mut handle = self.local_worker.handle.lock();
        if let Some(existing) = handle.as_ref() {
            if existing.is_finished() {
                handle.take();
                self.note_worker_restart(
                    "NBI local",
                    &self.local_worker.queued,
                    &self.local_worker.dropped,
                    "exited unexpectedly",
                );
            } else {
                return true;
            }
        }

        let Some(worker_rx) = self.local_worker.ensure_receiver(NBI_LOCAL_QUEUE_CAPACITY) else {
            return false;
        };

        let path = self.path.clone();
        let database = Arc::clone(&self.database);
        let runtime_health = Arc::clone(&self.runtime_health);
        let queued_events = Arc::clone(&self.local_worker.queued);
        let local_dropped = Arc::clone(&self.local_worker.dropped);
        let export_dropped = Arc::clone(&self.export_worker.dropped);
        let export_rejected = Arc::clone(&self.export_rejected);
        let export_unknown = Arc::clone(&self.export_unknown);
        let local_persist_failures = Arc::clone(&self.local_persist_failures);
        let worker_restarts = Arc::clone(&self.worker_restarts);
        let last_worker_error = Arc::clone(&self.last_worker_error);
        let last_local_persist_error = Arc::clone(&self.last_local_persist_error);
        let worker_handle = runtime.spawn(async move {
            NbiCollector::run_local_worker(
                worker_rx,
                path,
                database,
                runtime_health,
                queued_events,
                local_dropped,
                export_dropped,
                export_rejected,
                export_unknown,
                local_persist_failures,
                worker_restarts,
                last_worker_error,
                last_local_persist_error,
            )
            .await;
        });
        *handle = Some(worker_handle);
        drop(handle);
        if let Some(runtime_health) = self.runtime_health.read().clone() {
            self.sync_local_persistence_health(&runtime_health);
        }
        self.ensure_supervisor_started();
        true
    }

    fn ensure_export_worker_started(&self) -> bool {
        if self.fanout.read().is_none() && self.retired_fanouts.read().is_empty() {
            return true;
        }

        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return false;
        };

        let mut handle = self.export_worker.handle.lock();
        if let Some(existing) = handle.as_ref() {
            if existing.is_finished() {
                handle.take();
                self.note_export_worker_restart("exited unexpectedly");
            } else {
                return true;
            }
        }

        let Some(worker_rx) = self
            .export_worker
            .ensure_receiver(NBI_EXPORT_QUEUE_CAPACITY)
        else {
            return false;
        };

        let fanout = Arc::clone(&self.fanout);
        let retired_fanouts = Arc::clone(&self.retired_fanouts);
        let runtime_health = Arc::clone(&self.runtime_health);
        let queued_events = Arc::clone(&self.export_worker.queued);
        let local_dropped = Arc::clone(&self.local_worker.dropped);
        let export_dropped = Arc::clone(&self.export_worker.dropped);
        let export_rejected = Arc::clone(&self.export_rejected);
        let export_unknown = Arc::clone(&self.export_unknown);
        let local_persist_failures = Arc::clone(&self.local_persist_failures);
        let worker_restarts = Arc::clone(&self.worker_restarts);
        let last_worker_error = Arc::clone(&self.last_worker_error);
        let last_local_persist_error = Arc::clone(&self.last_local_persist_error);
        let worker_handle = runtime.spawn(async move {
            NbiCollector::run_export_worker(
                worker_rx,
                fanout,
                retired_fanouts,
                runtime_health,
                queued_events,
                local_dropped,
                export_dropped,
                export_rejected,
                export_unknown,
                local_persist_failures,
                worker_restarts,
                last_worker_error,
                last_local_persist_error,
            )
            .await;
        });
        *handle = Some(worker_handle);
        drop(handle);
        self.ensure_supervisor_started();
        true
    }

    async fn run_local_worker(
        mut worker_rx: tokio::sync::mpsc::Receiver<LocalWorkerCommand>,
        path: Option<PathBuf>,
        database: Arc<parking_lot::RwLock<Option<Arc<crate::database::DatabaseBackend>>>>,
        runtime_health: Arc<parking_lot::RwLock<Option<Arc<nettrap_api::RuntimeHealth>>>>,
        queued_events: Arc<AtomicUsize>,
        local_dropped: Arc<AtomicU64>,
        export_dropped: Arc<AtomicU64>,
        export_rejected: Arc<AtomicU64>,
        export_unknown: Arc<AtomicU64>,
        local_persist_failures: Arc<AtomicU64>,
        worker_restarts: Arc<AtomicU64>,
        last_worker_error: Arc<parking_lot::RwLock<Option<String>>>,
        last_local_persist_error: Arc<parking_lot::RwLock<Option<String>>>,
    ) {
        while let Some(command) = worker_rx.recv().await {
            match command {
                LocalWorkerCommand::Record(nbi) => {
                    let outcome =
                        NbiCollector::persist_local_record(path.as_ref(), &database, &nbi).await;
                    if let Some(error) = outcome.error_summary() {
                        NbiCollector::note_local_persist_issue_shared(
                            &runtime_health,
                            &local_dropped,
                            &export_dropped,
                            &export_rejected,
                            &export_unknown,
                            &local_persist_failures,
                            &worker_restarts,
                            &last_worker_error,
                            &last_local_persist_error,
                            error,
                            outcome.is_total_failure(),
                        );
                    } else if outcome.any_target_configured() {
                        if let Some(runtime_health) = runtime_health.read().clone() {
                            runtime_health.set_nbi_pipeline_running();
                            runtime_health.update_nbi_collector(
                                NbiCollector::build_health_snapshot(
                                    &local_dropped,
                                    &export_dropped,
                                    &export_rejected,
                                    &export_unknown,
                                    &local_persist_failures,
                                    &worker_restarts,
                                    &last_worker_error,
                                    &last_local_persist_error,
                                ),
                            );
                        }
                    }
                    queued_events.fetch_sub(1, Ordering::Relaxed);
                }
                LocalWorkerCommand::Flush(flush_tx) => {
                    let _ = flush_tx.send(());
                }
            }
        }
    }

    async fn run_export_worker(
        mut worker_rx: tokio::sync::mpsc::Receiver<ExportWorkerCommand>,
        active_fanout: Arc<parking_lot::RwLock<Option<Arc<crate::distributed::EventFanout>>>>,
        retired_fanouts: Arc<parking_lot::RwLock<Vec<Arc<crate::distributed::EventFanout>>>>,
        runtime_health: Arc<parking_lot::RwLock<Option<Arc<nettrap_api::RuntimeHealth>>>>,
        queued_events: Arc<AtomicUsize>,
        local_dropped: Arc<AtomicU64>,
        export_dropped: Arc<AtomicU64>,
        export_rejected: Arc<AtomicU64>,
        export_unknown: Arc<AtomicU64>,
        local_persist_failures: Arc<AtomicU64>,
        worker_restarts: Arc<AtomicU64>,
        last_worker_error: Arc<parking_lot::RwLock<Option<String>>>,
        last_local_persist_error: Arc<parking_lot::RwLock<Option<String>>>,
    ) {
        while let Some(command) = worker_rx.recv().await {
            match command {
                ExportWorkerCommand::Record(nbi, fanout) => {
                    let event_id = nbi.normalized_event_id();
                    fanout.note_send_started(&event_id);
                    queued_events.fetch_sub(1, Ordering::Relaxed);
                    let outcome = fanout.send(&nbi).await;
                    let outcome_error = outcome.error.clone();
                    let completion = fanout.note_dequeued_record(&event_id);
                    if completion.final_loss {
                        let reason = outcome_error.clone().unwrap_or_else(|| {
                            "distributed export lost an accepted event without retry buffer"
                                .to_string()
                        });
                        NbiCollector::note_export_delivery_loss_shared(
                            &runtime_health,
                            &local_dropped,
                            &export_dropped,
                            &export_rejected,
                            &export_unknown,
                            &local_persist_failures,
                            &worker_restarts,
                            &last_worker_error,
                            &last_local_persist_error,
                            reason,
                        );
                    }
                    if completion.became_unknown {
                        NbiCollector::note_export_delivery_unknown_shared(
                            &runtime_health,
                            &local_dropped,
                            &export_dropped,
                            &export_rejected,
                            &export_unknown,
                            &local_persist_failures,
                            &worker_restarts,
                            &last_worker_error,
                            &last_local_persist_error,
                            1,
                            outcome_error.unwrap_or_else(|| {
                                "distributed export send was interrupted before completion"
                                    .to_string()
                            }),
                        );
                    }
                }
                ExportWorkerCommand::Flush(current_fanout, flush_tx) => {
                    let mut flush_errors = Vec::new();
                    let fanouts_to_flush = NbiCollector::collect_draining_fanouts(
                        current_fanout.or_else(|| active_fanout.read().clone()),
                        &retired_fanouts,
                    );
                    for fanout in &fanouts_to_flush {
                        if let Err(err) = fanout.flush_all().await {
                            flush_errors.push(err);
                        }
                        let unknown = fanout.consume_unknown_sink_events() as u64;
                        NbiCollector::note_export_delivery_unknown_shared(
                            &runtime_health,
                            &local_dropped,
                            &export_dropped,
                            &export_rejected,
                            &export_unknown,
                            &local_persist_failures,
                            &worker_restarts,
                            &last_worker_error,
                            &last_local_persist_error,
                            unknown,
                            "distributed export flush left delivery state unknown",
                        );
                    }
                    NbiCollector::prune_retired_fanouts_shared(
                        &retired_fanouts,
                        active_fanout.read().clone(),
                        &runtime_health,
                    );
                    let _ = if flush_errors.is_empty() {
                        flush_tx.send(Ok(()))
                    } else {
                        flush_tx.send(Err(flush_errors.join("; ")))
                    };
                }
                ExportWorkerCommand::Shutdown(shutdown_tx) => {
                    let fanouts_to_flush = NbiCollector::collect_draining_fanouts(
                        active_fanout.read().clone(),
                        &retired_fanouts,
                    );
                    for fanout in &fanouts_to_flush {
                        let _ = fanout.flush_all().await;
                        let unknown = fanout.consume_unknown_sink_events() as u64;
                        NbiCollector::note_export_delivery_unknown_shared(
                            &runtime_health,
                            &local_dropped,
                            &export_dropped,
                            &export_rejected,
                            &export_unknown,
                            &local_persist_failures,
                            &worker_restarts,
                            &last_worker_error,
                            &last_local_persist_error,
                            unknown,
                            "distributed export shutdown flush left delivery state unknown",
                        );
                    }
                    NbiCollector::prune_retired_fanouts_shared(
                        &retired_fanouts,
                        active_fanout.read().clone(),
                        &runtime_health,
                    );
                    let _ = shutdown_tx.send(());
                    break;
                }
            }
        }
    }

    async fn persist_local_record(
        path: Option<&PathBuf>,
        database: &Arc<parking_lot::RwLock<Option<Arc<crate::database::DatabaseBackend>>>>,
        nbi: &NetworkBehaviorIndicator,
    ) -> LocalPersistOutcome {
        let mut outcome = LocalPersistOutcome {
            file_configured: path.is_some(),
            db_configured: false,
            file_persisted: false,
            db_persisted: false,
            file_error: None,
            db_error: None,
        };

        if let Some(path) = path {
            match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
            {
                Ok(mut file) => {
                    use tokio::io::AsyncWriteExt;
                    if let Err(e) = file.write_all(nbi.to_json().as_bytes()).await {
                        outcome.file_error =
                            Some(format!("failed to write NBI event to file: {}", e));
                    } else if let Err(e) = file.write_all(b"\n").await {
                        outcome.file_error =
                            Some(format!("failed to write NBI newline to file: {}", e));
                    } else {
                        outcome.file_persisted = true;
                    }
                }
                Err(e) => {
                    outcome.file_error =
                        Some(format!("failed to open NBI file {}: {}", path.display(), e));
                }
            }
        }

        let db = { database.read().clone() };
        if let Some(db) = db {
            outcome.db_configured = true;
            if let Err(e) = db.insert_event(nbi).await {
                outcome.db_error = Some(format!("database insert error: {}", e));
            } else {
                outcome.db_persisted = true;
            }
        }

        outcome
    }

    fn drop_local_event(&self, reason: &str) {
        let dropped = self.local_worker.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        self.publish_runtime_health();
        if let Some(runtime_health) = self.runtime_health.read().clone() {
            runtime_health.set_nbi_pipeline_loss(format!("local NBI persistence drop: {}", reason));
        }
        if dropped == 1 || dropped % 100 == 0 {
            tracing::warn!(
                "Dropping NBI local event: {} (dropped={}, capacity={})",
                reason,
                dropped,
                NBI_LOCAL_QUEUE_CAPACITY
            );
        }
    }

    fn drop_export_event(&self, reason: &str) {
        let rejected = self.export_rejected.fetch_add(1, Ordering::Relaxed) + 1;
        let reason = format!(
            "distributed export rejected event before fanout acceptance: {}",
            reason
        );
        *self.last_worker_error.write() = Some(reason.clone());
        self.publish_runtime_health();
        if let Some(runtime_health) = self.runtime_health.read().clone() {
            runtime_health.set_distributed_export_degraded(reason.clone());
        }
        if rejected == 1 || rejected % 100 == 0 {
            tracing::warn!(
                "Rejecting NBI export event before fanout acceptance: {} (rejected={}, capacity={})",
                reason,
                rejected,
                NBI_EXPORT_QUEUE_CAPACITY
            );
        }
    }

    fn enqueue_local_record(&self, nbi: NetworkBehaviorIndicator) {
        if !self.has_local_persistence_target() {
            if let Some(runtime_health) = self.runtime_health.read().clone() {
                self.sync_local_persistence_health(&runtime_health);
            }
            return;
        }

        if !self.ensure_local_worker_started() {
            self.drop_local_event("local worker unavailable");
            return;
        }

        self.local_worker.queued.fetch_add(1, Ordering::Relaxed);
        let mut command = Some(LocalWorkerCommand::Record(nbi));
        for attempt in 0..2 {
            let tx = self.local_worker.sender();
            match tx.try_send(command.take().expect("local worker command missing")) {
                Ok(()) => return,
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    self.local_worker.queued.fetch_sub(1, Ordering::Relaxed);
                    self.drop_local_event("local queue full");
                    return;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(cmd)) if attempt == 0 => {
                    self.local_worker.queued.fetch_sub(1, Ordering::Relaxed);
                    self.note_worker_restart(
                        "NBI local",
                        &self.local_worker.queued,
                        &self.local_worker.dropped,
                        "channel closed",
                    );
                    if !self.ensure_local_worker_started() {
                        self.drop_local_event("local worker restart failed");
                        return;
                    }
                    self.local_worker.queued.fetch_add(1, Ordering::Relaxed);
                    command = Some(cmd);
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    self.local_worker.queued.fetch_sub(1, Ordering::Relaxed);
                    self.drop_local_event("local worker channel closed");
                    return;
                }
            }
        }
    }

    fn enqueue_export_record(&self, nbi: NetworkBehaviorIndicator) {
        let Some(fanout) = self.fanout.read().clone() else {
            return;
        };

        if !self.ensure_export_worker_started() {
            self.drop_export_event("export worker unavailable");
            return;
        }

        let event_id = nbi.normalized_event_id();
        self.export_worker.queued.fetch_add(1, Ordering::Relaxed);
        let mut command = Some(ExportWorkerCommand::Record(nbi, Arc::clone(&fanout)));
        for attempt in 0..2 {
            let tx = self.export_worker.sender();
            match tx.try_send(command.take().expect("export worker command missing")) {
                Ok(()) => {
                    fanout.note_queued_record(&event_id);
                    return;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    self.export_worker.queued.fetch_sub(1, Ordering::Relaxed);
                    self.drop_export_event("export queue full");
                    return;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(cmd)) if attempt == 0 => {
                    self.export_worker.queued.fetch_sub(1, Ordering::Relaxed);
                    self.note_export_worker_restart("channel closed");
                    if !self.ensure_export_worker_started() {
                        self.drop_export_event("export worker restart failed");
                        return;
                    }
                    self.export_worker.queued.fetch_add(1, Ordering::Relaxed);
                    command = Some(cmd);
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    self.export_worker.queued.fetch_sub(1, Ordering::Relaxed);
                    self.drop_export_event("export worker channel closed");
                    return;
                }
            }
        }
    }

    async fn flush_local(&self) {
        if !self.has_local_persistence_target() {
            return;
        }

        if !self.ensure_local_worker_started() {
            return;
        }

        let (flush_tx, flush_rx) = tokio::sync::oneshot::channel();
        match self
            .local_worker
            .sender()
            .send(LocalWorkerCommand::Flush(flush_tx))
            .await
        {
            Ok(()) => {
                let _ = flush_rx.await;
            }
            Err(_) => {
                self.note_worker_restart(
                    "NBI local",
                    &self.local_worker.queued,
                    &self.local_worker.dropped,
                    "flush channel closed",
                );
            }
        }
    }

    pub async fn flush_all_pending(&self) {
        self.flush_local().await;
        self.flush_distributed().await;
    }

    pub async fn finalize_distributed_shutdown(&self) {
        if self.fanout.read().is_none()
            && self.retired_fanouts.read().is_empty()
            && self.export_worker.queued.load(Ordering::Relaxed) == 0
            && self.export_worker.handle.lock().is_none()
        {
            return;
        }

        self.flush_distributed().await;

        let mut shutdown_acknowledged = false;
        let mut shutdown_timed_out = false;
        if self.export_worker.handle.lock().is_some() {
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
            match self
                .export_worker
                .sender()
                .send(ExportWorkerCommand::Shutdown(shutdown_tx))
                .await
            {
                Ok(()) => {
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(NBI_EXPORT_OPERATION_TIMEOUT_MS),
                        shutdown_rx,
                    )
                    .await
                    {
                        Ok(Ok(())) => shutdown_acknowledged = true,
                        Ok(Err(_)) => self.note_export_worker_restart("shutdown ack dropped"),
                        Err(_) => shutdown_timed_out = true,
                    }
                }
                Err(_) => {
                    self.note_export_worker_restart("shutdown channel closed");
                }
            }
        }

        if shutdown_timed_out {
            let unknown =
                Self::collect_draining_fanouts(self.fanout.read().clone(), &self.retired_fanouts)
                    .into_iter()
                    .map(|fanout| fanout.mark_inflight_unknown() as u64)
                    .sum::<u64>();
            Self::note_export_delivery_unknown_shared(
                &self.runtime_health,
                &self.local_worker.dropped,
                &self.export_worker.dropped,
                &self.export_rejected,
                &self.export_unknown,
                &self.local_persist_failures,
                &self.worker_restarts,
                &self.last_worker_error,
                &self.last_local_persist_error,
                unknown,
                "distributed export shutdown timed out while deliveries were still in flight",
            );
        }

        let worker_handle = { self.export_worker.handle.lock().take() };
        if let Some(handle) = worker_handle {
            if shutdown_timed_out {
                handle.abort();
            }
            let _ = handle.await;
        }

        if !shutdown_acknowledged {
            let active_fanout = self.fanout.read().clone();
            for fanout in Self::collect_draining_fanouts(active_fanout, &self.retired_fanouts) {
                let _ = fanout.flush_all().await;
                let unknown = fanout.consume_unknown_sink_events() as u64;
                Self::note_export_delivery_unknown_shared(
                    &self.runtime_health,
                    &self.local_worker.dropped,
                    &self.export_worker.dropped,
                    &self.export_rejected,
                    &self.export_unknown,
                    &self.local_persist_failures,
                    &self.worker_restarts,
                    &self.last_worker_error,
                    &self.last_local_persist_error,
                    unknown,
                    "distributed export shutdown fallback left delivery state unknown",
                );
            }
        }

        let lost_from_queue = self.export_worker.queued.swap(0, Ordering::Relaxed) as u64;
        let mut lost_from_fanouts = 0u64;
        let active_fanout = self.fanout.read().clone();
        for fanout in Self::collect_draining_fanouts(active_fanout.clone(), &self.retired_fanouts) {
            lost_from_fanouts += fanout.drop_pending_records() as u64;
        }

        self.record_shutdown_export_loss(lost_from_fanouts.max(lost_from_queue));
        self.prune_retired_fanouts(active_fanout);
    }

    pub fn stop_background_tasks(&self) {
        if let Some(handle) = self.supervisor_handle.lock().take() {
            handle.abort();
        }
    }

    pub fn snapshot(&self) -> NbiCollectorSnapshot {
        NbiCollectorSnapshot {
            local_queue_depth: self.local_worker.queued.load(Ordering::Relaxed),
            export_queue_depth: self.export_worker.queued.load(Ordering::Relaxed),
            local_dropped: self.local_worker.dropped.load(Ordering::Relaxed),
            export_dropped: self.export_worker.dropped.load(Ordering::Relaxed),
            export_rejected: self.export_rejected.load(Ordering::Relaxed),
            export_unknown: self.export_unknown.load(Ordering::Relaxed),
            local_persist_failures: self.local_persist_failures.load(Ordering::Relaxed),
            worker_restarts: self.worker_restarts.load(Ordering::Relaxed),
            last_worker_error: self.last_worker_error.read().clone(),
            last_local_persist_error: self.last_local_persist_error.read().clone(),
        }
    }

    /// Generate an HTML report from the NBI JSONL file
    pub fn generate_html_report(
        nbi_jsonl_path: &std::path::Path,
        output_path: &std::path::Path,
        lang: &str,
    ) -> std::io::Result<()> {
        let nbis = crate::output::load_nbis_from_jsonl(nbi_jsonl_path);
        Self::generate_html_report_from_events(&nbis, output_path, lang)
    }

    pub fn generate_html_report_from_events(
        nbis: &[NetworkBehaviorIndicator],
        output_path: &std::path::Path,
        lang: &str,
    ) -> std::io::Result<()> {
        use crate::i18n::t;
        let title = t("report_title", lang);
        let title_escaped = html_escape(&title);
        let mut html = format!(
            r#"<!DOCTYPE html>
<html><head>
<title>{}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #f5f5f5; }}
h1 {{ color: #d35400; border-bottom: 2px solid #d35400; padding-bottom: 10px; }}
h2 {{ color: #2c3e50; margin-top: 30px; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }}
th {{ background: #2c3e50; color: white; padding: 10px 15px; text-align: left; }}
td {{ padding: 8px 15px; border-bottom: 1px solid #ecf0f1; }}
tr:hover {{ background: #f8f9fa; }}
.summary {{ display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 20px; }}
.card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); min-width: 150px; }}
.card h3 {{ margin: 0 0 10px 0; color: #7f8c8d; font-size: 14px; }}
.card .value {{ font-size: 28px; font-weight: bold; color: #2c3e50; }}
.protocol-dns {{ color: #2980b9; }} .protocol-http {{ color: #27ae60; }}
.protocol-smtp {{ color: #8e44ad; }} .protocol-ftp {{ color: #d35400; }}
.protocol-pop3 {{ color: #c0392b; }} .protocol-irc {{ color: #16a085; }}
.protocol-tls {{ color: #f39c12; }} .protocol-raw {{ color: #7f8c8d; }}
.protocol-tftp {{ color: #2c3e50; }}
.indicators {{ font-family: monospace; font-size: 12px; }}
</style>
</head><body>
<h1>{}</h1>
"#,
            title_escaped, title_escaped
        );

        // Summary cards
        let total = nbis.len();
        let mut protocol_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut unique_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
        for nbi in nbis {
            *protocol_counts.entry(nbi.protocol.clone()).or_insert(0) += 1;
            unique_ips.insert(nbi.src_ip.clone());
        }

        html.push_str("<div class=\"summary\">");
        html.push_str(&format!(
            "<div class=\"card\"><h3>{}</h3><div class=\"value\">{}</div></div>",
            t("total_events", lang),
            total
        ));
        html.push_str(&format!(
            "<div class=\"card\"><h3>{}</h3><div class=\"value\">{}</div></div>",
            t("unique_sources", lang),
            unique_ips.len()
        ));
        html.push_str(&format!(
            "<div class=\"card\"><h3>{}</h3><div class=\"value\">{}</div></div>",
            t("protocols", lang),
            protocol_counts.len()
        ));
        html.push_str("</div>");

        // Protocol breakdown
        html.push_str(&format!(
            "<h2>{}</h2><table><tr><th>{}</th><th>{}</th></tr>",
            t("protocol_summary", lang),
            t("protocol", lang),
            t("events", lang)
        ));
        let mut sorted_protos: Vec<_> = protocol_counts.iter().collect();
        sorted_protos.sort_by(|a, b| b.1.cmp(a.1));
        for (proto, count) in &sorted_protos {
            html.push_str(&format!(
                "<tr><td class=\"protocol-{}\">{}</td><td>{}</td></tr>",
                html_escape(&proto.to_lowercase()),
                html_escape(proto),
                count
            ));
        }
        html.push_str("</table>");

        // Full event table
        html.push_str(&format!("<h2>{}</h2><table><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>",
            t("all_events", lang), t("time", lang), t("protocol", lang), t("listener", lang),
            t("source", lang), t("destination", lang), t("port", lang), t("indicators", lang), t("process", lang)));
        for nbi in nbis {
            let indicators_str: String = nbi
                .indicators
                .iter()
                .map(|(k, v)| format!("{}={}", html_escape(k), html_escape(v)))
                .collect::<Vec<_>>()
                .join(", ");
            let process_str = match (&nbi.process_name, &nbi.process_pid) {
                (Some(name), Some(pid)) => format!("{} ({})", html_escape(name), pid),
                (Some(name), None) => html_escape(name),
                _ => String::new(),
            };
            html.push_str(&format!(
                "<tr><td>{}</td><td class=\"protocol-{}\">{}</td><td>{}</td><td>{}:{}</td><td>{}</td><td>{}</td><td class=\"indicators\">{}</td><td>{}</td></tr>",
                if nbi.timestamp.len() >= 19 { &nbi.timestamp[..19] } else { &nbi.timestamp },
                html_escape(&nbi.protocol.to_lowercase()), html_escape(&nbi.protocol), html_escape(&nbi.listener),
                html_escape(&nbi.src_ip), nbi.src_port, html_escape(&nbi.dst_ip), nbi.dst_port, indicators_str, process_str
            ));
        }
        html.push_str("</table>");

        html.push_str(&format!(
            "<p><em>{} - {}</em></p>",
            t("generated_by", lang),
            chrono::Utc::now().to_rfc3339()
        ));
        html.push_str("</body></html>");

        std::fs::write(output_path, html)?;
        Ok(())
    }

    pub async fn record(&self, nbi: &NetworkBehaviorIndicator) {
        let nbi = self.enrich_with_process(nbi).with_fresh_event_id();

        // Always log to tracing
        tracing::info!(
            target: "nbi",
            "[NBI] {} {} {}:{} -> {}:{} {:?}",
            nbi.protocol,
            nbi.listener,
            nbi.src_ip,
            nbi.src_port,
            nbi.dst_ip,
            nbi.dst_port,
            nbi.indicators
        );

        self.enqueue_local_record(nbi.clone());
        self.enqueue_export_record(nbi);
    }

    /// Flush any pending distributed event batches.
    /// Call this during shutdown to prevent data loss.
    pub async fn flush_distributed(&self) {
        if self.fanout.read().is_none() && self.retired_fanouts.read().is_empty() {
            return;
        }

        if !self.ensure_export_worker_started() {
            let fanouts =
                Self::collect_draining_fanouts(self.fanout.read().clone(), &self.retired_fanouts);
            for fanout in fanouts {
                let _ = fanout.flush_all().await;
                let unknown = fanout.consume_unknown_sink_events() as u64;
                Self::note_export_delivery_unknown_shared(
                    &self.runtime_health,
                    &self.local_worker.dropped,
                    &self.export_worker.dropped,
                    &self.export_rejected,
                    &self.export_unknown,
                    &self.local_persist_failures,
                    &self.worker_restarts,
                    &self.last_worker_error,
                    &self.last_local_persist_error,
                    unknown,
                    "distributed export flush fallback left delivery state unknown",
                );
            }
            self.prune_retired_fanouts(self.fanout.read().clone());
            return;
        }

        let (flush_tx, flush_rx) = tokio::sync::oneshot::channel();
        let current_fanout = { self.fanout.read().clone() };
        match self
            .export_worker
            .sender()
            .send(ExportWorkerCommand::Flush(current_fanout, flush_tx))
            .await
        {
            Ok(()) => {
                if tokio::time::timeout(
                    std::time::Duration::from_millis(NBI_EXPORT_OPERATION_TIMEOUT_MS),
                    flush_rx,
                )
                .await
                .is_err()
                {
                    *self.last_worker_error.write() = Some(
                        "distributed export flush timed out while waiting for worker acknowledgement"
                            .to_string(),
                    );
                    self.publish_runtime_health();
                    if let Some(runtime_health) = self.runtime_health.read().clone() {
                        runtime_health.set_distributed_export_degraded(
                            "distributed export flush timed out while waiting for worker acknowledgement"
                                .to_string(),
                        );
                    }
                }
            }
            Err(_) => {
                self.note_export_worker_restart("flush channel closed");
                let fanouts = Self::collect_draining_fanouts(
                    self.fanout.read().clone(),
                    &self.retired_fanouts,
                );
                for fanout in fanouts {
                    let _ = fanout.flush_all().await;
                    let unknown = fanout.consume_unknown_sink_events() as u64;
                    Self::note_export_delivery_unknown_shared(
                        &self.runtime_health,
                        &self.local_worker.dropped,
                        &self.export_worker.dropped,
                        &self.export_rejected,
                        &self.export_unknown,
                        &self.local_persist_failures,
                        &self.worker_restarts,
                        &self.last_worker_error,
                        &self.last_local_persist_error,
                        unknown,
                        "distributed export flush fallback left delivery state unknown",
                    );
                }
                self.prune_retired_fanouts(self.fanout.read().clone());
            }
        }
    }

    fn enrich_with_process(&self, nbi: &NetworkBehaviorIndicator) -> NetworkBehaviorIndicator {
        if nbi.process_name.is_some() || nbi.process_pid.is_some() {
            return nbi.clone();
        }

        // Acquire both read locks atomically to prevent race condition
        // where session_tracker and listener_protocols could be modified
        // between individual lock acquisitions
        let (tracker, listener_protocol) = {
            let tracker = self.session_tracker.read().clone();
            let protocols = self.listener_protocols.read();
            let protocol = protocols.get(&nbi.listener.to_ascii_lowercase()).copied();
            (tracker, protocol)
        };

        let tracker = match tracker {
            Some(tracker) => tracker,
            None => return nbi.clone(),
        };

        let transport = match listener_protocol {
            Some(nettrap_core::prelude::Protocol::Tcp) => "TCP",
            Some(nettrap_core::prelude::Protocol::Udp) => "UDP",
            _ => return nbi.clone(),
        };

        let src_ip = match nbi.src_ip.parse() {
            Ok(ip) => ip,
            Err(_) => return nbi.clone(),
        };

        let src = std::net::SocketAddr::new(src_ip, nbi.src_port);
        let destination = SessionDestination::new(&nbi.dst_ip, nbi.dst_port);
        match tracker.get_process(&src, transport, &destination) {
            Some((name, pid)) if name.is_some() || pid.is_some() => {
                nbi.clone().with_process(name, pid)
            }
            _ => nbi.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{DatabaseBackend, SqliteStorage};
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct SlowSink;

    #[async_trait::async_trait]
    impl crate::distributed::EventSink for SlowSink {
        async fn send(
            &self,
            _event: &NetworkBehaviorIndicator,
        ) -> crate::distributed::SinkSendResult {
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
        async fn send(
            &self,
            _event: &NetworkBehaviorIndicator,
        ) -> crate::distributed::SinkSendResult {
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
        async fn send(
            &self,
            _event: &NetworkBehaviorIndicator,
        ) -> crate::distributed::SinkSendResult {
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
        async fn send(
            &self,
            _event: &NetworkBehaviorIndicator,
        ) -> crate::distributed::SinkSendResult {
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
        async fn send(
            &self,
            event: &NetworkBehaviorIndicator,
        ) -> crate::distributed::SinkSendResult {
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
        async fn send(
            &self,
            event: &NetworkBehaviorIndicator,
        ) -> crate::distributed::SinkSendResult {
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
        async fn send(
            &self,
            event: &NetworkBehaviorIndicator,
        ) -> crate::distributed::SinkSendResult {
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
        async fn send(
            &self,
            _event: &NetworkBehaviorIndicator,
        ) -> crate::distributed::SinkSendResult {
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
        let collector = NbiCollector::new(Some(path.clone()));
        let tracker = std::sync::Arc::new(crate::session::SessionTracker::new());
        let src: std::net::SocketAddr = "127.0.0.1:42424".parse().unwrap();

        let destination = crate::session::SessionDestination::new("10.0.0.7", 8080);
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

    #[tokio::test]
    async fn record_assigns_a_fresh_event_id_per_delivery() {
        let path =
            std::env::temp_dir().join(format!("nettrap-nbi-test-{}.jsonl", uuid::Uuid::new_v4()));
        let collector = NbiCollector::new(Some(path.clone()));
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
    async fn record_does_not_wait_for_slow_sink_delivery() {
        let collector = NbiCollector::new(None);
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
        let collector = NbiCollector::new(None);
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
        let collector = NbiCollector::new(Some(path.clone()));
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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();

        let mut fanout = crate::distributed::EventFanout::new();
        fanout.add_sink(Box::new(FailingSink));
        let fanout = Arc::new(fanout);
        fanout.attach_runtime_health(Arc::clone(&runtime_health));
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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();

        let mut fanout = crate::distributed::EventFanout::new();
        fanout.add_sink(Box::new(SlowSink));
        let fanout = Arc::new(fanout);
        fanout.attach_runtime_health(Arc::clone(&runtime_health));
        collector.attach_fanout(fanout);

        assert_eq!(
            runtime_health.snapshot().distributed_export.state,
            nettrap_api::ComponentState::Running
        );
    }

    #[tokio::test]
    async fn nbi_pipeline_is_disabled_without_local_persistence_targets() {
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        collector.attach_runtime_health(Arc::clone(&runtime_health));
        assert_eq!(
            runtime_health.snapshot().nbi_pipeline.state,
            nettrap_api::ComponentState::Disabled
        );

        let db_path =
            std::env::temp_dir().join(format!("nettrap-nbi-db-attach-{}.db", uuid::Uuid::new_v4()));
        let db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path.to_string_lossy(), "test-node", "test-run").unwrap(),
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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        runtime_health.set_distributed_export_disabled();
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        collector.attach_runtime_health(Arc::clone(&runtime_health));

        let mut fanout = crate::distributed::EventFanout::new();
        fanout.add_sink(Box::new(SlowSink));
        let fanout = Arc::new(fanout);
        fanout.attach_runtime_health(Arc::clone(&runtime_health));
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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);

        let mut fanout = crate::distributed::EventFanout::new();
        fanout.add_sink(Box::new(SlowSink));
        collector.attach_fanout(Arc::new(fanout));

        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        collector.attach_runtime_health(Arc::clone(&runtime_health));

        assert_eq!(
            runtime_health.snapshot().distributed_export.state,
            nettrap_api::ComponentState::Running
        );
    }

    #[tokio::test]
    async fn replacing_sinkful_fanout_keeps_queued_events_on_original_fanout() {
        let collector = NbiCollector::new(None);
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
        let collector = NbiCollector::new(None);
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
        let collector = NbiCollector::new(None);
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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);

        let mut original_fanout = crate::distributed::EventFanout::new();
        original_fanout.add_sink(Box::new(FailingSink));
        let original_fanout = Arc::new(original_fanout);
        original_fanout.note_queued_record("retired-event");
        collector.attach_fanout(Arc::clone(&original_fanout));

        let mut replacement_fanout = crate::distributed::EventFanout::new();
        replacement_fanout.add_sink(Box::new(SlowSink));
        collector.attach_fanout(Arc::new(replacement_fanout));

        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);
        collector.record_shutdown_export_loss(1);

        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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

    #[test]
    fn attach_runtime_health_replays_prior_export_rejection_as_degraded() {
        let collector = NbiCollector::new(None);
        collector.drop_export_event("pre-health rejection");

        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);
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

        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        collector.attach_runtime_health(Arc::clone(&runtime_health));

        let mut fanout = crate::distributed::EventFanout::new();
        fanout.add_sink(Box::new(SlowSink));
        let fanout = Arc::new(fanout);
        fanout.attach_runtime_health(Arc::clone(&runtime_health));
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
        let collector = NbiCollector::new(None);
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
        let collector = NbiCollector::new(None);
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
        let collector = NbiCollector::new(None);
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
        let collector = NbiCollector::new(None);
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
        let collector = Arc::new(NbiCollector::new(None));
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

        let collector = NbiCollector::new(Some(path.clone()));
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        runtime_health.set_distributed_export_disabled();
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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

    #[tokio::test]
    async fn partial_local_persist_failure_degrades_without_latching_loss() {
        let bad_path =
            std::env::temp_dir().join(format!("nettrap-nbi-partial-dir-{}", uuid::Uuid::new_v4()));
        let db_path = std::env::temp_dir().join(format!(
            "nettrap-nbi-partial-db-{}.db",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&bad_path).unwrap();

        let collector = NbiCollector::new(Some(bad_path.clone()));
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        runtime_health.set_distributed_export_disabled();
        collector.attach_runtime_health(Arc::clone(&runtime_health));

        let db = Arc::new(DatabaseBackend::Sqlite(
            SqliteStorage::new(&db_path.to_string_lossy(), "test-node", "test-run").unwrap(),
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
        let collector = NbiCollector::new(Some(path.clone()));
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        runtime_health.set_distributed_export_disabled();
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(Some(path.clone()));
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        runtime_health.set_distributed_export_disabled();
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
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
        fanout.attach_retired_runtime_health(Arc::clone(&runtime_health));

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
        let collector = NbiCollector::new(None);
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        collector.attach_runtime_health(Arc::clone(&runtime_health));

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
    async fn local_worker_restarts_after_unexpected_exit() {
        let path =
            std::env::temp_dir().join(format!("nettrap-nbi-test-{}.jsonl", uuid::Uuid::new_v4()));
        let collector = NbiCollector::new(Some(path.clone()));

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

    #[test]
    fn legacy_json_without_dst_ip_defaults_to_unknown_destination() {
        let legacy = r#"{"timestamp":"2026-01-01T00:00:00Z","listener":"raw","protocol":"RAW","src_ip":"127.0.0.1","src_port":1234,"dst_port":8080,"process_name":null,"process_pid":null,"indicators":{}}"#;
        let parsed: NetworkBehaviorIndicator = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.dst_ip, "0.0.0.0");
        assert_eq!(parsed.dst_port, 8080);
    }
}
