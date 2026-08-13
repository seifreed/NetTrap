mod factory;
mod fanout;
mod health;
mod ioc_enrich;
mod process_enrich;
mod report;
mod worker;
mod worker_ctl;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub use nettrap_core::NetworkBehaviorIndicator;
use nettrap_core::health::HealthSink;

pub use factory::{
    HttpNbiInput, dns_nbi, ftp_nbi, http_nbi, irc_nbi, pop3_nbi, quic_nbi, raw_nbi, smtp_nbi,
    tftp_nbi, tls_nbi,
};
pub(crate) use ioc_enrich::enrich_nbi_with_iocs;
pub use report::{print_summary, print_summary_from_events};
use worker::{
    ExportWorkerCommand, ExportWorkerInterruption, LocalWorkerCommand, WorkerHealthRefs, WorkerSlot,
};

const NBI_LOCAL_QUEUE_CAPACITY: usize = 1024;
const NBI_EXPORT_QUEUE_CAPACITY: usize = 1024;
const NBI_WORKER_SUPERVISOR_INTERVAL_MS: u64 = 250;
#[cfg(not(test))]
const NBI_LOCAL_OPERATION_TIMEOUT_MS: u64 = 5000;
#[cfg(test)]
const NBI_LOCAL_OPERATION_TIMEOUT_MS: u64 = 100;
#[cfg(not(test))]
const NBI_EXPORT_OPERATION_TIMEOUT_MS: u64 = 5000;
#[cfg(test)]
const NBI_EXPORT_OPERATION_TIMEOUT_MS: u64 = 100;

fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn saturating_sum_u64(values: impl IntoIterator<Item = u64>) -> u64 {
    values
        .into_iter()
        .fold(0u64, |total, value| total.saturating_add(value))
}

fn saturating_sum_usize_as_u64(values: impl IntoIterator<Item = usize>) -> u64 {
    saturating_sum_u64(values.into_iter().map(usize_to_u64_saturating))
}

fn atomic_fetch_add_saturating(counter: &AtomicU64, amount: u64) -> u64 {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(amount);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(observed) => current = observed,
        }
    }
}

/// NBI collector that writes to JSONL file and optionally fans out to distributed sinks
pub struct NbiCollector {
    path: Option<PathBuf>,
    fanout: Arc<parking_lot::RwLock<Option<Arc<crate::distributed::EventFanout>>>>,
    retired_fanouts: Arc<parking_lot::RwLock<Vec<Arc<crate::distributed::EventFanout>>>>,
    runtime_health: Arc<parking_lot::RwLock<Option<Arc<dyn HealthSink>>>>,
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
    pub fn new(path: Option<PathBuf>) -> crate::Result<Self> {
        if matches!(path.as_ref(), Some(path) if path.as_os_str().is_empty()) {
            return Err(crate::Error::Config(
                "NBI path must not be empty".to_string(),
            ));
        }
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
        if collector.has_local_persistence_target()
            && let Err(err) = collector.ensure_local_worker_started()
        {
            return Err(crate::Error::Other(format!(
                "failed to start NBI local worker: {err}"
            )));
        }
        collector.ensure_supervisor_started();
        Ok(collector)
    }

    /// Attach a distributed event fanout (only stored if it has active sinks)
    pub fn with_fanout(self, fanout: std::sync::Arc<crate::distributed::EventFanout>) -> Self {
        self.attach_fanout(fanout);
        self
    }

    /// Attach or replace a distributed event fanout on a shared collector.
    pub fn attach_runtime_health(&self, runtime_health: Arc<dyn HealthSink>) {
        *self.runtime_health.write() = Some(Arc::clone(&runtime_health));
        self.sync_local_persistence_health(runtime_health.as_ref());
        let active_fanout = self.fanout.read().clone();
        let retired_fanouts: Vec<_> = self.retired_fanouts.read().iter().cloned().collect();
        if let Some(fanout) = active_fanout {
            fanout.attach_runtime_health(runtime_health.clone());
        }
        let mut has_draining_export = false;
        for fanout in retired_fanouts {
            if fanout.pending_events() > 0 {
                fanout.attach_retired_runtime_health(runtime_health.clone());
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
            runtime_health.set_distributed_export_loss(&loss_reason);
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
            runtime_health.set_distributed_export_degraded(&unknown_reason);
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
            runtime_health.set_distributed_export_degraded(&rejection_reason);
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
            self.sync_local_persistence_health(runtime_health.as_ref());
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
            .map(|(listener, protocol)| (listener.to_lowercase(), protocol))
            .collect();
    }

    #[cfg(test)]
    pub(crate) fn listener_protocol_count(&self) -> usize {
        self.listener_protocols.read().len()
    }

    fn enqueue_local_record(&self, nbi: NetworkBehaviorIndicator) {
        if !self.has_local_persistence_target() {
            if let Some(runtime_health) = self.runtime_health.read().clone() {
                self.sync_local_persistence_health(runtime_health.as_ref());
            }
            return;
        }

        match self.ensure_local_worker_started() {
            Ok(true) => {}
            Ok(false) => {
                self.drop_local_event("local worker unavailable");
                return;
            }
            Err(err) => {
                self.drop_local_event(&format!("local worker unavailable: {err}"));
                return;
            }
        }

        self.local_worker.queued.fetch_add(1, Ordering::Relaxed);
        let mut command = Some(LocalWorkerCommand::Record(Box::new(nbi)));
        for attempt in 0..2 {
            let tx = self.local_worker.sender();
            let Some(cmd) = command.take() else {
                self.local_worker.queued.fetch_sub(1, Ordering::Relaxed);
                self.drop_local_event("local worker command missing");
                return;
            };
            match tx.try_send(cmd) {
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
                    match self.ensure_local_worker_started() {
                        Ok(true) => {}
                        Ok(false) => {
                            self.drop_local_event("local worker restart failed");
                            return;
                        }
                        Err(err) => {
                            self.drop_local_event(&format!("local worker restart failed: {err}"));
                            return;
                        }
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
        fanout.note_queued_record(&event_id);
        self.export_worker.queued.fetch_add(1, Ordering::Relaxed);
        let mut command = Some(ExportWorkerCommand::Record(
            Box::new(nbi),
            Arc::clone(&fanout),
        ));
        for attempt in 0..2 {
            let tx = self.export_worker.sender();
            let Some(cmd) = command.take() else {
                self.export_worker.queued.fetch_sub(1, Ordering::Relaxed);
                fanout.forget_queued_record(&event_id);
                self.drop_export_event("export worker command missing");
                return;
            };
            match tx.try_send(cmd) {
                Ok(()) => return,
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    self.export_worker.queued.fetch_sub(1, Ordering::Relaxed);
                    fanout.forget_queued_record(&event_id);
                    self.drop_export_event("export queue full");
                    return;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(cmd)) if attempt == 0 => {
                    self.export_worker.queued.fetch_sub(1, Ordering::Relaxed);
                    fanout.forget_queued_record(&event_id);
                    self.note_export_worker_restart("channel closed");
                    if !self.ensure_export_worker_started() {
                        self.drop_export_event("export worker restart failed");
                        return;
                    }
                    fanout.note_queued_record(&event_id);
                    self.export_worker.queued.fetch_add(1, Ordering::Relaxed);
                    command = Some(cmd);
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    self.export_worker.queued.fetch_sub(1, Ordering::Relaxed);
                    fanout.forget_queued_record(&event_id);
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

        match self.ensure_local_worker_started() {
            Ok(true) => {}
            Ok(false) => return,
            Err(err) => {
                tracing::warn!("NBI local worker could not start: {}", err);
                return;
            }
        }

        let (flush_tx, flush_rx) = tokio::sync::oneshot::channel();
        match self
            .local_worker
            .sender()
            .send(LocalWorkerCommand::Flush(flush_tx))
            .await
        {
            Ok(()) => {
                match tokio::time::timeout(
                    std::time::Duration::from_millis(NBI_LOCAL_OPERATION_TIMEOUT_MS),
                    flush_rx,
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => self.note_worker_restart(
                        "NBI local",
                        &self.local_worker.queued,
                        &self.local_worker.dropped,
                        "flush ack dropped",
                    ),
                    Err(_) => {
                        let worker_handle = { self.local_worker.handle.lock().take() };
                        if let Some(handle) = worker_handle {
                            handle.abort();
                            if let Err(err) = handle.await
                                && !err.is_cancelled()
                            {
                                self.note_worker_restart(
                                    "NBI local",
                                    &self.local_worker.queued,
                                    &self.local_worker.dropped,
                                    format!("failed to join timed out flush worker: {}", err),
                                );
                                return;
                            }
                        }
                        self.note_worker_restart(
                            "NBI local",
                            &self.local_worker.queued,
                            &self.local_worker.dropped,
                            "flush timed out",
                        );
                    }
                }
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
            let unknown = saturating_sum_usize_as_u64(
                Self::collect_draining_fanouts(self.fanout.read().clone(), &self.retired_fanouts)
                    .into_iter()
                    .map(|fanout| fanout.mark_inflight_unknown()),
            );
            Self::note_export_delivery_unknown_shared(
                &self.worker_health_refs(),
                unknown,
                "distributed export shutdown timed out while deliveries were still in flight",
            );
        }

        let worker_handle = { self.export_worker.handle.lock().take() };
        if let Some(handle) = worker_handle {
            if shutdown_timed_out {
                handle.abort();
            }
            match handle.await {
                Ok(()) => {}
                Err(err) if err.is_cancelled() => {}
                Err(err) => {
                    self.note_export_worker_restart(format!(
                        "failed to join shutdown worker: {}",
                        err
                    ));
                }
            }
        }

        if !shutdown_acknowledged {
            let active_fanout = self.fanout.read().clone();
            for fanout in Self::collect_draining_fanouts(active_fanout, &self.retired_fanouts) {
                if let Err(err) = fanout.flush_all().await {
                    Self::note_export_flush_issue_shared(
                        &self.worker_health_refs(),
                        format!("distributed export shutdown fallback flush failed: {}", err),
                    );
                }
                let unknown = fanout.consume_unknown_sink_events() as u64;
                Self::note_export_delivery_unknown_shared(
                    &self.worker_health_refs(),
                    unknown,
                    "distributed export shutdown fallback left delivery state unknown",
                );
            }
        }

        let lost_from_queue =
            usize_to_u64_saturating(self.export_worker.queued.swap(0, Ordering::Relaxed));
        let mut lost_from_fanouts = 0u64;
        let active_fanout = self.fanout.read().clone();
        for fanout in Self::collect_draining_fanouts(active_fanout.clone(), &self.retired_fanouts) {
            lost_from_fanouts = lost_from_fanouts
                .saturating_add(usize_to_u64_saturating(fanout.drop_pending_records()));
        }

        self.record_shutdown_export_loss(lost_from_fanouts.saturating_add(lost_from_queue));
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

    pub async fn record(&self, nbi: &NetworkBehaviorIndicator) {
        let nbi = self.enrich_with_process(nbi).with_fresh_event_id();
        if let Err(err) = nbi.validate_resource_bounds() {
            let reason = err.to_string();
            if self.has_local_persistence_target() {
                self.drop_local_event(&reason);
            }
            if self.fanout.read().is_some() {
                self.drop_export_event(&reason);
            }
            tracing::warn!("Rejecting invalid NBI event: {}", reason);
            return;
        }

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
                if let Err(err) = fanout.flush_all().await {
                    Self::note_export_flush_issue_shared(
                        &self.worker_health_refs(),
                        format!("distributed export flush fallback failed: {}", err),
                    );
                }
                let unknown = fanout.consume_unknown_sink_events() as u64;
                Self::note_export_delivery_unknown_shared(
                    &self.worker_health_refs(),
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
                match tokio::time::timeout(
                    std::time::Duration::from_millis(NBI_EXPORT_OPERATION_TIMEOUT_MS),
                    flush_rx,
                )
                .await
                {
                    Ok(Ok(Ok(()))) => {}
                    Ok(Ok(Err(err))) => self.note_export_worker_restart(format!(
                        "flush failed while waiting for worker acknowledgement: {}",
                        err
                    )),
                    Ok(Err(_)) => self.note_export_worker_restart("flush ack dropped"),
                    Err(_) => {
                        self.note_export_worker_restart(
                            "flush timed out while waiting for worker acknowledgement",
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
                    if let Err(err) = fanout.flush_all().await {
                        Self::note_export_flush_issue_shared(
                            &self.worker_health_refs(),
                            format!(
                                "distributed export flush fallback failed after channel close: {}",
                                err
                            ),
                        );
                    }
                    let unknown = fanout.consume_unknown_sink_events() as u64;
                    Self::note_export_delivery_unknown_shared(
                        &self.worker_health_refs(),
                        unknown,
                        "distributed export flush fallback left delivery state unknown",
                    );
                }
                self.prune_retired_fanouts(self.fanout.read().clone());
            }
        }
    }

    fn enrich_with_process(&self, nbi: &NetworkBehaviorIndicator) -> NetworkBehaviorIndicator {
        if nbi.process_name.is_some() && nbi.process_pid.is_some() {
            return nbi.clone();
        }

        // Acquire both read locks atomically to prevent race condition
        // where session_tracker and listener_protocols could be modified
        // between individual lock acquisitions
        let (tracker, listener_protocol) = {
            let tracker = self.session_tracker.read().clone();
            let protocols = self.listener_protocols.read();
            let protocol = protocols.get(&nbi.listener.to_lowercase()).copied();
            (tracker, protocol)
        };
        process_enrich::with_session_process(nbi, tracker.as_deref(), listener_protocol)
    }
}

#[cfg(test)]
#[path = "nbi_tests.rs"]
mod tests;
