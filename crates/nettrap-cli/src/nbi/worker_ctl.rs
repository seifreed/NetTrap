use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::worker::{
    ExportWorkerCommand, ExportWorkerContext, LocalPersistOutcome, LocalWorkerCommand,
    LocalWorkerContext, WorkerHealthRefs, WorkerSlotRefs, WorkerSupervisorContext,
};
use super::{
    NBI_EXPORT_QUEUE_CAPACITY, NBI_LOCAL_QUEUE_CAPACITY, NBI_WORKER_SUPERVISOR_INTERVAL_MS,
    NbiCollector, NetworkBehaviorIndicator, atomic_fetch_add_saturating,
    saturating_sum_usize_as_u64, usize_to_u64_saturating,
};
use nettrap_fsutil::append_regular_file;

fn send_worker_ack(sender: tokio::sync::oneshot::Sender<()>, context: &str) {
    if sender.send(()).is_err() {
        tracing::warn!(
            "Dropped worker ack because the receiver closed: {}",
            context
        );
    }
}

fn send_flush_result(
    sender: tokio::sync::oneshot::Sender<Result<(), String>>,
    result: Result<(), String>,
) {
    if sender.send(result).is_err() {
        tracing::warn!("Dropped worker flush result because the receiver closed");
    }
}

impl NbiCollector {
    pub(super) fn ensure_supervisor_started(&self) {
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

        let supervisor = WorkerSupervisorContext {
            health: self.worker_health_refs(),
            fanout: Arc::clone(&self.fanout),
            retired_fanouts: Arc::clone(&self.retired_fanouts),
            local: self.local_worker.refs(),
            export: self.export_worker.refs(),
        };

        *handle = Some(runtime.spawn(async move {
            NbiCollector::run_worker_supervisor(supervisor).await;
        }));
    }

    async fn run_worker_supervisor(ctx: WorkerSupervisorContext) {
        let interval = std::time::Duration::from_millis(NBI_WORKER_SUPERVISOR_INTERVAL_MS);
        loop {
            tokio::time::sleep(interval).await;

            NbiCollector::check_worker_exit(&ctx.health, "NBI local", &ctx.local).await;

            let active_fanout = { ctx.fanout.read().clone() };
            let draining_fanouts =
                NbiCollector::collect_draining_fanouts(active_fanout.clone(), &ctx.retired_fanouts);
            let supervise_export = !draining_fanouts.is_empty()
                || ctx.export.handle.lock().as_ref().is_some()
                || ctx.export.queued.load(Ordering::Relaxed) > 0;
            if supervise_export {
                NbiCollector::check_export_worker_exit(&ctx, &active_fanout).await;
                for draining_fanout in &draining_fanouts {
                    if let Err(err) = draining_fanout.flush_stale_batches().await {
                        NbiCollector::note_export_flush_issue_shared(
                            &ctx.health,
                            format!("distributed export stale flush failed: {}", err),
                        );
                    }
                    let unknown = draining_fanout.consume_unknown_sink_events() as u64;
                    NbiCollector::note_export_delivery_unknown_shared(
                        &ctx.health,
                        unknown,
                        "distributed export stale flush left delivery state unknown",
                    );
                }
                NbiCollector::prune_retired_fanouts_shared(
                    &ctx.retired_fanouts,
                    active_fanout,
                    &ctx.health.runtime_health,
                );
            }
        }
    }

    async fn check_worker_exit(
        health: &WorkerHealthRefs,
        worker_name: &str,
        slot: &WorkerSlotRefs,
    ) {
        let finished = {
            let mut guard = slot.handle.lock();
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
                health,
                worker_name,
                &slot.queued,
                &slot.dropped,
                reason,
            );
        }
    }

    async fn check_export_worker_exit(
        ctx: &WorkerSupervisorContext,
        active_fanout: &Option<Arc<crate::distributed::EventFanout>>,
    ) {
        let finished = {
            let mut guard = ctx.export.handle.lock();
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
            let lost_from_queue =
                usize_to_u64_saturating(ctx.export.queued.swap(0, Ordering::Relaxed));
            let lost_from_fanouts = saturating_sum_usize_as_u64(
                Self::collect_draining_fanouts(active_fanout.clone(), &ctx.retired_fanouts)
                    .into_iter()
                    .map(|fanout| fanout.drop_queued_records()),
            );
            let unknown = saturating_sum_usize_as_u64(
                Self::collect_draining_fanouts(active_fanout.clone(), &ctx.retired_fanouts)
                    .into_iter()
                    .map(|fanout| fanout.mark_inflight_unknown()),
            );
            let lost = lost_from_queue.saturating_add(lost_from_fanouts);
            if lost > 0 {
                atomic_fetch_add_saturating(&ctx.export.dropped, lost);
            }
            if unknown > 0 {
                atomic_fetch_add_saturating(&ctx.health.export_unknown, unknown);
            }
            atomic_fetch_add_saturating(&ctx.health.worker_restarts, 1);
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
            *ctx.health.last_worker_error.write() = Some(reason.clone());
            if let Some(runtime_health) = ctx.health.runtime_health.read().clone() {
                runtime_health.update_nbi_collector(ctx.health.snapshot());
                if lost > 0 {
                    runtime_health.set_distributed_export_loss(&reason);
                } else {
                    runtime_health.set_distributed_export_degraded(&reason);
                }
            }
            tracing::warn!("{}", reason);
            Self::prune_retired_fanouts_shared(
                &ctx.retired_fanouts,
                active_fanout.clone(),
                &ctx.health.runtime_health,
            );
        }
    }

    pub(super) fn note_export_flush_issue_shared(
        health: &WorkerHealthRefs,
        reason: impl Into<String>,
    ) {
        let reason = reason.into();
        *health.last_worker_error.write() = Some(reason.clone());
        if let Some(runtime_health) = health.runtime_health.read().clone() {
            runtime_health.update_nbi_collector(health.snapshot());
            runtime_health.set_distributed_export_degraded(&reason);
        }
        tracing::warn!("{}", reason);
    }

    pub(super) fn ensure_local_worker_started(&self) -> Result<bool, String> {
        if !self.has_local_persistence_target() {
            if let Some(runtime_health) = self.runtime_health.read().clone() {
                self.sync_local_persistence_health(runtime_health.as_ref());
            }
            return Ok(false);
        }

        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return Ok(false);
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
                return Ok(true);
            }
        }

        let worker_rx = match self.local_worker.ensure_receiver(NBI_LOCAL_QUEUE_CAPACITY) {
            Ok(Some(worker_rx)) => worker_rx,
            Ok(None) => return Ok(false),
            Err(err) => {
                self.note_worker_restart(
                    "NBI local",
                    &self.local_worker.queued,
                    &self.local_worker.dropped,
                    err,
                );
                return Err("failed to prepare NBI local worker receiver".to_string());
            }
        };

        let worker_ctx = LocalWorkerContext {
            path: self.path.clone(),
            database: Arc::clone(&self.database),
            health: self.worker_health_refs(),
            queued_events: Arc::clone(&self.local_worker.queued),
        };
        let worker_handle = runtime.spawn(async move {
            NbiCollector::run_local_worker(worker_rx, worker_ctx).await;
        });
        *handle = Some(worker_handle);
        drop(handle);
        if let Some(runtime_health) = self.runtime_health.read().clone() {
            self.sync_local_persistence_health(runtime_health.as_ref());
        }
        self.ensure_supervisor_started();
        Ok(true)
    }

    pub(super) fn ensure_export_worker_started(&self) -> bool {
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

        let worker_rx = match self
            .export_worker
            .ensure_receiver(NBI_EXPORT_QUEUE_CAPACITY)
        {
            Ok(Some(worker_rx)) => worker_rx,
            Ok(None) => return false,
            Err(err) => {
                self.note_export_worker_restart(err);
                return false;
            }
        };

        let worker_ctx = ExportWorkerContext {
            active_fanout: Arc::clone(&self.fanout),
            retired_fanouts: Arc::clone(&self.retired_fanouts),
            health: self.worker_health_refs(),
            queued_events: Arc::clone(&self.export_worker.queued),
        };
        let worker_handle = runtime.spawn(async move {
            NbiCollector::run_export_worker(worker_rx, worker_ctx).await;
        });
        *handle = Some(worker_handle);
        drop(handle);
        self.ensure_supervisor_started();
        true
    }

    async fn run_local_worker(
        mut worker_rx: tokio::sync::mpsc::Receiver<LocalWorkerCommand>,
        ctx: LocalWorkerContext,
    ) {
        while let Some(command) = worker_rx.recv().await {
            match command {
                LocalWorkerCommand::Record(nbi) => {
                    let outcome =
                        NbiCollector::persist_local_record(ctx.path.as_ref(), &ctx.database, &nbi)
                            .await;
                    if let Some(error) = outcome.error_summary() {
                        NbiCollector::note_local_persist_issue_shared(
                            &ctx.health,
                            error,
                            outcome.is_total_failure(),
                        );
                    } else if outcome.any_target_configured()
                        && let Some(runtime_health) = ctx.health.runtime_health.read().clone()
                    {
                        runtime_health.set_nbi_pipeline_running();
                        runtime_health.update_nbi_collector(ctx.health.snapshot());
                    }
                    ctx.queued_events.fetch_sub(1, Ordering::Relaxed);
                }
                LocalWorkerCommand::Flush(flush_tx) => {
                    send_worker_ack(flush_tx, "local worker flush");
                }
            }
        }
    }

    async fn run_export_worker(
        mut worker_rx: tokio::sync::mpsc::Receiver<ExportWorkerCommand>,
        ctx: ExportWorkerContext,
    ) {
        while let Some(command) = worker_rx.recv().await {
            match command {
                ExportWorkerCommand::Record(nbi, fanout) => {
                    let event_id = nbi.normalized_event_id();
                    fanout.note_send_started(&event_id);
                    ctx.queued_events.fetch_sub(1, Ordering::Relaxed);
                    let outcome = fanout.send(&nbi).await;
                    let outcome_error = outcome.error.clone();
                    let completion = fanout.note_dequeued_record(&event_id);
                    if completion.final_loss {
                        let reason = outcome_error.clone().unwrap_or_else(|| {
                            "distributed export lost an accepted event without retry buffer"
                                .to_string()
                        });
                        NbiCollector::note_export_delivery_loss_shared(&ctx.health, reason);
                    }
                    if completion.became_unknown {
                        NbiCollector::note_export_delivery_unknown_shared(
                            &ctx.health,
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
                        current_fanout.or_else(|| ctx.active_fanout.read().clone()),
                        &ctx.retired_fanouts,
                    );
                    for fanout in &fanouts_to_flush {
                        if let Err(err) = fanout.flush_all().await {
                            flush_errors.push(err);
                        }
                        let unknown = fanout.consume_unknown_sink_events() as u64;
                        NbiCollector::note_export_delivery_unknown_shared(
                            &ctx.health,
                            unknown,
                            "distributed export flush left delivery state unknown",
                        );
                    }
                    NbiCollector::prune_retired_fanouts_shared(
                        &ctx.retired_fanouts,
                        ctx.active_fanout.read().clone(),
                        &ctx.health.runtime_health,
                    );
                    if flush_errors.is_empty() {
                        send_flush_result(flush_tx, Ok(()));
                    } else {
                        send_flush_result(flush_tx, Err(flush_errors.join("; ")));
                    }
                }
                ExportWorkerCommand::Shutdown(shutdown_tx) => {
                    let fanouts_to_flush = NbiCollector::collect_draining_fanouts(
                        ctx.active_fanout.read().clone(),
                        &ctx.retired_fanouts,
                    );
                    for fanout in &fanouts_to_flush {
                        if let Err(err) = fanout.flush_all().await {
                            NbiCollector::note_export_flush_issue_shared(
                                &ctx.health,
                                format!("distributed export shutdown flush failed: {}", err),
                            );
                        }
                        let unknown = fanout.consume_unknown_sink_events() as u64;
                        NbiCollector::note_export_delivery_unknown_shared(
                            &ctx.health,
                            unknown,
                            "distributed export shutdown flush left delivery state unknown",
                        );
                    }
                    NbiCollector::prune_retired_fanouts_shared(
                        &ctx.retired_fanouts,
                        ctx.active_fanout.read().clone(),
                        &ctx.health.runtime_health,
                    );
                    send_worker_ack(shutdown_tx, "export worker shutdown");
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
            match nbi.to_json() {
                Ok(json) => {
                    let path = path.clone();
                    let file_result = tokio::task::spawn_blocking(move || {
                        use std::io::Write;

                        let mut file = append_regular_file(&path).map_err(|err| {
                            format!("failed to open NBI file {}: {}", path.display(), err)
                        })?;
                        file.write_all(json.as_bytes())
                            .map_err(|err| format!("failed to write NBI event to file: {}", err))?;
                        file.write_all(b"\n").map_err(|err| {
                            format!("failed to write NBI newline to file: {}", err)
                        })?;
                        Ok::<(), String>(())
                    })
                    .await
                    .map_err(|err| format!("NBI file worker failed: {}", err))
                    .and_then(|result| result);
                    match file_result {
                        Ok(()) => outcome.file_persisted = true,
                        Err(error) => outcome.file_error = Some(error),
                    }
                }
                Err(error) => {
                    outcome.file_error = Some(format!("failed to serialize NBI event: {}", error))
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
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    use nettrap_core::health::{
        ComponentHealth, HealthSink, HealthStatus, NbiCollectorHealth, RuntimeHealthSnapshot,
    };
    use parking_lot::{Mutex, RwLock};

    use super::NbiCollector;
    use super::WorkerHealthRefs;

    #[derive(Default)]
    struct RecordingHealthSink {
        snapshot: Mutex<Option<RuntimeHealthSnapshot>>,
        degraded: Mutex<Vec<String>>,
    }

    impl HealthSink for RecordingHealthSink {
        fn snapshot(&self) -> RuntimeHealthSnapshot {
            self.snapshot
                .lock()
                .clone()
                .unwrap_or_else(|| RuntimeHealthSnapshot {
                    status: HealthStatus::Ok,
                    startup_complete: false,
                    fatal_error: None,
                    listeners: Vec::new(),
                    interceptor: ComponentHealth::default(),
                    api: ComponentHealth::default(),
                    distributed_export: ComponentHealth::default(),
                    nbi_pipeline: ComponentHealth::default(),
                    nbi_collector: NbiCollectorHealth::default(),
                })
        }

        fn distributed_export_loss_latched(&self) -> bool {
            false
        }

        fn set_distributed_export_running(&self) {}

        fn set_distributed_export_disabled(&self) {}

        fn set_distributed_export_degraded(&self, error: &str) {
            self.degraded.lock().push(error.to_string());
        }

        fn set_distributed_export_loss(&self, _error: &str) {}

        fn set_nbi_pipeline_running(&self) {}

        fn set_nbi_pipeline_disabled(&self) {}

        fn set_nbi_pipeline_degraded(&self, _error: &str) {}

        fn set_nbi_pipeline_loss(&self, _error: &str) {}

        fn update_nbi_collector(&self, snapshot: NbiCollectorHealth) {
            self.snapshot.lock().replace(RuntimeHealthSnapshot {
                status: HealthStatus::Degraded,
                startup_complete: false,
                fatal_error: None,
                listeners: Vec::new(),
                interceptor: ComponentHealth::default(),
                api: ComponentHealth::default(),
                distributed_export: ComponentHealth::default(),
                nbi_pipeline: ComponentHealth::default(),
                nbi_collector: snapshot,
            });
        }
    }

    fn worker_health_refs(runtime_health: Option<Arc<dyn HealthSink>>) -> WorkerHealthRefs {
        WorkerHealthRefs {
            runtime_health: Arc::new(RwLock::new(runtime_health)),
            local_dropped: Arc::new(AtomicU64::new(0)),
            export_dropped: Arc::new(AtomicU64::new(0)),
            export_rejected: Arc::new(AtomicU64::new(0)),
            export_unknown: Arc::new(AtomicU64::new(0)),
            local_persist_failures: Arc::new(AtomicU64::new(0)),
            worker_restarts: Arc::new(AtomicU64::new(0)),
            last_worker_error: Arc::new(RwLock::new(None)),
            last_local_persist_error: Arc::new(RwLock::new(None)),
        }
    }

    #[tokio::test]
    async fn ensure_local_worker_started_reports_poisoned_receiver_lock() {
        let path = std::env::temp_dir().join(format!(
            "nettrap-local-worker-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let collector = NbiCollector::new(Some(path)).expect("collector should build");

        let handle = collector
            .local_worker
            .handle
            .lock()
            .take()
            .expect("local worker should be running");
        handle.abort();
        let _ = handle.await;

        let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = collector.local_worker.rx.lock().unwrap();
            panic!("poison worker receiver lock");
        }));
        assert!(poison.is_err());

        let err = collector
            .ensure_local_worker_started()
            .expect_err("poisoned receiver lock should be reported");
        assert_eq!(err, "failed to prepare NBI local worker receiver");
    }

    #[test]
    fn note_export_flush_issue_shared_updates_health_and_error_state() {
        let runtime = Arc::new(RecordingHealthSink::default());
        let health = worker_health_refs(Some(runtime.clone()));

        NbiCollector::note_export_flush_issue_shared(&health, "timeout");

        assert_eq!(health.last_worker_error.read().as_deref(), Some("timeout"));
        assert_eq!(runtime.degraded.lock().len(), 1);
        assert_eq!(
            runtime.degraded.lock().first().map(String::as_str),
            Some("timeout")
        );
        assert_eq!(
            runtime
                .snapshot
                .lock()
                .as_ref()
                .map(|snapshot| snapshot.nbi_collector.last_worker_error.as_deref()),
            Some(Some("timeout"))
        );
    }

    #[test]
    fn note_export_flush_issue_shared_keeps_existing_prefix_single() {
        let runtime = Arc::new(RecordingHealthSink::default());
        let health = worker_health_refs(Some(runtime.clone()));

        NbiCollector::note_export_flush_issue_shared(
            &health,
            "distributed export stale flush failed: timeout",
        );

        assert_eq!(
            health.last_worker_error.read().as_deref(),
            Some("distributed export stale flush failed: timeout")
        );
        assert_eq!(runtime.degraded.lock().len(), 1);
        assert_eq!(
            runtime.degraded.lock().first().map(String::as_str),
            Some("distributed export stale flush failed: timeout")
        );
    }

    #[test]
    fn send_flush_result_reports_closed_receiver_without_panicking() {
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        drop(rx);

        crate::nbi::worker_ctl::send_flush_result(tx, Ok(()));
    }
}
