use super::*;

impl NbiCollector {
    pub(super) fn note_export_delivery_loss_shared(
        health: &WorkerHealthRefs,
        reason: impl Into<String>,
    ) {
        let reason = format!("distributed export lost accepted event: {}", reason.into());
        atomic_fetch_add_saturating(&health.export_dropped, 1);
        *health.last_worker_error.write() = Some(reason.clone());
        if let Some(runtime_health) = health.runtime_health.read().clone() {
            runtime_health.update_nbi_collector(health.snapshot());
            runtime_health.set_distributed_export_loss(&reason);
        }
        tracing::warn!("{}", reason);
    }

    pub(super) fn note_export_delivery_unknown_shared(
        health: &WorkerHealthRefs,
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
        atomic_fetch_add_saturating(&health.export_unknown, count);
        *health.last_worker_error.write() = Some(reason.clone());
        if let Some(runtime_health) = health.runtime_health.read().clone() {
            runtime_health.update_nbi_collector(health.snapshot());
            runtime_health.set_distributed_export_degraded(&reason);
        }
        tracing::warn!("{}", reason);
    }

    pub(super) fn worker_health_refs(&self) -> WorkerHealthRefs {
        WorkerHealthRefs {
            runtime_health: Arc::clone(&self.runtime_health),
            local_dropped: Arc::clone(&self.local_worker.dropped),
            export_dropped: Arc::clone(&self.export_worker.dropped),
            export_rejected: Arc::clone(&self.export_rejected),
            export_unknown: Arc::clone(&self.export_unknown),
            local_persist_failures: Arc::clone(&self.local_persist_failures),
            worker_restarts: Arc::clone(&self.worker_restarts),
            last_worker_error: Arc::clone(&self.last_worker_error),
            last_local_persist_error: Arc::clone(&self.last_local_persist_error),
        }
    }

    pub(super) fn current_health_snapshot(&self) -> nettrap_core::health::NbiCollectorHealth {
        self.worker_health_refs().snapshot()
    }

    pub(super) fn publish_runtime_health(&self) {
        if let Some(runtime_health) = self.runtime_health.read().clone() {
            runtime_health.update_nbi_collector(self.current_health_snapshot());
        }
    }

    pub(super) fn has_local_persistence_target(&self) -> bool {
        self.path.is_some() || self.database.read().is_some()
    }

    pub(super) fn sync_local_persistence_health(&self, runtime_health: &dyn HealthSink) {
        if self.has_local_persistence_target() {
            runtime_health.set_nbi_pipeline_running();
        } else {
            runtime_health.set_nbi_pipeline_disabled();
        }
    }

    pub(super) fn note_local_persist_issue_shared(
        health: &WorkerHealthRefs,
        reason: impl Into<String>,
        total_loss: bool,
    ) {
        let reason = reason.into();
        atomic_fetch_add_saturating(&health.local_persist_failures, 1);
        *health.last_local_persist_error.write() = Some(reason.clone());
        if let Some(runtime_health) = health.runtime_health.read().clone() {
            runtime_health.update_nbi_collector(health.snapshot());
            if total_loss {
                runtime_health
                    .set_nbi_pipeline_loss(&format!("local NBI persistence failure: {}", reason));
            } else {
                runtime_health.set_nbi_pipeline_degraded(&format!(
                    "local NBI persistence failure: {}",
                    reason
                ));
            }
        }
        tracing::warn!("Local NBI persistence failure: {}", reason);
    }

    pub(super) fn record_worker_exit_shared(
        health: &WorkerHealthRefs,
        worker_name: &str,
        queued: &Arc<AtomicUsize>,
        dropped: &Arc<AtomicU64>,
        reason: String,
    ) {
        let lost = usize_to_u64_saturating(queued.swap(0, Ordering::Relaxed));
        if lost > 0 {
            atomic_fetch_add_saturating(dropped, lost);
        }
        atomic_fetch_add_saturating(&health.worker_restarts, 1);
        let reason = if lost > 0 {
            format!(
                "{} worker {} (dropped {} queued events)",
                worker_name, reason, lost
            )
        } else {
            format!("{} worker {}", worker_name, reason)
        };
        *health.last_worker_error.write() = Some(reason.clone());
        if let Some(runtime_health) = health.runtime_health.read().clone() {
            runtime_health.update_nbi_collector(health.snapshot());
            if worker_name.contains("local") {
                if lost > 0 {
                    runtime_health.set_nbi_pipeline_loss(&reason);
                } else {
                    runtime_health.set_nbi_pipeline_degraded(&reason);
                }
            } else if lost > 0 {
                runtime_health.set_distributed_export_loss(&reason);
            } else {
                runtime_health.set_distributed_export_degraded(&reason);
            }
        }
        tracing::warn!("{}", reason);
    }

    pub(super) fn drop_local_event(&self, reason: &str) {
        let dropped = atomic_fetch_add_saturating(&self.local_worker.dropped, 1);
        self.publish_runtime_health();
        if let Some(runtime_health) = self.runtime_health.read().clone() {
            runtime_health
                .set_nbi_pipeline_loss(&format!("local NBI persistence drop: {}", reason));
        }
        if dropped == 1 || dropped.is_multiple_of(100) {
            tracing::warn!(
                "Dropping NBI local event: {} (dropped={}, capacity={})",
                reason,
                dropped,
                NBI_LOCAL_QUEUE_CAPACITY
            );
        }
    }

    pub(super) fn drop_export_event(&self, reason: &str) {
        let rejected = atomic_fetch_add_saturating(&self.export_rejected, 1);
        let reason = format!(
            "distributed export rejected event before fanout acceptance: {}",
            reason
        );
        *self.last_worker_error.write() = Some(reason.clone());
        self.publish_runtime_health();
        if let Some(runtime_health) = self.runtime_health.read().clone() {
            runtime_health.set_distributed_export_degraded(&reason);
        }
        if rejected == 1 || rejected.is_multiple_of(100) {
            tracing::warn!(
                "Rejecting NBI export event before fanout acceptance: {} (rejected={}, capacity={})",
                reason,
                rejected,
                NBI_EXPORT_QUEUE_CAPACITY
            );
        }
    }
}
