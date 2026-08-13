use super::*;

impl NbiCollector {
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
                            &self.worker_health_refs(),
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
                        &self.worker_health_refs(),
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
                    &self.worker_health_refs(),
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

    pub(super) fn register_retired_fanout(&self, fanout: Arc<crate::distributed::EventFanout>) {
        let mut retired_fanouts = self.retired_fanouts.write();
        if retired_fanouts
            .iter()
            .any(|existing| Arc::ptr_eq(existing, &fanout))
        {
            return;
        }
        retired_fanouts.push(fanout);
    }

    pub(super) fn collect_draining_fanouts(
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

    pub(super) fn prune_retired_fanouts(
        &self,
        active_fanout: Option<Arc<crate::distributed::EventFanout>>,
    ) {
        Self::prune_retired_fanouts_shared(
            &self.retired_fanouts,
            active_fanout,
            &self.runtime_health,
        );
    }

    pub(super) fn prune_retired_fanouts_shared(
        retired_fanouts: &Arc<parking_lot::RwLock<Vec<Arc<crate::distributed::EventFanout>>>>,
        active_fanout: Option<Arc<crate::distributed::EventFanout>>,
        runtime_health_ref: &Arc<parking_lot::RwLock<Option<Arc<dyn HealthSink>>>>,
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

        if active_fanout.is_none()
            && registry_empty
            && let Some(runtime_health) = runtime_health_ref.read().clone()
            && !runtime_health.distributed_export_loss_latched()
        {
            runtime_health.set_distributed_export_disabled();
        }
    }

    pub(super) fn pending_export_backlog(
        &self,
        fanout: &Arc<crate::distributed::EventFanout>,
    ) -> u64 {
        usize_to_u64_saturating(fanout.pending_events())
    }

    pub(super) fn record_retired_export_loss(&self, dropped: u64, reason: &str) {
        if dropped == 0 {
            return;
        }

        atomic_fetch_add_saturating(&self.export_worker.dropped, dropped);
        let reason = format!(
            "distributed export lost {} accepted events while retiring fanout: {}",
            dropped, reason
        );
        *self.last_worker_error.write() = Some(reason.clone());
        self.publish_runtime_health();
        if let Some(runtime_health) = self.runtime_health.read().clone() {
            runtime_health.set_distributed_export_loss(&reason);
        }
    }

    pub(super) fn record_shutdown_export_loss(&self, dropped: u64) {
        if dropped == 0 {
            return;
        }

        atomic_fetch_add_saturating(&self.export_worker.dropped, dropped);
        let reason = format!(
            "distributed export lost {} accepted events during shutdown finalization",
            dropped
        );
        *self.last_worker_error.write() = Some(reason.clone());
        self.publish_runtime_health();
        if let Some(runtime_health) = self.runtime_health.read().clone() {
            runtime_health.set_distributed_export_loss(&reason);
        }
    }

    pub(super) fn stop_export_worker(&self) -> ExportWorkerInterruption {
        if let Some(handle) = self.export_worker.handle.lock().take() {
            handle.abort();
        }
        self.reconcile_export_worker_interruption()
    }

    pub(super) fn note_worker_restart(
        &self,
        worker_name: &str,
        queued: &Arc<AtomicUsize>,
        dropped: &Arc<AtomicU64>,
        reason: impl Into<String>,
    ) {
        Self::record_worker_exit_shared(
            &self.worker_health_refs(),
            worker_name,
            queued,
            dropped,
            reason.into(),
        );
    }

    pub(super) fn reconcile_export_worker_interruption(&self) -> ExportWorkerInterruption {
        let lost_from_queue =
            usize_to_u64_saturating(self.export_worker.queued.swap(0, Ordering::Relaxed));
        let lost_from_fanouts = saturating_sum_usize_as_u64(
            Self::collect_draining_fanouts(self.fanout.read().clone(), &self.retired_fanouts)
                .into_iter()
                .map(|fanout| fanout.drop_queued_records()),
        );
        let unknown = saturating_sum_usize_as_u64(
            Self::collect_draining_fanouts(self.fanout.read().clone(), &self.retired_fanouts)
                .into_iter()
                .map(|fanout| fanout.mark_inflight_unknown()),
        );
        ExportWorkerInterruption {
            dropped: lost_from_queue.saturating_add(lost_from_fanouts),
            unknown,
        }
    }

    pub(super) fn note_export_worker_restart(&self, reason: impl Into<String>) {
        let interruption = self.reconcile_export_worker_interruption();
        if interruption.dropped > 0 {
            atomic_fetch_add_saturating(&self.export_worker.dropped, interruption.dropped);
        }
        if interruption.unknown > 0 {
            atomic_fetch_add_saturating(&self.export_unknown, interruption.unknown);
        }
        atomic_fetch_add_saturating(&self.worker_restarts, 1);
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
                runtime_health.set_distributed_export_loss(&reason);
            } else {
                runtime_health.set_distributed_export_degraded(&reason);
            }
        }
        self.prune_retired_fanouts(self.fanout.read().clone());
        tracing::warn!(
            "{}",
            self.last_worker_error.read().clone().unwrap_or_default()
        );
    }
}
