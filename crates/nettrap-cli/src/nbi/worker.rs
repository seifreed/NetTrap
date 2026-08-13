//! Internal worker state for the NBI collector.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use nettrap_core::health::HealthSink;

use super::NetworkBehaviorIndicator;

pub(super) enum LocalWorkerCommand {
    Record(Box<NetworkBehaviorIndicator>),
    Flush(tokio::sync::oneshot::Sender<()>),
}

pub(super) enum ExportWorkerCommand {
    Record(
        Box<NetworkBehaviorIndicator>,
        Arc<crate::distributed::EventFanout>,
    ),
    Flush(
        Option<Arc<crate::distributed::EventFanout>>,
        tokio::sync::oneshot::Sender<Result<(), String>>,
    ),
    Shutdown(tokio::sync::oneshot::Sender<()>),
}

#[derive(Clone)]
pub(super) struct WorkerHealthRefs {
    pub(super) runtime_health: Arc<parking_lot::RwLock<Option<Arc<dyn HealthSink>>>>,
    pub(super) local_dropped: Arc<AtomicU64>,
    pub(super) export_dropped: Arc<AtomicU64>,
    pub(super) export_rejected: Arc<AtomicU64>,
    pub(super) export_unknown: Arc<AtomicU64>,
    pub(super) local_persist_failures: Arc<AtomicU64>,
    pub(super) worker_restarts: Arc<AtomicU64>,
    pub(super) last_worker_error: Arc<parking_lot::RwLock<Option<String>>>,
    pub(super) last_local_persist_error: Arc<parking_lot::RwLock<Option<String>>>,
}

impl WorkerHealthRefs {
    pub(super) fn snapshot(&self) -> nettrap_api::NbiCollectorHealth {
        nettrap_api::NbiCollectorHealth {
            local_dropped: self.local_dropped.load(Ordering::Acquire),
            export_dropped: self.export_dropped.load(Ordering::Acquire),
            export_rejected: self.export_rejected.load(Ordering::Acquire),
            export_unknown: self.export_unknown.load(Ordering::Acquire),
            local_persist_failures: self.local_persist_failures.load(Ordering::Acquire),
            worker_restarts: self.worker_restarts.load(Ordering::Acquire),
            last_worker_error: self.last_worker_error.read().clone(),
            last_local_persist_error: self.last_local_persist_error.read().clone(),
        }
    }
}

#[derive(Clone)]
pub(super) struct WorkerSlotRefs {
    pub(super) handle: Arc<parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    pub(super) queued: Arc<AtomicUsize>,
    pub(super) dropped: Arc<AtomicU64>,
}

#[derive(Clone)]
pub(super) struct WorkerSupervisorContext {
    pub(super) health: WorkerHealthRefs,
    pub(super) fanout: Arc<parking_lot::RwLock<Option<Arc<crate::distributed::EventFanout>>>>,
    pub(super) retired_fanouts: Arc<parking_lot::RwLock<Vec<Arc<crate::distributed::EventFanout>>>>,
    pub(super) local: WorkerSlotRefs,
    pub(super) export: WorkerSlotRefs,
}

pub(super) struct LocalWorkerContext {
    pub(super) path: Option<PathBuf>,
    pub(super) database: Arc<parking_lot::RwLock<Option<Arc<crate::database::DatabaseBackend>>>>,
    pub(super) health: WorkerHealthRefs,
    pub(super) queued_events: Arc<AtomicUsize>,
}

pub(super) struct ExportWorkerContext {
    pub(super) active_fanout:
        Arc<parking_lot::RwLock<Option<Arc<crate::distributed::EventFanout>>>>,
    pub(super) retired_fanouts: Arc<parking_lot::RwLock<Vec<Arc<crate::distributed::EventFanout>>>>,
    pub(super) health: WorkerHealthRefs,
    pub(super) queued_events: Arc<AtomicUsize>,
}

pub(super) struct LocalPersistOutcome {
    pub(super) file_configured: bool,
    pub(super) db_configured: bool,
    pub(super) file_persisted: bool,
    pub(super) db_persisted: bool,
    pub(super) file_error: Option<String>,
    pub(super) db_error: Option<String>,
}

impl LocalPersistOutcome {
    pub(super) fn any_target_configured(&self) -> bool {
        self.file_configured || self.db_configured
    }

    pub(super) fn any_success(&self) -> bool {
        self.file_persisted || self.db_persisted
    }

    pub(super) fn is_total_failure(&self) -> bool {
        self.any_target_configured() && !self.any_success()
    }

    pub(super) fn error_summary(&self) -> Option<String> {
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

pub(super) struct WorkerSlot<C> {
    pub(super) tx: parking_lot::RwLock<tokio::sync::mpsc::Sender<C>>,
    pub(super) rx: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<C>>>,
    pub(super) handle: Arc<parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    pub(super) queued: Arc<AtomicUsize>,
    pub(super) dropped: Arc<AtomicU64>,
}

const MIN_WORKER_QUEUE_CAPACITY: usize = 1;

fn normalize_worker_queue_capacity(capacity: usize) -> usize {
    capacity.max(MIN_WORKER_QUEUE_CAPACITY)
}

impl<C> WorkerSlot<C> {
    pub(super) fn new(capacity: usize) -> Self {
        let capacity = normalize_worker_queue_capacity(capacity);
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        Self {
            tx: parking_lot::RwLock::new(tx),
            rx: std::sync::Mutex::new(Some(rx)),
            handle: Arc::new(parking_lot::Mutex::new(None)),
            queued: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(super) fn sender(&self) -> tokio::sync::mpsc::Sender<C> {
        self.tx.read().clone()
    }

    pub(super) fn refs(&self) -> WorkerSlotRefs {
        WorkerSlotRefs {
            handle: Arc::clone(&self.handle),
            queued: Arc::clone(&self.queued),
            dropped: Arc::clone(&self.dropped),
        }
    }

    pub(super) fn ensure_receiver(
        &self,
        capacity: usize,
    ) -> Result<Option<tokio::sync::mpsc::Receiver<C>>, String> {
        let mut guard = self
            .rx
            .lock()
            .map_err(|_| "worker receiver lock poisoned".to_string())?;
        if guard.is_none() {
            let capacity = normalize_worker_queue_capacity(capacity);
            let (tx, rx) = tokio::sync::mpsc::channel(capacity);
            *self.tx.write() = tx;
            *guard = Some(rx);
        }
        Ok(guard.take())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(super) struct ExportWorkerInterruption {
    pub(super) dropped: u64,
    pub(super) unknown: u64,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::WorkerSlot;

    #[test]
    fn worker_slot_normalizes_zero_capacity() {
        let slot = WorkerSlot::<u8>::new(0);
        assert_eq!(slot.sender().capacity(), 1);
    }

    #[test]
    fn ensure_receiver_normalizes_zero_capacity() {
        let slot = WorkerSlot::<u8>::new(1);
        let first_receiver = slot
            .ensure_receiver(1)
            .expect("receiver lock should not be poisoned")
            .expect("initial receiver should be available");
        drop(first_receiver);

        let replacement = slot
            .ensure_receiver(0)
            .expect("receiver lock should not be poisoned")
            .expect("replacement receiver should be available");

        assert_eq!(replacement.capacity(), 1);
    }

    #[test]
    fn ensure_receiver_reports_poisoned_lock_without_panicking() {
        let slot = Arc::new(WorkerSlot::<u8>::new(1));
        let poisoned_slot = Arc::clone(&slot);

        let _ = std::thread::spawn(move || {
            let _guard = poisoned_slot
                .rx
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            panic!("poison worker receiver lock");
        })
        .join();

        match slot.ensure_receiver(1) {
            Ok(_) => panic!("poisoned receiver lock should be reported"),
            Err(err) => assert_eq!(err, "worker receiver lock poisoned"),
        }
    }
}
