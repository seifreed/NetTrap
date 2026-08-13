use std::collections::HashMap;

use parking_lot::RwLock;

pub use nettrap_core::health::{
    ComponentHealth, ComponentState, HealthSink, HealthStatus, ListenerHealth, NbiCollectorHealth,
    RuntimeHealthSnapshot, runtime_health_payload,
};

#[derive(Debug, Default)]
struct RuntimeHealthState {
    startup_complete: bool,
    fatal_error: Option<String>,
    allow_zero_listeners: bool,
    listeners: HashMap<String, ListenerHealth>,
    interceptor: ComponentHealth,
    api: ComponentHealth,
    distributed_export: ComponentHealth,
    nbi_pipeline: ComponentHealth,
    nbi_collector: NbiCollectorHealth,
    distributed_export_loss_latched: bool,
    nbi_pipeline_loss_latched: bool,
}

#[derive(Debug, Default)]
pub struct RuntimeHealth {
    state: RwLock<RuntimeHealthState>,
}

impl RuntimeHealth {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_listener(
        &self,
        name: impl Into<String>,
        protocol: impl Into<String>,
        port: u16,
    ) {
        let name = name.into();
        self.state.write().listeners.insert(
            name.clone(),
            ListenerHealth {
                name,
                protocol: protocol.into(),
                port,
                state: ComponentState::Starting,
                error: None,
            },
        );
    }

    pub fn mark_listener_running(&self, name: &str, port: u16) {
        if let Some(listener) = self.state.write().listeners.get_mut(name) {
            listener.port = port;
            listener.state = ComponentState::Running;
            listener.error = None;
        }
    }

    pub fn mark_listener_failed(&self, name: &str, error: impl Into<String>) {
        let error = error.into();
        let mut state = self.state.write();
        if let Some(listener) = state.listeners.get_mut(name) {
            listener.state = ComponentState::Failed;
            listener.error = Some(error.clone());
        }
        state.fatal_error = Some(error);
    }

    pub fn mark_listener_stopped(&self, name: &str) {
        if let Some(listener) = self.state.write().listeners.get_mut(name) {
            listener.state = ComponentState::Stopped;
        }
    }

    pub fn mark_startup_complete(&self) {
        self.state.write().startup_complete = true;
    }

    pub fn set_fatal_error(&self, error: impl Into<String>) {
        self.state.write().fatal_error = Some(error.into());
    }

    pub fn set_allow_zero_listeners(&self, allow: bool) {
        self.state.write().allow_zero_listeners = allow;
    }

    pub fn set_interceptor_disabled(&self) {
        let mut state = self.state.write();
        state.interceptor.state = ComponentState::Disabled;
        state.interceptor.error = None;
    }

    pub fn set_interceptor_starting(&self) {
        let mut state = self.state.write();
        state.interceptor.state = ComponentState::Starting;
        state.interceptor.error = None;
    }

    pub fn set_interceptor_running(&self) {
        let mut state = self.state.write();
        state.interceptor.state = ComponentState::Running;
        state.interceptor.error = None;
    }

    pub fn set_interceptor_stopped(&self) {
        let mut state = self.state.write();
        state.interceptor.state = ComponentState::Stopped;
        state.interceptor.error = None;
    }

    pub fn set_interceptor_failed(&self, error: impl Into<String>) {
        let error = error.into();
        let mut state = self.state.write();
        state.interceptor.state = ComponentState::Failed;
        state.interceptor.error = Some(error.clone());
        state.fatal_error = Some(error);
    }

    pub fn set_api_disabled(&self) {
        let mut state = self.state.write();
        state.api.state = ComponentState::Disabled;
        state.api.error = None;
    }

    pub fn set_api_running(&self) {
        let mut state = self.state.write();
        state.api.state = ComponentState::Running;
        state.api.error = None;
    }

    pub fn set_api_failed(&self, error: impl Into<String>) {
        let error = error.into();
        let mut state = self.state.write();
        state.api.state = ComponentState::Failed;
        state.api.error = Some(error.clone());
        state.fatal_error = Some(error);
    }

    fn sticky_distributed_export_error(state: &RuntimeHealthState) -> Option<String> {
        if state.distributed_export_loss_latched {
            return state.distributed_export.error.clone();
        }

        if state.nbi_collector.export_unknown > 0 {
            return Some(
                state
                    .nbi_collector
                    .last_worker_error
                    .clone()
                    .filter(|error| error.contains("delivery state is unknown"))
                    .unwrap_or_else(|| {
                        format!(
                            "distributed export has {} events in unknown delivery state",
                            state.nbi_collector.export_unknown
                        )
                    }),
            );
        }

        if state.nbi_collector.export_rejected > 0 {
            return Some(
                state
                    .nbi_collector
                    .last_worker_error
                    .clone()
                    .filter(|error| error.contains("distributed export rejected"))
                    .unwrap_or_else(|| {
                        format!(
                            "distributed export previously rejected {} events",
                            state.nbi_collector.export_rejected
                        )
                    }),
            );
        }

        None
    }

    pub fn set_distributed_export_disabled(&self) {
        let mut state = self.state.write();
        if state.distributed_export_loss_latched {
            return;
        }
        if let Some(error) = Self::sticky_distributed_export_error(&state) {
            state.distributed_export.state = ComponentState::Degraded;
            state.distributed_export.error = Some(error);
            return;
        }
        state.distributed_export.state = ComponentState::Disabled;
        state.distributed_export.error = None;
    }

    pub fn set_distributed_export_starting(&self) {
        let mut state = self.state.write();
        if state.distributed_export_loss_latched {
            return;
        }
        if let Some(error) = Self::sticky_distributed_export_error(&state) {
            state.distributed_export.state = ComponentState::Degraded;
            state.distributed_export.error = Some(error);
            return;
        }
        state.distributed_export.state = ComponentState::Starting;
        state.distributed_export.error = None;
    }

    pub fn set_distributed_export_running(&self) {
        let mut state = self.state.write();
        if state.distributed_export_loss_latched {
            return;
        }
        if let Some(error) = Self::sticky_distributed_export_error(&state) {
            state.distributed_export.state = ComponentState::Degraded;
            state.distributed_export.error = Some(error);
            return;
        }
        state.distributed_export.state = ComponentState::Running;
        state.distributed_export.error = None;
    }

    pub fn set_distributed_export_degraded(&self, error: impl Into<String>) {
        let mut state = self.state.write();
        if state.distributed_export_loss_latched {
            return;
        }
        state.distributed_export.state = ComponentState::Degraded;
        state.distributed_export.error = Some(error.into());
    }

    pub fn set_distributed_export_loss(&self, error: impl Into<String>) {
        let mut state = self.state.write();
        state.distributed_export_loss_latched = true;
        state.distributed_export.state = ComponentState::Degraded;
        state.distributed_export.error = Some(error.into());
    }

    pub fn distributed_export_loss_latched(&self) -> bool {
        self.state.read().distributed_export_loss_latched
    }

    pub fn set_nbi_pipeline_running(&self) {
        let mut state = self.state.write();
        if state.nbi_pipeline_loss_latched {
            return;
        }
        state.nbi_pipeline.state = ComponentState::Running;
        state.nbi_pipeline.error = None;
    }

    pub fn set_nbi_pipeline_disabled(&self) {
        let mut state = self.state.write();
        state.nbi_pipeline.state = ComponentState::Disabled;
        state.nbi_pipeline.error = None;
        state.nbi_pipeline_loss_latched = false;
    }

    pub fn set_nbi_pipeline_degraded(&self, error: impl Into<String>) {
        let mut state = self.state.write();
        if state.nbi_pipeline_loss_latched {
            return;
        }
        state.nbi_pipeline.state = ComponentState::Degraded;
        state.nbi_pipeline.error = Some(error.into());
    }

    pub fn set_nbi_pipeline_loss(&self, error: impl Into<String>) {
        let mut state = self.state.write();
        state.nbi_pipeline_loss_latched = true;
        state.nbi_pipeline.state = ComponentState::Degraded;
        state.nbi_pipeline.error = Some(error.into());
    }

    pub fn update_nbi_collector(&self, snapshot: NbiCollectorHealth) {
        let mut state = self.state.write();
        state.nbi_collector = snapshot;
        if state.distributed_export_loss_latched {
            return;
        }
        if let Some(error) = Self::sticky_distributed_export_error(&state) {
            state.distributed_export.state = ComponentState::Degraded;
            state.distributed_export.error = Some(error);
        }
    }

    pub fn snapshot(&self) -> RuntimeHealthSnapshot {
        let state = self.state.read();
        let mut listeners: Vec<_> = state.listeners.values().cloned().collect();
        listeners.sort_by(|left, right| {
            left.port
                .cmp(&right.port)
                .then_with(|| left.name.cmp(&right.name))
        });

        RuntimeHealthSnapshot {
            status: compute_status(&state),
            startup_complete: state.startup_complete,
            fatal_error: state.fatal_error.clone(),
            listeners,
            interceptor: state.interceptor.clone(),
            api: state.api.clone(),
            distributed_export: state.distributed_export.clone(),
            nbi_pipeline: state.nbi_pipeline.clone(),
            nbi_collector: state.nbi_collector.clone(),
        }
    }
}

impl HealthSink for RuntimeHealth {
    fn snapshot(&self) -> RuntimeHealthSnapshot {
        RuntimeHealth::snapshot(self)
    }

    fn distributed_export_loss_latched(&self) -> bool {
        RuntimeHealth::distributed_export_loss_latched(self)
    }

    fn set_distributed_export_running(&self) {
        RuntimeHealth::set_distributed_export_running(self)
    }

    fn set_distributed_export_disabled(&self) {
        RuntimeHealth::set_distributed_export_disabled(self)
    }

    fn set_distributed_export_degraded(&self, error: &str) {
        RuntimeHealth::set_distributed_export_degraded(self, error)
    }

    fn set_distributed_export_loss(&self, error: &str) {
        RuntimeHealth::set_distributed_export_loss(self, error)
    }

    fn set_nbi_pipeline_running(&self) {
        RuntimeHealth::set_nbi_pipeline_running(self)
    }

    fn set_nbi_pipeline_disabled(&self) {
        RuntimeHealth::set_nbi_pipeline_disabled(self)
    }

    fn set_nbi_pipeline_degraded(&self, error: &str) {
        RuntimeHealth::set_nbi_pipeline_degraded(self, error)
    }

    fn set_nbi_pipeline_loss(&self, error: &str) {
        RuntimeHealth::set_nbi_pipeline_loss(self, error)
    }

    fn update_nbi_collector(&self, snapshot: NbiCollectorHealth) {
        RuntimeHealth::update_nbi_collector(self, snapshot)
    }
}

fn compute_status(state: &RuntimeHealthState) -> HealthStatus {
    if state.fatal_error.is_some()
        || state.interceptor.state == ComponentState::Failed
        || state.api.state == ComponentState::Failed
        || state
            .listeners
            .values()
            .any(|listener| listener.state == ComponentState::Failed)
    {
        return HealthStatus::Error;
    }

    if !state.startup_complete
        || state.interceptor.state == ComponentState::Starting
        || state.api.state == ComponentState::Starting
        || state
            .listeners
            .values()
            .any(|listener| listener.state == ComponentState::Starting)
    {
        return HealthStatus::Starting;
    }

    if state.listeners.is_empty() && !state.allow_zero_listeners {
        return HealthStatus::Degraded;
    }

    if state
        .listeners
        .values()
        .any(|listener| listener.state != ComponentState::Running)
    {
        return HealthStatus::Degraded;
    }

    if state.distributed_export.state == ComponentState::Degraded {
        return HealthStatus::Degraded;
    }

    if state.nbi_pipeline.state == ComponentState::Degraded {
        return HealthStatus::Degraded;
    }

    if matches!(
        state.interceptor.state,
        ComponentState::Disabled | ComponentState::Running
    ) && matches!(
        state.api.state,
        ComponentState::Disabled | ComponentState::Running
    ) && matches!(
        state.distributed_export.state,
        ComponentState::Disabled | ComponentState::Running | ComponentState::Starting
    ) && matches!(
        state.nbi_pipeline.state,
        ComponentState::Disabled | ComponentState::Running
    ) {
        return HealthStatus::Ok;
    }

    HealthStatus::Degraded
}

#[cfg(test)]
mod tests {
    use super::{ComponentState, HealthStatus, NbiCollectorHealth, RuntimeHealth};

    #[test]
    fn startup_complete_without_listeners_is_degraded() {
        let runtime_health = RuntimeHealth::new();
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        runtime_health.set_distributed_export_disabled();

        let snapshot = runtime_health.snapshot();

        assert_eq!(snapshot.status, HealthStatus::Degraded);
    }

    #[test]
    fn startup_complete_without_listeners_is_ok_in_api_only_mode() {
        let runtime_health = RuntimeHealth::new();
        runtime_health.set_allow_zero_listeners(true);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_running();
        runtime_health.set_interceptor_disabled();
        runtime_health.set_distributed_export_disabled();

        let snapshot = runtime_health.snapshot();

        assert_eq!(snapshot.status, HealthStatus::Ok);
    }

    #[test]
    fn startup_complete_with_running_listener_is_ok() {
        let runtime_health = RuntimeHealth::new();
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        runtime_health.set_distributed_export_disabled();

        let snapshot = runtime_health.snapshot();

        assert_eq!(snapshot.status, HealthStatus::Ok);
    }

    #[test]
    fn degraded_distributed_export_keeps_runtime_degraded() {
        let runtime_health = RuntimeHealth::new();
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        runtime_health.set_distributed_export_degraded("sink unavailable");

        let snapshot = runtime_health.snapshot();

        assert_eq!(snapshot.status, HealthStatus::Degraded);
        assert_eq!(snapshot.distributed_export.state, ComponentState::Degraded);
        assert_eq!(
            snapshot.distributed_export.error.as_deref(),
            Some("sink unavailable")
        );
    }

    #[test]
    fn starting_distributed_export_does_not_block_ready_runtime() {
        let runtime_health = RuntimeHealth::new();
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        runtime_health.set_distributed_export_starting();
        runtime_health.set_nbi_pipeline_running();

        let snapshot = runtime_health.snapshot();

        assert_eq!(snapshot.status, HealthStatus::Ok);
        assert_eq!(snapshot.distributed_export.state, ComponentState::Starting);
    }

    #[test]
    fn degraded_nbi_pipeline_keeps_runtime_degraded() {
        let runtime_health = RuntimeHealth::new();
        runtime_health.register_listener("http", "tcp", 80);
        runtime_health.mark_listener_running("http", 80);
        runtime_health.mark_startup_complete();
        runtime_health.set_api_disabled();
        runtime_health.set_interceptor_disabled();
        runtime_health.set_distributed_export_disabled();
        runtime_health.set_nbi_pipeline_degraded("local queue full");

        let snapshot = runtime_health.snapshot();

        assert_eq!(snapshot.status, HealthStatus::Degraded);
        assert_eq!(snapshot.nbi_pipeline.state, ComponentState::Degraded);
        assert_eq!(
            snapshot.nbi_pipeline.error.as_deref(),
            Some("local queue full")
        );
    }

    #[test]
    fn distributed_export_loss_is_latched_across_running_updates() {
        let runtime_health = RuntimeHealth::new();
        runtime_health.set_distributed_export_loss("export queue full");
        runtime_health.set_distributed_export_running();

        let snapshot = runtime_health.snapshot();

        assert_eq!(snapshot.distributed_export.state, ComponentState::Degraded);
        assert_eq!(
            snapshot.distributed_export.error.as_deref(),
            Some("export queue full")
        );
    }

    #[test]
    fn distributed_export_loss_is_latched_across_disabled_updates() {
        let runtime_health = RuntimeHealth::new();
        runtime_health.set_distributed_export_loss("export queue full");
        runtime_health.set_distributed_export_disabled();

        let snapshot = runtime_health.snapshot();

        assert_eq!(snapshot.distributed_export.state, ComponentState::Degraded);
        assert_eq!(
            snapshot.distributed_export.error.as_deref(),
            Some("export queue full")
        );
    }

    #[test]
    fn distributed_export_rejections_remain_degraded_across_running_and_disabled_updates() {
        let runtime_health = RuntimeHealth::new();
        runtime_health.update_nbi_collector(NbiCollectorHealth {
            export_rejected: 1,
            last_worker_error: Some(
                "distributed export rejected event before fanout acceptance: queue full"
                    .to_string(),
            ),
            ..Default::default()
        });

        runtime_health.set_distributed_export_running();
        let running_snapshot = runtime_health.snapshot();
        assert_eq!(
            running_snapshot.distributed_export.state,
            ComponentState::Degraded
        );
        assert!(
            running_snapshot
                .distributed_export
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("distributed export rejected")
        );

        runtime_health.set_distributed_export_disabled();
        let disabled_snapshot = runtime_health.snapshot();
        assert_eq!(
            disabled_snapshot.distributed_export.state,
            ComponentState::Degraded
        );
        assert!(
            disabled_snapshot
                .distributed_export
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("distributed export rejected")
        );
    }

    #[test]
    fn nbi_pipeline_loss_is_latched_across_running_updates() {
        let runtime_health = RuntimeHealth::new();
        runtime_health.set_nbi_pipeline_loss("local persistence failed");
        runtime_health.set_nbi_pipeline_running();

        let snapshot = runtime_health.snapshot();

        assert_eq!(snapshot.nbi_pipeline.state, ComponentState::Degraded);
        assert_eq!(
            snapshot.nbi_pipeline.error.as_deref(),
            Some("local persistence failed")
        );
    }
}
