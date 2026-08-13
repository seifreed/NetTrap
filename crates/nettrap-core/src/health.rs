use serde::Serialize;
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Starting,
    Ok,
    Degraded,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    Disabled,
    Starting,
    Running,
    Degraded,
    Failed,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListenerHealth {
    pub name: String,
    pub protocol: String,
    pub port: u16,
    pub state: ComponentState,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentHealth {
    pub state: ComponentState,
    pub error: Option<String>,
}

impl Default for ComponentHealth {
    fn default() -> Self {
        Self {
            state: ComponentState::Disabled,
            error: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NbiCollectorHealth {
    pub local_dropped: u64,
    pub export_dropped: u64,
    pub export_rejected: u64,
    pub export_unknown: u64,
    pub local_persist_failures: u64,
    pub worker_restarts: u64,
    pub last_worker_error: Option<String>,
    pub last_local_persist_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeHealthSnapshot {
    pub status: HealthStatus,
    pub startup_complete: bool,
    pub fatal_error: Option<String>,
    pub listeners: Vec<ListenerHealth>,
    pub interceptor: ComponentHealth,
    pub api: ComponentHealth,
    pub distributed_export: ComponentHealth,
    pub nbi_pipeline: ComponentHealth,
    pub nbi_collector: NbiCollectorHealth,
}

/// Behavior-layer view of runtime health reporting.
///
/// Captures exactly the `RuntimeHealth` methods the business layer
/// (`NbiCollector`, `EventFanout`/sinks, NBI worker) invokes, so those
/// components can depend on this abstraction instead of the concrete
/// `nettrap_engine::RuntimeHealth`. Object-safe by construction: no generic
/// method parameters, no `impl Trait` arguments, no by-value `Self`, and
/// only `nettrap_core` value types in signatures.
pub trait HealthSink: Send + Sync {
    fn snapshot(&self) -> RuntimeHealthSnapshot;

    fn distributed_export_loss_latched(&self) -> bool;

    fn set_distributed_export_running(&self);

    fn set_distributed_export_disabled(&self);

    fn set_distributed_export_degraded(&self, error: &str);

    fn set_distributed_export_loss(&self, error: &str);

    fn set_nbi_pipeline_running(&self);

    fn set_nbi_pipeline_disabled(&self);

    fn set_nbi_pipeline_degraded(&self, error: &str);

    fn set_nbi_pipeline_loss(&self, error: &str);

    fn update_nbi_collector(&self, snapshot: NbiCollectorHealth);
}

pub fn runtime_health_payload(snapshot: &RuntimeHealthSnapshot) -> serde_json::Value {
    json!({
        "status": snapshot.status,
        "version": env!("CARGO_PKG_VERSION"),
        "startup_complete": snapshot.startup_complete,
        "fatal_error": snapshot.fatal_error,
        "listeners": snapshot.listeners,
        "interceptor": snapshot.interceptor,
        "api": snapshot.api,
        "distributed_export": snapshot.distributed_export,
        "nbi_pipeline": snapshot.nbi_pipeline,
        "nbi_collector": snapshot.nbi_collector,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_health_payload_uses_the_package_version() {
        let snapshot = RuntimeHealthSnapshot {
            status: HealthStatus::Ok,
            startup_complete: true,
            fatal_error: None,
            listeners: Vec::new(),
            interceptor: ComponentHealth::default(),
            api: ComponentHealth::default(),
            distributed_export: ComponentHealth::default(),
            nbi_pipeline: ComponentHealth::default(),
            nbi_collector: NbiCollectorHealth::default(),
        };

        let payload = runtime_health_payload(&snapshot);

        assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));
    }
}
