use axum::{Router, extract::State, response::Json, routing::get};
use std::sync::Arc;

use nettrap_flow::FlowManager;

use crate::health::RuntimeHealth;

pub struct ApiState {
    pub flow_manager: Arc<FlowManager>,
    pub runtime_health: Arc<RuntimeHealth>,
}

impl ApiState {
    pub fn new(flow_manager: Arc<FlowManager>) -> Self {
        let runtime_health = Arc::new(RuntimeHealth::new());
        runtime_health.set_allow_zero_listeners(true);
        Self::with_runtime_health(flow_manager, runtime_health)
    }

    pub fn with_runtime_health(
        flow_manager: Arc<FlowManager>,
        runtime_health: Arc<RuntimeHealth>,
    ) -> Self {
        Self {
            flow_manager,
            runtime_health,
        }
    }
}

pub fn create_router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/api/flows", get(flows_handler))
        .route("/api/stats", get(stats_handler))
        .with_state(Arc::new(state))
}

pub async fn health_handler(State(state): State<Arc<ApiState>>) -> Json<serde_json::Value> {
    let health = state.runtime_health.snapshot();
    Json(crate::runtime_health_payload(&health))
}

pub async fn flows_handler(State(state): State<Arc<ApiState>>) -> Json<serde_json::Value> {
    let flows: Vec<_> = state.flow_manager.iter().collect();
    Json(serde_json::json!({
        "flows": flows.iter().map(|f| {
            serde_json::json!({
                "id": f.id.to_string(),
                "src": endpoint_text(f.five_tuple.src_ip, f.five_tuple.src_port),
                "dst": endpoint_text(f.five_tuple.dst_ip, f.five_tuple.dst_port),
                "protocol": format!("{:?}", f.five_tuple.protocol),
                "bytes_sent": f.metadata.bytes_sent,
                "bytes_received": f.metadata.bytes_received,
            })
        }).collect::<Vec<_>>()
    }))
}

fn endpoint_text(ip: std::net::IpAddr, port: u16) -> String {
    std::net::SocketAddr::new(ip, port).to_string()
}

pub async fn stats_handler(State(state): State<Arc<ApiState>>) -> Json<serde_json::Value> {
    let flows: Vec<_> = state.flow_manager.iter().collect();
    let total_bytes = flows.iter().fold(0u64, |total, flow| {
        total.saturating_add(
            flow.metadata
                .bytes_sent
                .saturating_add(flow.metadata.bytes_received),
        )
    });
    Json(serde_json::json!({
        "total_flows": state.flow_manager.active_count(),
        "total_bytes": total_bytes,
    }))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use super::*;
    use nettrap_core::prelude::{FiveTuple, Protocol};

    fn test_state() -> (Arc<ApiState>, Arc<FlowManager>, Arc<RuntimeHealth>) {
        let manager = Arc::new(FlowManager::default());
        let runtime_health = Arc::new(RuntimeHealth::new());
        let state = Arc::new(ApiState::with_runtime_health(
            Arc::clone(&manager),
            Arc::clone(&runtime_health),
        ));
        (state, manager, runtime_health)
    }

    fn insert_flow(
        manager: &Arc<FlowManager>,
        src_port: u16,
        dst_port: u16,
        sent: u64,
        received: u64,
    ) {
        insert_flow_with_ips(
            manager,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            src_port,
            dst_port,
            sent,
            received,
        );
    }

    fn insert_flow_with_ips(
        manager: &Arc<FlowManager>,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        sent: u64,
        received: u64,
    ) {
        let flow = manager.get_or_create(FiveTuple::new(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            Protocol::Tcp,
        ));
        manager
            .update(&flow.key(), |flow| {
                flow.metadata.bytes_sent = sent;
                flow.metadata.bytes_received = received;
            })
            .expect("flow should exist");
    }

    #[tokio::test]
    async fn flows_handler_reads_live_flow_manager_state() {
        let (state, manager, _) = test_state();

        insert_flow(&manager, 53000, 443, 128, 256);

        let response = flows_handler(State(state)).await.0;
        let flows = response["flows"].as_array().expect("flows array");

        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0]["src"], "192.168.1.10:53000");
        assert_eq!(flows[0]["dst"], "10.0.0.5:443");
        assert_eq!(flows[0]["bytes_sent"], 128);
        assert_eq!(flows[0]["bytes_received"], 256);
    }

    #[tokio::test]
    async fn flows_handler_brackets_ipv6_endpoints() {
        let (state, manager, _) = test_state();

        insert_flow_with_ips(
            &manager,
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            53000,
            443,
            1,
            2,
        );

        let response = flows_handler(State(state)).await.0;
        let flows = response["flows"].as_array().expect("flows array");

        assert_eq!(flows[0]["src"], "[::1]:53000");
        assert_eq!(flows[0]["dst"], "[::]:443");
    }

    #[tokio::test]
    async fn stats_handler_reflects_flows_added_after_state_creation() {
        let (state, manager, _) = test_state();

        insert_flow(&manager, 53001, 80, 10, 20);
        insert_flow(&manager, 53002, 53, 30, 40);

        let response = stats_handler(State(state)).await.0;

        assert_eq!(response["total_flows"], 2);
        assert_eq!(response["total_bytes"], 100);
    }

    #[tokio::test]
    async fn stats_handler_saturates_total_bytes_on_overflow() {
        let (state, manager, _) = test_state();

        insert_flow(&manager, 53001, 80, u64::MAX, 1);
        insert_flow(&manager, 53002, 443, 1, 1);

        let response = stats_handler(State(state)).await.0;

        assert_eq!(response["total_flows"], 2);
        assert_eq!(response["total_bytes"], u64::MAX);
    }

    #[tokio::test]
    async fn health_handler_reports_listener_failure() {
        let (state, _, runtime_health) = test_state();
        runtime_health.register_listener("dns", "udp", 53);
        runtime_health.mark_listener_failed("dns", "bind failed");

        let response = health_handler(State(state)).await.0;

        assert_eq!(response["status"], "error");
        assert_eq!(response["fatal_error"], "bind failed");
        assert_eq!(response["listeners"][0]["state"], "failed");
    }

    #[tokio::test]
    async fn api_state_new_treats_zero_listener_runtime_as_api_only() {
        let state = Arc::new(ApiState::new(Arc::new(FlowManager::default())));
        state.runtime_health.mark_startup_complete();
        state.runtime_health.set_api_running();
        state.runtime_health.set_interceptor_disabled();
        state.runtime_health.set_distributed_export_disabled();

        let response = health_handler(State(state)).await.0;

        assert_eq!(response["status"], "ok");
    }
}
