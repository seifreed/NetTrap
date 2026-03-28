use axum::{
    Router,
    routing::get,
    response::Json,
    extract::State,
};
use std::sync::Arc;

use nettrap_flow::Flow;

pub struct ApiState {
    pub flows: parking_lot::RwLock<Vec<Flow>>,
}

pub fn create_router(state: ApiState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/api/flows", get(flows_handler))
        .route("/api/stats", get(stats_handler))
        .with_state(Arc::new(state))
}

pub async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": "0.1.0"
    }))
}

pub async fn flows_handler(
    State(state): State<Arc<ApiState>>
) -> Json<serde_json::Value> {
    let flows = state.flows.read();
    Json(serde_json::json!({
        "flows": flows.iter().map(|f| {
            serde_json::json!({
                "id": f.id.to_string(),
                "src": format!("{}:{}", f.five_tuple.src_ip, f.five_tuple.src_port),
                "dst": format!("{}:{}", f.five_tuple.dst_ip, f.five_tuple.dst_port),
                "protocol": format!("{:?}", f.five_tuple.protocol),
                "bytes_sent": f.metadata.bytes_sent,
                "bytes_received": f.metadata.bytes_received,
            })
        }).collect::<Vec<_>>()
    }))
}

pub async fn stats_handler(
    State(state): State<Arc<ApiState>>
) -> Json<serde_json::Value> {
    let flows = state.flows.read();
    Json(serde_json::json!({
        "total_flows": flows.len(),
        "total_bytes": flows.iter().map(|f| f.metadata.bytes_sent + f.metadata.bytes_received).sum::<u64>(),
    }))
}