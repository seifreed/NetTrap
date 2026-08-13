use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::send_fatal_runtime_error;

pub(super) async fn start_api_server(
    bind: &str,
    flow_manager: Arc<nettrap_flow::FlowManager>,
    runtime_health: Arc<nettrap_engine::RuntimeHealth>,
    fatal_runtime_tx: mpsc::UnboundedSender<String>,
    background_tasks: &mut Vec<JoinHandle<()>>,
) -> crate::Result<()> {
    let addr = canonicalize_socket_addr_bind(bind)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let router = nettrap_api::create_router(nettrap_api::ApiState::with_runtime_health(
        flow_manager,
        Arc::clone(&runtime_health),
    ));

    tracing::info!("REST API listening on {}", local_addr);
    runtime_health.set_api_running();

    background_tasks.push(tokio::spawn(async move {
        report_api_server_exit(
            nettrap_api::serve(listener, router).await,
            Arc::clone(&runtime_health),
            fatal_runtime_tx,
        );
    }));

    Ok(())
}

pub(super) fn canonicalize_socket_addr_bind(bind: &str) -> crate::Result<std::net::SocketAddr> {
    let addr = bind
        .parse::<std::net::SocketAddr>()
        .map_err(|e| crate::Error::Config(format!("Invalid api_bind '{}': {}", bind, e)))?;

    Ok(match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            std::net::SocketAddr::new(std::net::IpAddr::V4(ip), addr.port())
        }
        std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(addr, |mapped| {
            std::net::SocketAddr::new(std::net::IpAddr::V4(mapped), addr.port())
        }),
    })
}

pub(super) fn report_api_server_exit(
    result: std::result::Result<(), nettrap_core::Error>,
    runtime_health: Arc<nettrap_engine::RuntimeHealth>,
    fatal_runtime_tx: mpsc::UnboundedSender<String>,
) {
    match result {
        Ok(()) => {
            let message = "API server exited unexpectedly".to_string();
            runtime_health.set_api_failed(message.clone());
            send_fatal_runtime_error(&fatal_runtime_tx, message.clone());
            tracing::warn!("{}", message);
        }
        Err(err) => {
            runtime_health.set_api_failed(err.to_string());
            send_fatal_runtime_error(&fatal_runtime_tx, format!("API server failed: {}", err));
            tracing::warn!("API server exited with error: {}", err);
        }
    }
}
