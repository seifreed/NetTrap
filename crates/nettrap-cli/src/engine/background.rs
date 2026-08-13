use std::sync::Arc;

use crate::config::EngineConfig;

pub fn init_distributed(
    config: &EngineConfig,
    node_identity: &Arc<crate::distributed::NodeIdentity>,
    runtime_health: &Arc<nettrap_engine::RuntimeHealth>,
    fatal_runtime_tx: tokio::sync::mpsc::UnboundedSender<String>,
    bg_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> crate::Result<()> {
    if !config.distributed.enabled {
        if config.distributed.health_bind.is_some()
            || config.distributed.metrics_bind.is_some()
            || config.distributed.control_plane_url.is_some()
            || !config.distributed.event_sinks.is_empty()
            || config.distributed.heartbeat_interval_secs > 0
        {
            tracing::warn!(
                "Distributed config is present but distributed.enabled=false; health, metrics, heartbeat, and event sinks remain disabled"
            );
        }
        return Ok(());
    }

    tracing::info!(
        "Distributed mode enabled — node_id: {}",
        node_identity.node_id
    );

    if config.distributed.heartbeat_interval_secs > 0
        && config.distributed.control_plane_url.is_none()
    {
        return Err(crate::Error::Config(
            "distributed.heartbeat_interval_secs requires distributed.control_plane_url"
                .to_string(),
        ));
    }

    if let Some(ref health_bind) = config.distributed.health_bind {
        let (listener, local_addr) = crate::distributed::bind_health_server(health_bind)?;
        tracing::info!("health/readiness server on {}", local_addr);
        let bind = health_bind.clone();
        let node = Arc::clone(node_identity);
        let runtime_health = Arc::clone(runtime_health);
        let fatal_runtime_tx = fatal_runtime_tx.clone();
        bg_tasks.push(tokio::spawn(async move {
            report_background_service_exit(
                "Health/readiness server",
                format!("Health/readiness server failed on {}: ", bind),
                crate::distributed::serve_health_server(listener, node, runtime_health.clone())
                    .await,
                Arc::clone(&runtime_health),
                fatal_runtime_tx,
            );
        }));
    }

    if let Some(ref metrics_bind) = config.distributed.metrics_bind {
        let (listener, local_addr) = crate::distributed::bind_metrics_server(metrics_bind)?;
        tracing::info!("metrics server on {}", local_addr);
        let bind = metrics_bind.clone();
        let node = Arc::clone(node_identity);
        let runtime_health = Arc::clone(runtime_health);
        let fatal_runtime_tx = fatal_runtime_tx.clone();
        bg_tasks.push(tokio::spawn(async move {
            report_background_service_exit(
                "Metrics server",
                format!("Metrics server failed on {}: ", bind),
                crate::distributed::serve_metrics_server(listener, node, runtime_health.clone())
                    .await,
                Arc::clone(&runtime_health),
                fatal_runtime_tx,
            );
        }));
    }

    if let Some(ref control_url) = config.distributed.control_plane_url {
        let url = control_url.clone();
        let token = config.distributed.control_plane_token.clone();
        let node = Arc::clone(node_identity);
        let interval = config.distributed.heartbeat_interval_secs;
        if interval > 0 {
            let runtime_health = Arc::clone(runtime_health);
            let fatal_runtime_tx = fatal_runtime_tx.clone();
            bg_tasks.push(tokio::spawn(async move {
                report_background_service_exit(
                    "Control plane heartbeat",
                    "Control plane heartbeat failed: ".to_string(),
                    crate::distributed::run_heartbeat_with_now(
                        url,
                        token,
                        node,
                        interval,
                        crate::faketime::fake_now,
                    )
                    .await,
                    Arc::clone(&runtime_health),
                    fatal_runtime_tx,
                );
            }));
        }
    }

    Ok(())
}

pub fn init_faketime(
    config: &EngineConfig,
    runtime_health: Arc<nettrap_engine::RuntimeHealth>,
    fatal_runtime_tx: tokio::sync::mpsc::UnboundedSender<String>,
    bg_tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    if !config.faketime.enabled {
        return;
    }

    crate::faketime::set_delta(config.faketime.init_delta);
    tracing::info!(
        "FakeTime mode enabled — initial delta: {} seconds",
        config.faketime.init_delta
    );
    if config.faketime.auto_delay_secs == 0 || config.faketime.auto_increment_secs == 0 {
        return;
    }

    let ft_config = config.faketime.clone();
    bg_tasks.push(tokio::spawn(async move {
        crate::faketime::run_auto_increment(ft_config).await;
        report_unexpected_task_completion(
            "FakeTime auto-increment",
            Arc::clone(&runtime_health),
            fatal_runtime_tx,
        );
    }));
}

pub(crate) fn report_background_service_exit<E>(
    service_name: &str,
    prefix: String,
    result: std::result::Result<(), E>,
    runtime_health: Arc<nettrap_engine::RuntimeHealth>,
    fatal_runtime_tx: tokio::sync::mpsc::UnboundedSender<String>,
) where
    E: std::fmt::Display,
{
    match result {
        Ok(()) => {
            report_unexpected_task_completion(service_name, runtime_health, fatal_runtime_tx);
        }
        Err(err) => {
            let message = format!("{}{}", prefix, err);
            runtime_health.set_fatal_error(message.clone());
            crate::engine::send_fatal_runtime_error(&fatal_runtime_tx, message.clone());
            tracing::warn!("{}", message);
        }
    }
}

fn report_unexpected_task_completion(
    task_name: &str,
    runtime_health: Arc<nettrap_engine::RuntimeHealth>,
    fatal_runtime_tx: tokio::sync::mpsc::UnboundedSender<String>,
) {
    let message = format!("{} exited unexpectedly", task_name);
    runtime_health.set_fatal_error(message.clone());
    crate::engine::send_fatal_runtime_error(&fatal_runtime_tx, message.clone());
    tracing::warn!("{}", message);
}
