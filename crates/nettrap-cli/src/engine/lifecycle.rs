use std::path::Path;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::EngineConfig;
use crate::engine::interceptor::RunningInterceptor;
use crate::engine::shutdown::{ShutdownContext, execute_shutdown};
use crate::engine::startup::StartupContext;
use nettrap_fsutil::ensure_no_symlink_ancestors;

async fn shutdown_listener_tasks(handles: Vec<JoinHandle<crate::Result<()>>>) {
    for handle in &handles {
        if !handle.is_finished() {
            handle.abort();
        }
    }

    for handle in handles {
        match handle.await {
            Ok(Err(err)) => {
                tracing::warn!("Listener task had error: {}", err);
            }
            Err(err) if !err.is_cancelled() => {
                tracing::warn!("Listener task panicked: {}", err);
            }
            _ => {}
        }
    }
}

async fn stop_runtime_tasks(
    startup: &mut StartupContext,
    listener_handles: Vec<JoinHandle<crate::Result<()>>>,
    interceptor: Option<RunningInterceptor>,
) -> Option<crate::Error> {
    shutdown_listener_tasks(listener_handles).await;

    let interceptor_shutdown_error = if let Some(interceptor) = interceptor {
        interceptor.shutdown().await.err()
    } else {
        None
    };

    if let Some(task) = startup.session_cleanup_task.take() {
        task.abort();
        if let Some(message) = report_task_exit("session cleanup task", task).await {
            tracing::warn!("{}", message);
        }
    }

    for task in &startup.background_tasks {
        task.abort();
    }
    for task in startup.background_tasks.drain(..) {
        if let Some(message) = report_task_exit("background task", task).await {
            tracing::warn!("{}", message);
        }
    }

    interceptor_shutdown_error
}

async fn report_task_exit(task_name: &str, task: JoinHandle<()>) -> Option<String> {
    match task.await {
        Ok(()) => Some(format!("{} exited unexpectedly during shutdown", task_name)),
        Err(err) if err.is_cancelled() => None,
        Err(err) => Some(format!("{} panicked during shutdown: {}", task_name, err)),
    }
}

pub(super) async fn shutdown_runtime(
    startup: &mut StartupContext,
    config: &EngineConfig,
    listener_handles: Vec<JoinHandle<crate::Result<()>>>,
    interceptor: Option<RunningInterceptor>,
) -> Option<crate::Error> {
    let interceptor_shutdown_error =
        stop_runtime_tasks(startup, listener_handles, interceptor).await;

    let mut shutdown_ctx = ShutdownContext::new(
        startup.output_path.clone(),
        startup.nbi_path.clone(),
        startup.pcap_writer.clone(),
        startup.database.clone(),
        Some(Arc::clone(&startup.nbi_collector)),
        startup.database_node_id.clone(),
        Some(startup.run_id.clone()),
    );
    shutdown_ctx.windows_ca_trust_thumbprint = startup.windows_ca_trust_thumbprint.clone();
    execute_shutdown(&shutdown_ctx, config).await;

    interceptor_shutdown_error
}

pub(super) async fn shutdown_and_return(
    startup: &mut StartupContext,
    config: &EngineConfig,
    listener_handles: Vec<JoinHandle<crate::Result<()>>>,
    interceptor: Option<RunningInterceptor>,
    error: crate::Error,
    context: &str,
) -> crate::Result<()> {
    if let Some(shutdown_err) =
        shutdown_runtime(startup, config, listener_handles, interceptor).await
    {
        tracing::warn!(
            "Runtime shutdown reported an additional error after {}: {}",
            context,
            shutdown_err
        );
    }
    Err(error)
}

pub(super) use nettrap_engine::ShutdownReason;

pub(super) async fn wait_for_shutdown(
    stop_flag: Option<std::path::PathBuf>,
    fatal_runtime_rx: &mut mpsc::UnboundedReceiver<String>,
) -> ShutdownReason {
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if result.is_ok() {
                tracing::info!("Received Ctrl+C, shutting down...");
            }
            ShutdownReason::Signal
        }
        _ = wait_for_terminate() => {
            tracing::info!("Received SIGTERM, shutting down...");
            ShutdownReason::Signal
        }
        _ = watch_stop_flag(stop_flag) => {
            tracing::info!("Stop flag detected, shutting down...");
            ShutdownReason::StopFlag
        }
        fatal = fatal_runtime_rx.recv() => {
            let message = fatal.unwrap_or_else(|| "runtime component failed".to_string());
            tracing::warn!("Fatal runtime error: {}", message);
            ShutdownReason::Fatal(message)
        }
    }
}

/// Resolve when the process receives SIGTERM (the signal `docker stop`,
/// `systemctl stop`, and `kill <pid>` send by default). Without this, the
/// default SIGTERM action terminates the process abruptly and skips the
/// graceful drain (NBI flush, report export, database/pcap close). On
/// non-Unix platforms there is no SIGTERM, so this stays pending forever and
/// the other `select!` arms drive shutdown.
async fn wait_for_terminate() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                term.recv().await;
            }
            Err(err) => {
                tracing::warn!("Failed to install SIGTERM handler: {}", err);
                std::future::pending::<()>().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        std::future::pending::<()>().await;
    }
}

async fn watch_stop_flag(path: Option<std::path::PathBuf>) {
    match path {
        Some(p) => loop {
            if stop_flag_present(&p) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        },
        None => {
            std::future::pending::<()>().await;
        }
    }
}

fn stop_flag_present(path: &Path) -> bool {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        && ensure_no_symlink_ancestors(parent).is_err()
    {
        return false;
    }

    match path.symlink_metadata() {
        Ok(metadata) => metadata.is_file(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::report_task_exit;
    #[cfg(unix)]
    use super::stop_flag_present;
    #[cfg(unix)]
    use std::path::Path;
    use tokio::task::JoinHandle;

    async fn report_task_exit_result(task: JoinHandle<()>) -> Option<String> {
        match task.await {
            Ok(()) => None,
            Err(err) if err.is_cancelled() => None,
            Err(err) => Some(err.to_string()),
        }
    }

    #[cfg(unix)]
    #[test]
    fn stop_flag_present_rejects_final_symlink() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-stop-flag-symlink-{}",
            uuid::Uuid::new_v4()
        ));
        let real = root.join("real.flag");
        let link = root.join("flag");
        std::fs::create_dir_all(&root).expect("create temp root");
        std::fs::write(&real, b"stop").expect("create real flag");
        std::os::unix::fs::symlink(&real, &link).expect("create symlink");

        assert!(!stop_flag_present(Path::new(&link)));
        assert!(stop_flag_present(Path::new(&real)));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn stop_flag_present_rejects_symlinked_parent_directory() {
        let root = std::env::temp_dir().join(format!(
            "nettrap-stop-flag-parent-symlink-{}",
            uuid::Uuid::new_v4()
        ));
        let real_parent = root.join("real");
        let link_parent = root.join("linked");
        std::fs::create_dir_all(&real_parent).expect("create real parent");
        std::fs::write(real_parent.join("stop.flag"), b"stop").expect("create stop flag");
        std::os::unix::fs::symlink(&real_parent, &link_parent).expect("create symlink parent");

        assert!(!stop_flag_present(&link_parent.join("stop.flag")));

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn report_task_exit_result_surfaces_panics_from_join_handle() {
        let task = tokio::spawn(async {
            panic!("background task panic");
        });

        let err = report_task_exit_result(task)
            .await
            .expect("panic should be reported");

        assert!(err.contains("background task panic"));
    }

    #[tokio::test]
    async fn report_task_exit_reports_clean_completion_as_unexpected() {
        let task = tokio::spawn(async {});

        let message = report_task_exit("background task", task)
            .await
            .expect("clean completion should be reported");

        assert_eq!(
            message,
            "background task exited unexpectedly during shutdown"
        );
    }
}
