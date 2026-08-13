use std::sync::Arc;

pub(super) fn start_runtime_cleanup_task(
    session_tracker: Arc<crate::session::SessionTracker>,
    port_forward_table: Arc<crate::session::PortForwardTable>,
    flow_manager: Arc<nettrap_flow::FlowManager>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(session_tracker.cleanup_interval()).await;
            let expired_sessions = session_tracker.cleanup_expired_sessions();
            for session in expired_sessions {
                if let Some(five_tuple) = session.to_five_tuple() {
                    flow_manager.remove(&nettrap_core::prelude::FlowKey::from_five_tuple(
                        &five_tuple,
                    ));
                }
            }
            port_forward_table.purge_stale_destinations(session_tracker.ttl());
            tracing::debug!(
                "Session cleanup completed, active sessions: {}",
                session_tracker.active_count()
            );
        }
    })
}
