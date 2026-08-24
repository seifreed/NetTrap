use std::sync::{Arc, OnceLock};
use tokio::sync::Semaphore;

const MAX_CONCURRENT_ATTRIBUTION_TASKS: usize = 64;

pub(crate) fn attribution_semaphore() -> Arc<Semaphore> {
    static SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();
    Arc::clone(SEMAPHORE.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_ATTRIBUTION_TASKS))))
}

pub(crate) mod tcp_dispatch;
pub(crate) mod tcp_framing;
mod tcp_ftp;
pub mod tcp_handler;
pub mod tcp_listener;
pub(crate) mod tcp_response;
pub mod udp_listener;
pub(crate) mod udp_tftp;

pub use tcp_handler::{
    build_tls_response, handle_smtp_data, handle_tcp_connection, handle_wrapped_connection,
};
pub use tcp_listener::run_tcp_listener;
pub(crate) use tcp_listener::run_tcp_listener_with_policy;
pub use udp_listener::run_udp_listener;
pub(crate) use udp_listener::run_udp_listener_with_policy;
