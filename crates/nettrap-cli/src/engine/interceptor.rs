use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::config::EngineConfig;

type SharedInterceptor = Arc<Mutex<Box<dyn nettrap_interceptor::Interceptor>>>;

#[cfg(any(target_os = "windows", target_os = "linux"))]
use tokio::sync::oneshot;

pub struct RunningInterceptor {
    interceptor: SharedInterceptor,
    handle: JoinHandle<crate::Result<()>>,
}

impl RunningInterceptor {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    fn new(interceptor: SharedInterceptor, handle: JoinHandle<crate::Result<()>>) -> Self {
        Self {
            interceptor,
            handle,
        }
    }

    pub async fn shutdown(self) -> crate::Result<()> {
        self.handle.abort();

        match self.handle.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::warn!(
                "Interceptor task exited with error before shutdown: {}",
                err
            ),
            Err(err) if err.is_cancelled() => {}
            Err(err) => tracing::warn!("Failed to join interceptor task during shutdown: {}", err),
        }

        let mut interceptor = self.interceptor.lock().await;
        if !interceptor.is_running() {
            return Ok(());
        }

        let name = interceptor.name();
        interceptor.shutdown().await.map_err(|e| {
            crate::Error::Other(format!("Failed to shutdown interceptor '{}': {}", name, e))
        })
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
struct PreparedInterceptor {
    interceptor: SharedInterceptor,
    active_message: &'static str,
    port_forward_table: Option<Arc<crate::session::PortForwardTable>>,
}

pub async fn spawn_interceptor(
    config: &EngineConfig,
    interface: Option<String>,
    output_override: Option<PathBuf>,
    port_forward_table: Arc<crate::session::PortForwardTable>,
    runtime_health: Arc<nettrap_api::RuntimeHealth>,
    fatal_runtime_tx: tokio::sync::mpsc::UnboundedSender<String>,
) -> crate::Result<Option<RunningInterceptor>> {
    let output_path = output_override
        .clone()
        .or_else(|| config.output_path.clone().map(PathBuf::from));

    #[cfg(target_os = "windows")]
    {
        let Some(prepared) = build_windows_interceptor(interface, port_forward_table)? else {
            return Ok(None);
        };

        let (startup_tx, startup_rx) = oneshot::channel();
        let handle = spawn_interceptor_task(
            Arc::clone(&prepared.interceptor),
            output_path,
            prepared.active_message,
            prepared.port_forward_table,
            startup_tx,
            runtime_health,
            fatal_runtime_tx,
        );

        match startup_rx.await {
            Ok(Ok(())) => Ok(Some(RunningInterceptor::new(prepared.interceptor, handle))),
            Ok(Err(err)) => {
                let _ = handle.await;
                Err(err)
            }
            Err(_) => {
                let _ = handle.await;
                Err(crate::Error::Other(
                    "Interceptor startup channel closed unexpectedly".to_string(),
                ))
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let Some(prepared) = build_linux_interceptor(config, port_forward_table)? else {
            return Ok(None);
        };

        let (startup_tx, startup_rx) = oneshot::channel();
        let handle = spawn_interceptor_task(
            Arc::clone(&prepared.interceptor),
            output_path,
            prepared.active_message,
            prepared.port_forward_table,
            startup_tx,
            runtime_health,
            fatal_runtime_tx,
        );

        match startup_rx.await {
            Ok(Ok(())) => Ok(Some(RunningInterceptor::new(prepared.interceptor, handle))),
            Ok(Err(err)) => {
                let _ = handle.await;
                Err(err)
            }
            Err(_) => {
                let _ = handle.await;
                Err(crate::Error::Other(
                    "Interceptor startup channel closed unexpectedly".to_string(),
                ))
            }
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = (
            interface,
            output_path,
            port_forward_table,
            runtime_health,
            fatal_runtime_tx,
        );
        tracing::warn!("`--intercept` requires Windows (WinDivert) or Linux (NFQUEUE)");
        Ok(None)
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn spawn_interceptor_task(
    interceptor: SharedInterceptor,
    output_path: Option<PathBuf>,
    active_message: &'static str,
    port_forward_table: Option<Arc<crate::session::PortForwardTable>>,
    startup_tx: oneshot::Sender<crate::Result<()>>,
    runtime_health: Arc<nettrap_api::RuntimeHealth>,
    fatal_runtime_tx: tokio::sync::mpsc::UnboundedSender<String>,
) -> JoinHandle<crate::Result<()>> {
    tokio::spawn(async move {
        {
            let mut guard = Arc::clone(&interceptor).lock_owned().await;
            if let Err(err) = guard.init().await.map_err(|e| {
                crate::Error::Other(format!("Failed to initialize interceptor: {}", e))
            }) {
                runtime_health.set_interceptor_failed(err.to_string());
                let _ = startup_tx.send(Err(crate::Error::Other(err.to_string())));
                let _ = fatal_runtime_tx.send(format!("Interceptor startup failed: {}", err));
                return Err(err);
            }
        }

        runtime_health.set_interceptor_running();
        let _ = startup_tx.send(Ok(()));
        tracing::info!("{}", active_message);

        loop {
            let recv_result = {
                let guard = Arc::clone(&interceptor).lock_owned().await;
                guard.recv_packet().await
            };

            match recv_result {
                Ok(packet) => {
                    if let Some(table) = port_forward_table.as_ref() {
                        track_original_destination(&packet, table);
                    }
                    if let Err(err) = log_intercepted_packet(&packet, output_path.as_deref()).await
                    {
                        let message = format!("Interceptor packet processing failed: {}", err);
                        runtime_health.set_interceptor_failed(message.clone());
                        let _ = fatal_runtime_tx.send(message.clone());
                        return Err(crate::Error::Other(message));
                    }
                }
                Err(nettrap_core::Error::Shutdown) => {
                    runtime_health.set_interceptor_stopped();
                    return Ok(());
                }
                Err(e) => {
                    let message = format!("Interceptor receive error: {}", e);
                    tracing::warn!("{}", message);
                    runtime_health.set_interceptor_failed(message.clone());
                    let _ = fatal_runtime_tx.send(message.clone());
                    return Err(crate::Error::Other(message));
                }
            }
        }
    })
}

#[cfg(target_os = "windows")]
fn build_windows_interceptor(
    interface: Option<String>,
    _port_forward_table: Arc<crate::session::PortForwardTable>,
) -> crate::Result<Option<PreparedInterceptor>> {
    use nettrap_interceptor::InterceptorBuilder;

    let mut builder = InterceptorBuilder::new()
        .buffer_size(65535)
        .promiscuous(true);

    if let Some(iface) = interface {
        builder = builder.interface(iface);
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    let interceptor = builder
        .mode(nettrap_core::InterceptionMode::WinDivert)
        .build()
        .map_err(|e| {
            crate::Error::Other(format!("Failed to build WinDivert interceptor: {}", e))
        })?;

    #[cfg(target_arch = "aarch64")]
    let interceptor = builder
        .mode(nettrap_core::InterceptionMode::Userspace)
        .build()
        .map_err(|e| crate::Error::Other(format!("Failed to build Npcap interceptor: {}", e)))?;

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    let active_message = "WinDivert capture active";

    #[cfg(target_arch = "aarch64")]
    let active_message = "Npcap capture active";

    Ok(Some(PreparedInterceptor {
        interceptor: Arc::new(Mutex::new(Box::new(interceptor))),
        active_message,
        port_forward_table: None,
    }))
}

#[cfg(target_os = "linux")]
fn build_linux_interceptor(
    config: &EngineConfig,
    port_forward_table: Arc<crate::session::PortForwardTable>,
) -> crate::Result<Option<PreparedInterceptor>> {
    use nettrap_interceptor::nfqueue::{NetworkMode, NfqueueInterceptor, PortRedirect};

    let redirect_rules = build_linux_redirect_rules(config);
    if redirect_rules.is_empty() {
        tracing::warn!(
            "Interception requested but no active listener redirect rules were generated"
        );
        return Ok(None);
    }

    let mode = match config.effective_network_mode() {
        crate::config::NetworkMode::MultiHost => NetworkMode::MultiHost,
        _ => NetworkMode::SingleHost,
    };

    let flush_on_start = config.has_debug_flag("FLUSH_IPTABLES");
    let mut interceptor =
        NfqueueInterceptor::new(nettrap_interceptor::InterceptorConfig::default())?
            .with_mode(mode)
            .with_port_redirects(redirect_rules)
            .with_flush_on_start(flush_on_start);

    if let Some(ref iface) = config.restrict_interface {
        interceptor = interceptor.with_interface(iface.clone());
    }

    configure_linux_redirect_tracking(config, &port_forward_table);
    Ok(Some(PreparedInterceptor {
        interceptor: Arc::new(Mutex::new(Box::new(interceptor))),
        active_message: "NFQUEUE interceptor active",
        port_forward_table: Some(port_forward_table),
    }))
}

#[cfg(target_os = "linux")]
fn build_linux_redirect_rules(
    config: &EngineConfig,
) -> Vec<nettrap_interceptor::nfqueue::PortRedirect> {
    use nettrap_core::prelude::Protocol;
    use nettrap_interceptor::nfqueue::PortRedirect;

    let mut redirects = Vec::new();

    for listener in &config.listeners {
        if !super::listener_should_spawn(config, listener) {
            continue;
        }

        let is_tcp = listener.protocol == Protocol::Tcp;
        redirects.push(PortRedirect::new(listener.port, is_tcp, listener.port));
    }

    if !config.redirect_all_traffic {
        return redirects;
    }

    let default_tcp_target = config.default_tcp_listener.as_deref().and_then(|name| {
        super::startup::resolve_default_listener_port(config, name, Protocol::Tcp)
    });
    let default_udp_target = config.default_udp_listener.as_deref().and_then(|name| {
        super::startup::resolve_default_listener_port(config, name, Protocol::Udp)
    });

    if let Some(target_port) = default_tcp_target {
        redirects.push(PortRedirect::catch_all(true, target_port));
    }

    if let Some(target_port) = default_udp_target {
        redirects.push(PortRedirect::catch_all(false, target_port));
    }

    tracing::info!(
        "redirect_all_traffic: generated {} explicit redirect rules",
        redirects.len()
    );

    redirects
}

#[cfg(target_os = "linux")]
fn configure_linux_redirect_tracking(
    config: &EngineConfig,
    port_forward_table: &crate::session::PortForwardTable,
) {
    use nettrap_core::prelude::Protocol;

    for listener in &config.listeners {
        if !super::listener_should_spawn(config, listener) {
            continue;
        }

        match listener.protocol {
            Protocol::Tcp => port_forward_table.add_tcp_forward(listener.port, listener.port),
            Protocol::Udp => port_forward_table.add_udp_forward(listener.port, listener.port),
            _ => {}
        }
    }

    if let Some(target_port) = config
        .default_tcp_listener
        .as_deref()
        .and_then(|name| super::startup::resolve_default_listener_port(config, name, Protocol::Tcp))
    {
        port_forward_table.set_default_tcp_target(target_port);
    }

    if let Some(target_port) = config
        .default_udp_listener
        .as_deref()
        .and_then(|name| super::startup::resolve_default_listener_port(config, name, Protocol::Udp))
    {
        port_forward_table.set_default_udp_target(target_port);
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn track_original_destination(
    packet: &nettrap_core::prelude::Packet,
    port_forward_table: &crate::session::PortForwardTable,
) {
    #[cfg(target_os = "linux")]
    {
        use nettrap_core::prelude::Protocol;

        if !packet.direction.is_inbound() {
            return;
        }

        let protocol = match packet.five_tuple.protocol {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            _ => return,
        };

        let original_dst = packet.dst();
        let Some(listener_port) =
            port_forward_table.resolve_redirect_target(protocol, original_dst.port())
        else {
            return;
        };

        if listener_port == original_dst.port() {
            return;
        }

        port_forward_table.record_original_dest(
            &packet.src(),
            protocol,
            listener_port,
            &original_dst,
        );
    }

    #[cfg(not(target_os = "linux"))]
    let _ = (packet, port_forward_table);
}

#[cfg(target_os = "linux")]
async fn log_intercepted_packet(
    packet: &nettrap_core::prelude::Packet,
    output_path: Option<&std::path::Path>,
) -> crate::Result<()> {
    tracing::trace!(
        "Intercepted {} bytes from {} to {}",
        packet.payload.len(),
        packet.src(),
        packet.dst()
    );

    if let Some(path) = output_path {
        tracing::debug!("Would log intercepted packet to {}", path.display());
    }

    Ok(())
}

#[cfg(all(test, any(target_os = "windows", target_os = "linux")))]
mod tests {
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_trait::async_trait;
    use bytes::Bytes;
    use parking_lot::Mutex as ParkingMutex;
    use tokio::sync::{Mutex, mpsc, oneshot};

    use super::*;
    use nettrap_core::prelude::{FiveTuple, Packet, PacketDirection, Protocol};

    struct MockInterceptor {
        running: AtomicBool,
        recv_results: ParkingMutex<VecDeque<nettrap_core::Result<Packet>>>,
    }

    impl MockInterceptor {
        fn new(results: Vec<nettrap_core::Result<Packet>>) -> Self {
            Self {
                running: AtomicBool::new(false),
                recv_results: ParkingMutex::new(results.into()),
            }
        }
    }

    #[async_trait]
    impl nettrap_interceptor::Interceptor for MockInterceptor {
        async fn init(&mut self) -> nettrap_core::Result<()> {
            self.running.store(true, Ordering::Release);
            Ok(())
        }

        async fn recv_packet(&self) -> nettrap_core::Result<Packet> {
            self.recv_results
                .lock()
                .pop_front()
                .unwrap_or_else(|| Err(nettrap_core::Error::Shutdown))
        }

        async fn send_packet(&self, _packet: Packet) -> nettrap_core::Result<()> {
            Ok(())
        }

        async fn shutdown(&mut self) -> nettrap_core::Result<()> {
            self.running.store(false, Ordering::Release);
            Ok(())
        }

        fn name(&self) -> &'static str {
            "mock"
        }

        fn is_running(&self) -> bool {
            self.running.load(Ordering::Acquire)
        }
    }

    fn sample_packet() -> Packet {
        Packet::new(
            FiveTuple::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
                50000,
                80,
                Protocol::Tcp,
            ),
            PacketDirection::Inbound,
            Bytes::from_static(b"ping"),
        )
    }

    #[tokio::test]
    async fn interceptor_recv_error_marks_failed_and_signals_fatal_runtime() {
        let interceptor: SharedInterceptor = Arc::new(Mutex::new(Box::new(MockInterceptor::new(
            vec![Err(nettrap_core::Error::Other("recv failed".into()))],
        ))));
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        let (startup_tx, startup_rx) = oneshot::channel();
        let (fatal_tx, mut fatal_rx) = mpsc::unbounded_channel();

        let handle = spawn_interceptor_task(
            interceptor,
            None,
            "mock active",
            None,
            startup_tx,
            Arc::clone(&runtime_health),
            fatal_tx,
        );

        startup_rx
            .await
            .expect("startup result")
            .expect("startup ok");
        let fatal = fatal_rx.recv().await.expect("fatal message");
        let result = handle.await.expect("join interceptor task");
        let snapshot = runtime_health.snapshot();

        assert!(fatal.contains("Interceptor receive error"));
        assert!(result.is_err());
        assert_eq!(
            snapshot.interceptor.state,
            nettrap_api::ComponentState::Failed
        );
    }

    #[tokio::test]
    async fn interceptor_shutdown_signal_marks_stopped_without_fatal_runtime() {
        let interceptor: SharedInterceptor = Arc::new(Mutex::new(Box::new(MockInterceptor::new(
            vec![Err(nettrap_core::Error::Shutdown)],
        ))));
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        let (startup_tx, startup_rx) = oneshot::channel();
        let (fatal_tx, mut fatal_rx) = mpsc::unbounded_channel();

        let handle = spawn_interceptor_task(
            interceptor,
            None,
            "mock active",
            None,
            startup_tx,
            Arc::clone(&runtime_health),
            fatal_tx,
        );

        startup_rx
            .await
            .expect("startup result")
            .expect("startup ok");
        let result = handle.await.expect("join interceptor task");
        let snapshot = runtime_health.snapshot();

        assert!(result.is_ok());
        assert!(fatal_rx.try_recv().is_err());
        assert_eq!(
            snapshot.interceptor.state,
            nettrap_api::ComponentState::Stopped
        );
    }

    #[tokio::test]
    async fn interceptor_packet_processing_can_continue_on_successful_packet() {
        let interceptor: SharedInterceptor =
            Arc::new(Mutex::new(Box::new(MockInterceptor::new(vec![
                Ok(sample_packet()),
                Err(nettrap_core::Error::Shutdown),
            ]))));
        let runtime_health = Arc::new(nettrap_api::RuntimeHealth::new());
        let (startup_tx, startup_rx) = oneshot::channel();
        let (fatal_tx, mut fatal_rx) = mpsc::unbounded_channel();

        let handle = spawn_interceptor_task(
            interceptor,
            None,
            "mock active",
            None,
            startup_tx,
            Arc::clone(&runtime_health),
            fatal_tx,
        );

        startup_rx
            .await
            .expect("startup result")
            .expect("startup ok");
        let result = handle.await.expect("join interceptor task");
        let snapshot = runtime_health.snapshot();

        assert!(result.is_ok());
        assert!(fatal_rx.try_recv().is_err());
        assert_eq!(
            snapshot.interceptor.state,
            nettrap_api::ComponentState::Stopped
        );
    }
}

#[cfg(target_os = "windows")]
async fn log_intercepted_packet(
    packet: &nettrap_core::prelude::Packet,
    output_path: Option<&std::path::Path>,
) -> crate::Result<()> {
    tracing::trace!(
        "Intercepted {} bytes from {} to {}",
        packet.payload.len(),
        packet.src(),
        packet.dst()
    );

    if let Some(path) = output_path {
        tracing::debug!("Would log intercepted packet to {}", path.display());
    }

    Ok(())
}
