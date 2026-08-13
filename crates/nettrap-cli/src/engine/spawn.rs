use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::send_fatal_runtime_error;
use crate::config::EngineConfig;
use crate::engine::startup::StartupContext;
use crate::engine::startup::build_listener_context;
use crate::listeners::{run_tcp_listener, run_udp_listener};

pub(super) fn has_spawnable_listeners(config: &EngineConfig) -> bool {
    config
        .listeners
        .iter()
        .any(|listener| listener_should_spawn(config, listener))
}

#[cfg(test)]
pub(super) fn validate_listener_presence(
    config: &EngineConfig,
    mode: nettrap_engine::StartupMode,
    allow_zero_listeners: bool,
) -> crate::Result<()> {
    nettrap_engine::validate_listener_presence(
        mode,
        allow_zero_listeners,
        has_spawnable_listeners(config),
    )
    .map_err(crate::Error::from)
}

enum PreparedListener {
    Tcp {
        name: String,
        listener: TcpListener,
        ctx: Arc<crate::listener_context::ListenerContext>,
        output_path: Option<PathBuf>,
    },
    Udp {
        name: String,
        socket: UdpSocket,
        bind_addr: std::net::IpAddr,
        ctx: Box<crate::listener_context::ListenerContext>,
        output_path: Option<PathBuf>,
    },
}

pub(super) fn listener_is_default_target(
    config: &EngineConfig,
    listener: &crate::config::ListenerConfig,
) -> bool {
    use nettrap_core::prelude::Protocol;

    match listener.protocol {
        Protocol::Tcp => config
            .default_tcp_listener
            .as_deref()
            .is_some_and(|name| same_listener_name(name, listener.name.as_str())),
        Protocol::Udp => config
            .default_udp_listener
            .as_deref()
            .is_some_and(|name| same_listener_name(name, listener.name.as_str())),
        _ => false,
    }
}

fn same_listener_name(left: &str, right: &str) -> bool {
    left.to_lowercase() == right.to_lowercase()
}

fn canonical_listener_bind_addr(bind_addr: std::net::IpAddr) -> std::net::IpAddr {
    match bind_addr {
        std::net::IpAddr::V4(addr) => std::net::IpAddr::V4(addr),
        std::net::IpAddr::V6(addr) => addr
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(addr), std::net::IpAddr::V4),
    }
}

pub(crate) fn listener_should_spawn(
    config: &EngineConfig,
    listener: &crate::config::ListenerConfig,
) -> bool {
    use nettrap_core::prelude::Protocol;

    if !listener.enabled {
        return false;
    }

    if listener.hidden && !listener_is_default_target(config, listener) {
        return false;
    }

    let is_tcp = listener.protocol == Protocol::Tcp;
    !config.is_port_blacklisted(listener.port, is_tcp)
}

pub(super) async fn spawn_listeners(
    config: &EngineConfig,
    startup: &StartupContext,
    runtime_health: Arc<nettrap_engine::RuntimeHealth>,
    fatal_runtime_tx: mpsc::UnboundedSender<String>,
) -> crate::Result<Vec<JoinHandle<crate::Result<()>>>> {
    use nettrap_core::prelude::Protocol;

    let mut prepared = Vec::new();

    for listener in &config.listeners {
        let is_default_target = listener_is_default_target(config, listener);
        let should_spawn = listener_should_spawn(config, listener);

        if !should_spawn {
            if !listener.enabled {
                tracing::debug!("Listener {} disabled, skipping", listener.name);
            } else if listener.hidden && !is_default_target {
                tracing::info!(
                    "Listener {} registered as hidden (proxy-only) on port {}",
                    listener.name,
                    listener.port,
                );
            } else {
                tracing::debug!(
                    "Skipping listener {} on port {} (blacklisted or filtered)",
                    listener.name,
                    listener.port,
                );
            }
            continue;
        }

        runtime_health.register_listener(
            listener.name.clone(),
            format!("{:?}", listener.protocol),
            listener.port,
        );

        let is_tcp = listener.protocol == Protocol::Tcp;
        if listener.hidden {
            tracing::info!(
                "Starting hidden listener {} on port {} as default {} target",
                listener.name,
                listener.port,
                if is_tcp { "TCP" } else { "UDP" }
            );
        }

        tracing::info!(
            "Starting listener {} on port {} ({:?}){}",
            listener.name,
            listener.port,
            listener.protocol,
            if listener.use_ssl { " [SSL]" } else { "" }
        );

        let smtp_dir = startup
            .output_path
            .as_ref()
            .map(|p| p.parent().unwrap_or(p).join("smtp"));

        let listener_ctx = build_listener_context(listener, startup, smtp_dir)?;
        let bind_addr: std::net::IpAddr = listener.bind_address.parse().map_err(|err| {
            crate::Error::Config(format!(
                "Listener '{}' has invalid bind_address '{}': {}",
                listener.name, listener.bind_address, err
            ))
        })?;
        let bind_addr = canonical_listener_bind_addr(bind_addr);

        let output_path = startup.output_path.clone();
        let addr = std::net::SocketAddr::new(bind_addr, listener.port);

        match listener.protocol {
            Protocol::Udp => {
                let socket = UdpSocket::bind(addr).await.map_err(|err| {
                    let message = format!(
                        "Failed to bind UDP listener '{}' on {}: {}",
                        listener.name, addr, err
                    );
                    runtime_health.mark_listener_failed(&listener.name, message.clone());
                    crate::Error::Other(message)
                })?;
                let local_addr = socket.local_addr()?;
                runtime_health.mark_listener_running(&listener.name, local_addr.port());
                prepared.push(PreparedListener::Udp {
                    name: listener.name.clone(),
                    socket,
                    bind_addr,
                    ctx: Box::new(listener_ctx),
                    output_path,
                });
            }
            Protocol::Tcp => {
                let ctx = Arc::new(listener_ctx);
                let tcp_listener = TcpListener::bind(addr).await.map_err(|err| {
                    let message = format!(
                        "Failed to bind TCP listener '{}' on {}: {}",
                        listener.name, addr, err
                    );
                    runtime_health.mark_listener_failed(&listener.name, message.clone());
                    crate::Error::Other(message)
                })?;
                let local_addr = tcp_listener.local_addr()?;
                runtime_health.mark_listener_running(&listener.name, local_addr.port());
                prepared.push(PreparedListener::Tcp {
                    name: listener.name.clone(),
                    listener: tcp_listener,
                    ctx,
                    output_path,
                });
            }
            _ => {
                let message = format!(
                    "Unsupported protocol {:?} for listener {}",
                    listener.protocol, listener.name
                );
                runtime_health.mark_listener_failed(&listener.name, message.clone());
                return Err(crate::Error::Other(message));
            }
        }
    }

    if config.redirect_all_traffic
        && let Some(ref default_tcp) = config.default_tcp_listener
    {
        tracing::info!(
            "RedirectAllTraffic: unbound TCP ports will use taste router (default: {})",
            default_tcp
        );
    }

    let mut handles = Vec::with_capacity(prepared.len());
    for listener in prepared {
        match listener {
            PreparedListener::Udp {
                name,
                socket,
                bind_addr,
                ctx,
                output_path,
            } => {
                let runtime_health = Arc::clone(&runtime_health);
                let fatal_runtime_tx = fatal_runtime_tx.clone();
                handles.push(tokio::spawn(async move {
                    let result =
                        run_udp_listener(*ctx, socket, bind_addr, output_path.as_deref()).await;
                    let message = format!("UDP listener '{}' stopped unexpectedly", name);
                    match &result {
                        Ok(()) => {
                            runtime_health.mark_listener_stopped(&name);
                            runtime_health.set_fatal_error(message.clone());
                            send_fatal_runtime_error(&fatal_runtime_tx, message);
                        }
                        Err(err) => {
                            let message = format!("UDP listener '{}' failed: {}", name, err);
                            runtime_health.mark_listener_failed(&name, message.clone());
                            send_fatal_runtime_error(&fatal_runtime_tx, message);
                        }
                    }
                    result
                }));
            }
            PreparedListener::Tcp {
                name,
                listener,
                ctx,
                output_path,
            } => {
                let runtime_health = Arc::clone(&runtime_health);
                let fatal_runtime_tx = fatal_runtime_tx.clone();
                handles.push(tokio::spawn(async move {
                    let result = run_tcp_listener(ctx, listener, output_path.as_deref()).await;
                    let message = format!("TCP listener '{}' stopped unexpectedly", name);
                    match &result {
                        Ok(()) => {
                            runtime_health.mark_listener_stopped(&name);
                            runtime_health.set_fatal_error(message.clone());
                            send_fatal_runtime_error(&fatal_runtime_tx, message);
                        }
                        Err(err) => {
                            let message = format!("TCP listener '{}' failed: {}", name, err);
                            runtime_health.mark_listener_failed(&name, message.clone());
                            send_fatal_runtime_error(&fatal_runtime_tx, message);
                        }
                    }
                    result
                }));
            }
        }
    }

    Ok(handles)
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::config::ListenerConfig;

    #[test]
    fn listener_is_default_target_handles_unicode_case_folding() {
        let mut config = EngineConfig::default();
        config.default_tcp_listener = Some("MÜLLER".to_string());
        config.default_udp_listener = Some("MÜLLER".to_string());
        let listener = ListenerConfig::new("müller", 8080);

        assert!(listener_is_default_target(&config, &listener));
    }

    #[test]
    fn canonical_listener_bind_addr_canonicalizes_ipv4_mapped_addresses() {
        let bind_addr = "::ffff:192.0.2.10"
            .parse::<std::net::IpAddr>()
            .expect("valid bind addr");

        assert_eq!(
            canonical_listener_bind_addr(bind_addr),
            "192.0.2.10"
                .parse::<std::net::IpAddr>()
                .expect("valid IPv4 addr")
        );
    }
}
