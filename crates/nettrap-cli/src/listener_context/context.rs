//! Core ListenerContext struct with composition-based architecture.

use std::sync::Arc;

use crate::listener_config::ListenerConfig;
use crate::listener_runtime::{ConnectionDedup, ListenerRuntime, ListenerSecurity};
use crate::session::{SessionDestination, normalize_session_ip};
use crate::utils::canonical_socket_ip_string;

use super::ListenerContextBuilder;

/// Context passed to each listener task with all its configuration and runtime state.
///
/// This struct uses composition to organize its fields into logical groups:
/// - `config`: Immutable configuration from file/CLI
/// - `security`: Host and process filtering rules  
/// - `runtime`: Shared resources (router, session tracker, etc.)
/// - `connection_dedup`: Rate-limited logging deduplication
///
/// # Architecture
///
/// ```ignore
/// ListenerContext {
///     config: ListenerConfig,      // Immutable config from file
///     security: ListenerSecurity,  // Host/process filtering
///     runtime: ListenerRuntime,    // Shared resources
///     connection_dedup: Arc<ConnectionDedup>,
/// }
/// ```
#[derive(Clone)]
pub struct ListenerContext {
    /// Immutable configuration from config file / CLI
    pub config: ListenerConfig,

    /// Security filtering (host/process allow/deny)
    pub security: ListenerSecurity,

    /// Shared runtime resources
    pub runtime: ListenerRuntime,

    /// Rate-limited connection logging deduplication
    pub connection_dedup: Arc<ConnectionDedup>,
}

impl ListenerContext {
    fn pcap_destination_ip(destination: &SessionDestination) -> Option<std::net::IpAddr> {
        match destination.ip().parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip))
                if !is_unspecified_destination_ip(&std::net::IpAddr::V4(ip)) =>
            {
                Some(std::net::IpAddr::V4(ip))
            }
            Ok(std::net::IpAddr::V6(ip)) => ip.to_ipv4_mapped().map_or_else(
                || {
                    if is_unspecified_destination_ip(&std::net::IpAddr::V6(ip)) {
                        None
                    } else {
                        Some(std::net::IpAddr::V6(ip))
                    }
                },
                |mapped| {
                    if is_unspecified_destination_ip(&std::net::IpAddr::V4(mapped)) {
                        None
                    } else {
                        Some(std::net::IpAddr::V4(mapped))
                    }
                },
            ),
            Ok(_) => None,
            Err(_) => None,
        }
    }

    fn pcap_peer_ip(peer: &std::net::SocketAddr) -> std::net::IpAddr {
        normalize_session_ip(peer.ip())
    }

    fn session_process_for_destination(
        &self,
        peer: &std::net::SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
    ) -> (Option<String>, Option<u32>) {
        self.runtime
            .session_tracker
            .get_process(peer, protocol, destination)
            .unwrap_or((None, None))
    }

    fn session_process_for_destination_any(
        &self,
        peer: &std::net::SocketAddr,
        destination: &SessionDestination,
    ) -> (Option<String>, Option<u32>) {
        self.runtime
            .session_tracker
            .get_process(peer, "TCP", destination)
            .or_else(|| {
                self.runtime
                    .session_tracker
                    .get_process(peer, "UDP", destination)
            })
            .unwrap_or((None, None))
    }

    fn lookup_session_destination_for_port(
        &self,
        peer: &std::net::SocketAddr,
        protocol: &str,
        dst_port: u16,
    ) -> Option<SessionDestination> {
        self.runtime
            .session_tracker
            .get_destination_for_port(peer, protocol, dst_port)
    }

    fn lookup_session_destination_for_port_any(
        &self,
        peer: &std::net::SocketAddr,
        dst_port: u16,
    ) -> Option<SessionDestination> {
        self.lookup_session_destination_for_port(peer, "TCP", dst_port)
            .or_else(|| self.lookup_session_destination_for_port(peer, "UDP", dst_port))
    }

    pub(crate) fn resolve_session_destination_for_port(
        &self,
        peer: &std::net::SocketAddr,
        protocol: &str,
        dst_port: u16,
    ) -> SessionDestination {
        self.lookup_session_destination_for_port(peer, protocol, dst_port)
            .unwrap_or_else(|| unknown_session_destination_for_peer(peer, dst_port))
    }

    fn resolve_session_destination_for_port_any(
        &self,
        peer: &std::net::SocketAddr,
        dst_port: u16,
    ) -> SessionDestination {
        self.lookup_session_destination_for_port_any(peer, dst_port)
            .unwrap_or_else(|| unknown_session_destination_for_peer(peer, dst_port))
    }

    pub(crate) fn session_flow_five_tuple(
        &self,
        src: &std::net::SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
    ) -> Option<nettrap_core::prelude::FiveTuple> {
        let protocol = if protocol.eq_ignore_ascii_case("TCP") {
            nettrap_core::prelude::Protocol::Tcp
        } else if protocol.eq_ignore_ascii_case("UDP") {
            nettrap_core::prelude::Protocol::Udp
        } else {
            return None;
        };

        let src_ip = normalize_session_ip(src.ip());
        let dst_ip = match destination.ip().parse::<std::net::IpAddr>() {
            Ok(ip) => normalize_session_ip(ip),
            Err(_) => match unknown_session_destination_for_peer(src, destination.port())
                .ip()
                .parse::<std::net::IpAddr>()
            {
                Ok(ip) => ip,
                Err(_) => return None,
            },
        };

        Some(nettrap_core::prelude::FiveTuple::new(
            src_ip,
            dst_ip,
            src.port(),
            destination.port(),
            protocol,
        ))
    }

    fn sync_flow_process_metadata(
        &self,
        flow: &mut nettrap_flow::Flow,
        src: &std::net::SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
    ) {
        flow.metadata.process =
            match self
                .runtime
                .session_tracker
                .get_process(src, protocol, destination)
            {
                Some((Some(process_name), Some(process_pid))) => Some(
                    nettrap_core::prelude::ProcessInfo::new(process_pid, process_name),
                ),
                Some((None, Some(process_pid))) => Some(nettrap_core::prelude::ProcessInfo::new(
                    process_pid,
                    format!("pid-{}", process_pid),
                )),
                _ => None,
            }
    }

    fn ensure_session_flow(
        &self,
        src: &std::net::SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
    ) -> Option<nettrap_core::prelude::FlowKey> {
        let five_tuple = self.session_flow_five_tuple(src, protocol, destination)?;
        let key = self.runtime.flow_manager.get_or_create(five_tuple).key();

        if self
            .apply_session_flow_update(&key, src, protocol, destination)
            .is_none()
        {
            tracing::warn!(
                "Session flow for {}:{} expired during registration; recreating",
                src.ip(),
                destination.port()
            );
            let recreated_key = self.runtime.flow_manager.get_or_create(five_tuple).key();
            let _ = self.apply_session_flow_update(&recreated_key, src, protocol, destination);
            return Some(recreated_key);
        }

        Some(key)
    }

    fn apply_session_flow_update(
        &self,
        key: &nettrap_core::prelude::FlowKey,
        src: &std::net::SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
    ) -> Option<()> {
        self.runtime.flow_manager.update(key, |flow| {
            flow.direction = Self::session_flow_direction(src, destination);
            self.sync_flow_process_metadata(flow, src, protocol, destination);
        })?;
        Some(())
    }

    fn session_flow_direction(
        src: &std::net::SocketAddr,
        destination: &SessionDestination,
    ) -> nettrap_flow::FlowDirection {
        let Ok(dst_ip) = destination.ip().parse::<std::net::IpAddr>() else {
            return nettrap_flow::FlowDirection::Unknown;
        };

        if Self::is_unknown_session_destination(dst_ip) {
            return nettrap_flow::FlowDirection::Unknown;
        };

        if Self::is_loopback_address(src.ip()) && Self::is_loopback_address(dst_ip) {
            nettrap_flow::FlowDirection::Internal
        } else {
            nettrap_flow::FlowDirection::Inbound
        }
    }

    fn is_loopback_address(ip: std::net::IpAddr) -> bool {
        if ip.is_loopback() {
            return true;
        }

        matches!(
            ip,
            std::net::IpAddr::V6(v6) if v6
                .to_ipv4_mapped()
                .is_some_and(|mapped| mapped.is_loopback())
        )
    }

    fn is_unknown_session_destination(ip: std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(ip) => {
                ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast()
            }
            std::net::IpAddr::V6(ip) => {
                ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.to_ipv4_mapped().is_some_and(|mapped| {
                        mapped.is_unspecified() || mapped.is_multicast() || mapped.is_broadcast()
                    })
            }
        }
    }

    /// Create a new ListenerContext from its composed components.
    pub fn new(
        config: ListenerConfig,
        security: ListenerSecurity,
        runtime: ListenerRuntime,
    ) -> Self {
        Self {
            config,
            security,
            runtime,
            connection_dedup: Arc::new(ConnectionDedup::new()),
        }
    }

    pub fn builder() -> ListenerContextBuilder {
        ListenerContextBuilder::new()
    }

    pub fn is_host_allowed(&self, host: &str) -> bool {
        self.security.is_host_allowed(host)
    }

    pub fn is_process_allowed(&self, process_name: &str) -> bool {
        self.security.is_process_allowed(process_name)
    }

    pub fn fire_execute_cmd(&self, peer: &std::net::SocketAddr) {
        let destination = self.resolve_session_destination_for_port_any(peer, self.config.port);
        self.fire_execute_cmd_for_destination(peer, &destination);
    }

    pub fn fire_execute_cmd_for_port(&self, peer: &std::net::SocketAddr, dst_port: u16) {
        let destination = self.resolve_session_destination_for_port_any(peer, dst_port);
        self.fire_execute_cmd_for_destination(peer, &destination);
    }

    pub(crate) fn fire_execute_cmd_for_session(
        &self,
        peer: &std::net::SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
    ) {
        let (process_name, process_pid) =
            self.session_process_for_destination(peer, protocol, destination);

        if let Some(ref cmd) = self.config.execute_cmd {
            crate::execute::execute_on_connect(crate::execute::ExecuteOnConnect {
                template: cmd,
                pid: process_pid,
                procname: process_name.as_deref(),
                src_addr: &canonical_execute_src_ip(peer),
                src_port: peer.port(),
                dst_addr: &canonical_execute_dst_ip(peer, destination),
                dst_port: destination.port(),
                listener: &self.config.name,
            });
        }
    }

    pub fn fire_execute_cmd_for_destination(
        &self,
        peer: &std::net::SocketAddr,
        destination: &SessionDestination,
    ) {
        let (process_name, process_pid) =
            self.session_process_for_destination_any(peer, destination);

        if let Some(ref cmd) = self.config.execute_cmd {
            crate::execute::execute_on_connect(crate::execute::ExecuteOnConnect {
                template: cmd,
                pid: process_pid,
                procname: process_name.as_deref(),
                src_addr: &canonical_execute_src_ip(peer),
                src_port: peer.port(),
                dst_addr: &canonical_execute_dst_ip(peer, destination),
                dst_port: destination.port(),
                listener: &self.config.name,
            });
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // PCAP WRITING METHODS
    // ═══════════════════════════════════════════════════════════════════════

    pub fn write_pcap_event(&self, data: &[u8], peer: &std::net::SocketAddr) {
        let destination = self.resolve_session_destination_for_port(peer, "TCP", self.config.port);
        self.write_pcap_event_for_destination(data, peer, &destination);
    }

    pub fn write_pcap_event_for_port(
        &self,
        data: &[u8],
        peer: &std::net::SocketAddr,
        dst_port: u16,
    ) {
        let destination = self.resolve_session_destination_for_port(peer, "TCP", dst_port);
        self.write_pcap_event_for_destination(data, peer, &destination);
    }

    pub fn write_pcap_event_for_destination(
        &self,
        data: &[u8],
        peer: &std::net::SocketAddr,
        destination: &SessionDestination,
    ) {
        if let Some(ref writer) = self.runtime.pcap_writer {
            let Some(dst_ip) = Self::pcap_destination_ip(destination) else {
                return;
            };
            let packet = nettrap_core::prelude::Packet::new(
                nettrap_core::prelude::FiveTuple::new(
                    Self::pcap_peer_ip(peer),
                    dst_ip,
                    peer.port(),
                    destination.port(),
                    nettrap_core::prelude::Protocol::Tcp,
                ),
                nettrap_core::prelude::PacketDirection::Inbound,
                bytes::Bytes::copy_from_slice(data),
            );
            if let Err(err) = writer.write_packet(&packet) {
                tracing::warn!("Failed to write inbound PCAP packet: {}", err);
            }
        }
    }

    pub fn write_pcap_event_udp(&self, data: &[u8], peer: &std::net::SocketAddr) {
        let destination = self.resolve_session_destination_for_port(peer, "UDP", self.config.port);
        self.write_pcap_event_udp_for_destination(data, peer, &destination);
    }

    pub fn write_pcap_event_udp_for_port(
        &self,
        data: &[u8],
        peer: &std::net::SocketAddr,
        dst_port: u16,
    ) {
        let destination = self.resolve_session_destination_for_port(peer, "UDP", dst_port);
        self.write_pcap_event_udp_for_destination(data, peer, &destination);
    }

    pub fn write_pcap_event_udp_for_destination(
        &self,
        data: &[u8],
        peer: &std::net::SocketAddr,
        destination: &SessionDestination,
    ) {
        if let Some(ref writer) = self.runtime.pcap_writer {
            let Some(dst_ip) = Self::pcap_destination_ip(destination) else {
                return;
            };
            let packet = nettrap_core::prelude::Packet::new(
                nettrap_core::prelude::FiveTuple::new(
                    Self::pcap_peer_ip(peer),
                    dst_ip,
                    peer.port(),
                    destination.port(),
                    nettrap_core::prelude::Protocol::Udp,
                ),
                nettrap_core::prelude::PacketDirection::Inbound,
                bytes::Bytes::copy_from_slice(data),
            );
            if let Err(err) = writer.write_packet(&packet) {
                tracing::warn!("Failed to write inbound UDP PCAP packet: {}", err);
            }
        }
    }

    pub fn write_pcap_response(&self, data: &[u8], peer: &std::net::SocketAddr) {
        let destination = self.resolve_session_destination_for_port(peer, "TCP", self.config.port);
        self.write_pcap_response_for_destination(data, peer, &destination);
    }

    pub fn write_pcap_response_for_port(
        &self,
        data: &[u8],
        peer: &std::net::SocketAddr,
        dst_port: u16,
    ) {
        let destination = self.resolve_session_destination_for_port(peer, "TCP", dst_port);
        self.write_pcap_response_for_destination(data, peer, &destination);
    }

    pub fn write_pcap_response_for_destination(
        &self,
        data: &[u8],
        peer: &std::net::SocketAddr,
        destination: &SessionDestination,
    ) {
        if let Some(ref writer) = self.runtime.pcap_writer {
            let Some(dst_ip) = Self::pcap_destination_ip(destination) else {
                return;
            };
            let packet = nettrap_core::prelude::Packet::new(
                nettrap_core::prelude::FiveTuple::new(
                    dst_ip,
                    Self::pcap_peer_ip(peer),
                    destination.port(),
                    peer.port(),
                    nettrap_core::prelude::Protocol::Tcp,
                ),
                nettrap_core::prelude::PacketDirection::Outbound,
                bytes::Bytes::copy_from_slice(data),
            );
            if let Err(err) = writer.write_packet(&packet) {
                tracing::warn!("Failed to write outbound PCAP packet: {}", err);
            }
        }
    }

    pub fn write_pcap_response_udp(&self, data: &[u8], peer: &std::net::SocketAddr) {
        let destination = self.resolve_session_destination_for_port(peer, "UDP", self.config.port);
        self.write_pcap_response_udp_for_destination(data, peer, &destination);
    }

    pub fn write_pcap_response_udp_for_port(
        &self,
        data: &[u8],
        peer: &std::net::SocketAddr,
        dst_port: u16,
    ) {
        let destination = self.resolve_session_destination_for_port(peer, "UDP", dst_port);
        self.write_pcap_response_udp_for_destination(data, peer, &destination);
    }

    pub fn write_pcap_response_udp_for_destination(
        &self,
        data: &[u8],
        peer: &std::net::SocketAddr,
        destination: &SessionDestination,
    ) {
        if let Some(ref writer) = self.runtime.pcap_writer {
            let Some(dst_ip) = Self::pcap_destination_ip(destination) else {
                return;
            };
            let packet = nettrap_core::prelude::Packet::new(
                nettrap_core::prelude::FiveTuple::new(
                    dst_ip,
                    Self::pcap_peer_ip(peer),
                    destination.port(),
                    peer.port(),
                    nettrap_core::prelude::Protocol::Udp,
                ),
                nettrap_core::prelude::PacketDirection::Outbound,
                bytes::Bytes::copy_from_slice(data),
            );
            if let Err(err) = writer.write_packet(&packet) {
                tracing::warn!("Failed to write outbound UDP PCAP packet: {}", err);
            }
        }
    }

    pub async fn apply_response_delay(&self) {
        if self.config.response_delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(
                self.config.response_delay_ms,
            ))
            .await;
        }
    }

    pub fn name(&self) -> &str {
        &self.config.name
    }

    pub fn port(&self) -> u16 {
        self.config.port
    }

    pub fn banner(&self) -> Option<&str> {
        self.config.banner.as_deref()
    }

    pub fn webroot(&self) -> Option<&str> {
        self.config.webroot.as_deref()
    }

    pub fn ftproot(&self) -> Option<&str> {
        self.config.ftproot.as_deref()
    }

    pub fn tftproot(&self) -> Option<&str> {
        self.config.tftproot.as_deref()
    }

    pub fn use_ssl(&self) -> bool {
        self.config.use_ssl
    }

    pub fn timeout_ms(&self) -> u64 {
        self.config.timeout_ms
    }

    pub fn banner_delay_ms(&self) -> u64 {
        self.config.banner_delay_ms
    }

    pub fn max_connections(&self) -> Option<u32> {
        self.config.max_connections
    }

    pub fn dns_response_mode(&self) -> Option<&str> {
        self.config.dns_response_mode.as_deref()
    }

    pub fn dns_response_ip(&self) -> Option<&str> {
        self.config.dns_response_ip.as_deref()
    }

    pub fn dns_ncsi_response_ip(&self) -> Option<&str> {
        self.config.dns_ncsi_response_ip.as_deref()
    }

    pub fn custom_response(&self) -> Option<&str> {
        self.config.custom_response.as_deref()
    }

    pub fn dump_http_posts(&self) -> bool {
        self.config.dump_http_posts
    }

    pub fn dump_prefix(&self) -> Option<&str> {
        self.config.dump_prefix.as_deref()
    }

    pub fn server_version(&self) -> Option<&str> {
        self.config.server_version.as_deref()
    }

    pub async fn record_nbi(&self, nbi: &crate::nbi::NetworkBehaviorIndicator) {
        self.runtime.nbi_collector.record(nbi).await;
    }

    pub fn register_session(
        &self,
        src: &std::net::SocketAddr,
        protocol: &str,
        fallback_destination: Option<SessionDestination>,
    ) -> SessionDestination {
        self.register_session_state(src, protocol, fallback_destination)
            .0
    }

    pub fn register_session_state(
        &self,
        src: &std::net::SocketAddr,
        protocol: &str,
        fallback_destination: Option<SessionDestination>,
    ) -> (SessionDestination, bool) {
        let destination = self
            .runtime
            .port_forward_table
            .take_original_dest(src, protocol, self.config.port)
            .or(fallback_destination)
            .unwrap_or_else(|| unknown_session_destination_for_peer(src, self.config.port));

        let is_new =
            self.runtime
                .session_tracker
                .register(src, &destination, &self.config.name, protocol);
        self.ensure_session_flow(src, protocol, &destination);
        (destination, is_new)
    }

    pub fn update_session_bytes(
        &self,
        src: &std::net::SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
        recv: u64,
        sent: u64,
    ) {
        if let Some(key) = self.ensure_session_flow(src, protocol, destination) {
            let now = self.runtime.flow_manager.now();
            let updated = self.runtime.flow_manager.update(&key, |flow| {
                if (recv > 0 || sent > 0) && flow.state == nettrap_core::prelude::FlowState::New {
                    flow.update_state_with_now(nettrap_core::prelude::FlowState::Established, now);
                }
                if recv > 0 {
                    flow.update_received_with_now(
                        recv,
                        nettrap_core::prelude::PacketId::new_v4(),
                        now,
                    );
                }
                if sent > 0 {
                    flow.update_sent_with_now(sent, nettrap_core::prelude::PacketId::new_v4(), now);
                }
                self.sync_flow_process_metadata(flow, src, protocol, destination);
            });
            if updated.is_none() {
                tracing::warn!(
                    "Session flow for {}:{} expired during byte update; recreating",
                    src.ip(),
                    destination.port()
                );
                if let Some(key) = self.ensure_session_flow(src, protocol, destination) {
                    let now = self.runtime.flow_manager.now();
                    let _ = self.runtime.flow_manager.update(&key, |flow| {
                        if (recv > 0 || sent > 0)
                            && flow.state == nettrap_core::prelude::FlowState::New
                        {
                            flow.update_state_with_now(
                                nettrap_core::prelude::FlowState::Established,
                                now,
                            );
                        }
                        if recv > 0 {
                            flow.update_received_with_now(
                                recv,
                                nettrap_core::prelude::PacketId::new_v4(),
                                now,
                            );
                        }
                        if sent > 0 {
                            flow.update_sent_with_now(
                                sent,
                                nettrap_core::prelude::PacketId::new_v4(),
                                now,
                            );
                        }
                        self.sync_flow_process_metadata(flow, src, protocol, destination);
                    });
                }
            }
        }

        self.runtime
            .session_tracker
            .update_bytes(src, protocol, destination, recv, sent);
    }

    pub fn remove_session(
        &self,
        src: &std::net::SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
    ) {
        if let Some(five_tuple) = self.session_flow_five_tuple(src, protocol, destination) {
            let key = nettrap_core::prelude::FlowKey::from_five_tuple(&five_tuple);
            self.runtime.flow_manager.remove(&key);
        }

        self.runtime
            .session_tracker
            .remove(src, protocol, destination);
        self.runtime
            .port_forward_table
            .clear_original_dest(src, protocol, self.config.port);
    }
}

fn canonical_execute_src_ip(peer: &std::net::SocketAddr) -> String {
    canonical_socket_ip_string(peer)
}

fn canonical_execute_dst_ip(
    peer: &std::net::SocketAddr,
    destination: &SessionDestination,
) -> String {
    destination
        .ip()
        .parse::<std::net::IpAddr>()
        .ok()
        .map(normalize_session_ip)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| {
            unknown_session_destination_for_peer(peer, destination.port())
                .ip()
                .to_string()
        })
}

fn is_unspecified_destination_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast(),
        std::net::IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_multicast()
                || ip.to_ipv4_mapped().is_some_and(|mapped| {
                    mapped.is_unspecified() || mapped.is_multicast() || mapped.is_broadcast()
                })
        }
    }
}

fn unknown_session_destination_for_peer(
    peer: &std::net::SocketAddr,
    port: u16,
) -> SessionDestination {
    match crate::session::normalize_session_ip(peer.ip()) {
        std::net::IpAddr::V4(_) => SessionDestination::new_unchecked("0.0.0.0", port),
        std::net::IpAddr::V6(_) => SessionDestination::new_unchecked("::", port),
    }
}

#[cfg(test)]
#[path = "context_tests.rs"]
mod tests;
