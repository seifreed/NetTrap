//! Core ListenerContext struct with composition-based architecture.
//!
//! This module defines the primary context passed to each listener task,
//! organizing configuration and state into logical components.

use std::path::PathBuf;
use std::sync::Arc;

use crate::custom_response::CustomResponseConfig;
use crate::listener_config::ListenerConfig;
use crate::listener_runtime::{ConnectionDedup, ListenerRuntime, ListenerSecurity};
use crate::nbi::NbiCollector;
use crate::process_filter::ProcessFilter;
use crate::session::{PortForwardTable, SessionDestination, SessionTracker};

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

    // ═══════════════════════════════════════════════════════════════════════
    // BACKWARD-COMPATIBLE FIELD ALIASES (deprecated)
    // These are kept for gradual migration of existing code.
    // Use config.X, security.X, or runtime.X instead.
    // ═══════════════════════════════════════════════════════════════════════
    #[deprecated(note = "Use config.name instead")]
    pub name: String,
    #[deprecated(note = "Use config.port instead")]
    pub port: u16,
    #[deprecated(note = "Use config.banner instead")]
    pub banner: Option<String>,
    #[deprecated(note = "Use config.webroot instead")]
    pub webroot: Option<String>,
    #[deprecated(note = "Use config.ftproot instead")]
    pub ftproot: Option<String>,
    #[deprecated(note = "Use config.tftproot instead")]
    pub tftproot: Option<String>,
    #[deprecated(note = "Use config.execute_cmd instead")]
    pub execute_cmd: Option<String>,
    #[deprecated(note = "Use config.use_ssl instead")]
    pub use_ssl: bool,
    #[deprecated(note = "Use config.dump_http_posts instead")]
    pub dump_http_posts: bool,
    #[deprecated(note = "Use config.dump_prefix instead")]
    pub dump_prefix: Option<String>,
    #[deprecated(note = "Use config.timeout_ms instead")]
    pub timeout_ms: u64,
    #[deprecated(note = "Use config.response_delay_ms instead")]
    pub response_delay_ms: u64,
    #[deprecated(note = "Use config.custom_response instead")]
    pub custom_response: Option<String>,
    #[deprecated(note = "Use config.custom_response_config instead")]
    pub custom_response_config: Option<CustomResponseConfig>,
    #[deprecated(note = "Use config.server_version instead")]
    pub server_version: Option<String>,
    #[deprecated(note = "Use config.dns_response_mode instead")]
    pub dns_response_mode: Option<String>,
    #[deprecated(note = "Use config.dns_response_ip instead")]
    pub dns_response_ip: Option<String>,
    #[deprecated(note = "Use config.dns_response_mx instead")]
    pub dns_response_mx: Option<String>,
    #[deprecated(note = "Use config.dns_response_txt instead")]
    pub dns_response_txt: Option<String>,
    #[deprecated(note = "Use config.dns_nxdomains instead")]
    pub dns_nxdomains: Option<u32>,
    #[deprecated(note = "Use config.pasv_ports instead")]
    pub pasv_ports: Option<String>,
    #[deprecated(note = "Use config.max_connections instead")]
    pub max_connections: Option<u32>,
    #[deprecated(note = "Use config.banner_delay_ms instead")]
    pub banner_delay_ms: u64,
    #[deprecated(note = "Use config.smtp_dir instead")]
    pub smtp_dir: Option<PathBuf>,
    #[deprecated(note = "Use config.log_hexdump instead")]
    pub log_hexdump: bool,
    #[deprecated(note = "Use security.process_filter instead")]
    pub process_filter: ProcessFilter,
    #[deprecated(note = "Use security.host_whitelist instead")]
    pub host_whitelist: Vec<String>,
    #[deprecated(note = "Use security.host_blacklist instead")]
    pub host_blacklist: Vec<String>,
    #[deprecated(note = "Use runtime.ca instead")]
    pub ca: Option<Arc<nettrap_tls_mitm::CertificateAuthority>>,
    #[deprecated(note = "Use runtime.router instead")]
    pub router: Arc<nettrap_proxy::ProtocolRouter>,
    #[deprecated(note = "Use runtime.attribution instead")]
    pub attribution: Option<Arc<nettrap_attribution::AttributionEngine>>,
    #[deprecated(note = "Use runtime.pcap_writer instead")]
    pub pcap_writer: Option<Arc<nettrap_pcap::PcapWriter>>,
    #[deprecated(note = "Use runtime.nbi_collector instead")]
    pub nbi_collector: Arc<NbiCollector>,
    #[deprecated(note = "Use runtime.session_tracker instead")]
    pub session_tracker: Arc<SessionTracker>,
    #[deprecated(note = "Use runtime.port_forward_table instead")]
    pub port_forward_table: Arc<PortForwardTable>,
}

impl ListenerContext {
    fn pcap_destination_ip(destination: &SessionDestination) -> std::net::IpAddr {
        match destination.ip.parse::<std::net::IpAddr>() {
            Ok(ip) if !ip.is_unspecified() => ip,
            _ => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        }
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
            .unwrap_or_else(|| SessionDestination::unknown(dst_port))
    }

    fn resolve_session_destination_for_port_any(
        &self,
        peer: &std::net::SocketAddr,
        dst_port: u16,
    ) -> SessionDestination {
        self.lookup_session_destination_for_port_any(peer, dst_port)
            .unwrap_or_else(|| SessionDestination::unknown(dst_port))
    }

    fn session_flow_five_tuple(
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

        let dst_ip = destination
            .ip
            .parse()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

        Some(nettrap_core::prelude::FiveTuple::new(
            src.ip(),
            dst_ip,
            src.port(),
            destination.port,
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
        if let Some((process_name, process_pid)) =
            self.runtime
                .session_tracker
                .get_process(src, protocol, destination)
        {
            if let Some(process_name) = process_name {
                flow.metadata.process = Some(nettrap_core::prelude::ProcessInfo::new(
                    process_pid.unwrap_or_default(),
                    process_name,
                ));
            }
        }
    }

    fn ensure_session_flow(
        &self,
        src: &std::net::SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
    ) -> Option<nettrap_core::prelude::FlowKey> {
        let five_tuple = self.session_flow_five_tuple(src, protocol, destination)?;
        let flow = self.runtime.flow_manager.get_or_create(five_tuple);
        let key = flow.key();

        let _ = self.runtime.flow_manager.update(&key, |flow| {
            flow.direction = nettrap_flow::FlowDirection::Inbound;
            if flow.state != nettrap_core::prelude::FlowState::Established {
                flow.update_state(nettrap_core::prelude::FlowState::Established);
            }
            self.sync_flow_process_metadata(flow, src, protocol, destination);
        });

        Some(key)
    }

    /// Create a new ListenerContext from its composed components.
    #[allow(deprecated)]
    pub fn new(
        config: ListenerConfig,
        security: ListenerSecurity,
        runtime: ListenerRuntime,
    ) -> Self {
        Self {
            config: config.clone(),
            security: security.clone(),
            runtime: runtime.clone(),
            connection_dedup: Arc::new(ConnectionDedup::new()),

            name: config.name.clone(),
            port: config.port,
            banner: config.banner.clone(),
            webroot: config.webroot.clone(),
            ftproot: config.ftproot.clone(),
            tftproot: config.tftproot.clone(),
            execute_cmd: config.execute_cmd.clone(),
            use_ssl: config.use_ssl,
            dump_http_posts: config.dump_http_posts,
            dump_prefix: config.dump_prefix.clone(),
            timeout_ms: config.timeout_ms,
            response_delay_ms: config.response_delay_ms,
            custom_response: config.custom_response.clone(),
            custom_response_config: config.custom_response_config.clone(),
            server_version: config.server_version.clone(),
            dns_response_mode: config.dns_response_mode.clone(),
            dns_response_ip: config.dns_response_ip.clone(),
            dns_response_mx: config.dns_response_mx.clone(),
            dns_response_txt: config.dns_response_txt.clone(),
            dns_nxdomains: config.dns_nxdomains,
            pasv_ports: config.pasv_ports.clone(),
            max_connections: config.max_connections,
            banner_delay_ms: config.banner_delay_ms,
            smtp_dir: config.smtp_dir.clone(),
            log_hexdump: config.log_hexdump,
            process_filter: security.process_filter.clone(),
            host_whitelist: security.host_whitelist.clone(),
            host_blacklist: security.host_blacklist.clone(),
            ca: runtime.ca.clone(),
            router: runtime.router.clone(),
            attribution: runtime.attribution.clone(),
            pcap_writer: runtime.pcap_writer.clone(),
            nbi_collector: runtime.nbi_collector.clone(),
            session_tracker: runtime.session_tracker.clone(),
            port_forward_table: runtime.port_forward_table.clone(),
        }
    }

    /// Legacy constructor for backward compatibility during migration.
    #[allow(deprecated)]
    #[allow(clippy::too_many_arguments)]
    pub fn legacy(
        name: String,
        port: u16,
        banner: Option<String>,
        webroot: Option<String>,
        ftproot: Option<String>,
        tftproot: Option<String>,
        execute_cmd: Option<String>,
        use_ssl: bool,
        dump_http_posts: bool,
        dump_prefix: Option<String>,
        timeout_ms: u64,
        log_hexdump: bool,
        process_filter: ProcessFilter,
        host_whitelist: Vec<String>,
        host_blacklist: Vec<String>,
        ca: Option<Arc<nettrap_tls_mitm::CertificateAuthority>>,
        router: Arc<nettrap_proxy::ProtocolRouter>,
        attribution: Option<Arc<nettrap_attribution::AttributionEngine>>,
        pcap_writer: Option<Arc<nettrap_pcap::PcapWriter>>,
        response_delay_ms: u64,
        custom_response: Option<String>,
        nbi_collector: Arc<NbiCollector>,
        session_tracker: Arc<SessionTracker>,
        custom_response_config: Option<CustomResponseConfig>,
        server_version: Option<String>,
        dns_response_mode: Option<String>,
        dns_response_ip: Option<String>,
        dns_response_mx: Option<String>,
        dns_response_txt: Option<String>,
        dns_nxdomains: Option<u32>,
        pasv_ports: Option<String>,
        connection_dedup: Arc<ConnectionDedup>,
        port_forward_table: Arc<PortForwardTable>,
        max_connections: Option<u32>,
        banner_delay_ms: u64,
        smtp_dir: Option<PathBuf>,
        flow_manager: Arc<nettrap_flow::FlowManager>,
    ) -> crate::Result<Self> {
        let config = ListenerConfig {
            name,
            port,
            banner,
            webroot,
            ftproot,
            tftproot,
            execute_cmd,
            use_ssl,
            dump_http_posts,
            dump_prefix,
            timeout_ms,
            response_delay_ms,
            custom_response,
            custom_response_config,
            server_version,
            dns_response_mode,
            dns_response_ip,
            dns_response_mx,
            dns_response_txt,
            dns_nxdomains,
            pasv_ports,
            max_connections,
            banner_delay_ms,
            smtp_dir,
            log_hexdump,
        };

        let security = ListenerSecurity::new(process_filter, host_whitelist, host_blacklist)?;

        let runtime = ListenerRuntime::new(
            ca,
            router,
            attribution,
            pcap_writer,
            nbi_collector,
            session_tracker,
            port_forward_table,
            flow_manager,
        );

        Ok(Self {
            config: config.clone(),
            security: security.clone(),
            runtime: runtime.clone(),
            connection_dedup,
            name: config.name,
            port: config.port,
            banner: config.banner,
            webroot: config.webroot,
            ftproot: config.ftproot,
            tftproot: config.tftproot,
            execute_cmd: config.execute_cmd,
            use_ssl: config.use_ssl,
            dump_http_posts: config.dump_http_posts,
            dump_prefix: config.dump_prefix,
            timeout_ms: config.timeout_ms,
            response_delay_ms: config.response_delay_ms,
            custom_response: config.custom_response,
            custom_response_config: config.custom_response_config,
            server_version: config.server_version,
            dns_response_mode: config.dns_response_mode,
            dns_response_ip: config.dns_response_ip,
            dns_response_mx: config.dns_response_mx,
            dns_response_txt: config.dns_response_txt,
            dns_nxdomains: config.dns_nxdomains,
            pasv_ports: config.pasv_ports,
            max_connections: config.max_connections,
            banner_delay_ms: config.banner_delay_ms,
            smtp_dir: config.smtp_dir,
            log_hexdump: config.log_hexdump,
            process_filter: security.process_filter,
            host_whitelist: security.host_whitelist,
            host_blacklist: security.host_blacklist,
            ca: runtime.ca,
            router: runtime.router,
            attribution: runtime.attribution,
            pcap_writer: runtime.pcap_writer,
            nbi_collector: runtime.nbi_collector,
            session_tracker: runtime.session_tracker,
            port_forward_table: runtime.port_forward_table,
        })
    }

    pub fn builder() -> ListenerContextBuilder {
        ListenerContextBuilder::new()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CONVENIENCE METHODS
    // ═══════════════════════════════════════════════════════════════════════

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
            crate::execute::execute_on_connect(
                cmd,
                process_pid,
                process_name.as_deref(),
                &peer.ip().to_string(),
                peer.port(),
                &destination.ip,
                destination.port,
                &self.config.name,
            );
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
            crate::execute::execute_on_connect(
                cmd,
                process_pid,
                process_name.as_deref(),
                &peer.ip().to_string(),
                peer.port(),
                &destination.ip,
                destination.port,
                &self.config.name,
            );
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
            let packet = nettrap_core::prelude::Packet::new(
                nettrap_core::prelude::FiveTuple::new(
                    peer.ip(),
                    Self::pcap_destination_ip(destination),
                    peer.port(),
                    destination.port,
                    nettrap_core::prelude::Protocol::Tcp,
                ),
                nettrap_core::prelude::PacketDirection::Inbound,
                bytes::Bytes::copy_from_slice(data),
            );
            let _ = writer.write_packet(&packet);
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
            let packet = nettrap_core::prelude::Packet::new(
                nettrap_core::prelude::FiveTuple::new(
                    peer.ip(),
                    Self::pcap_destination_ip(destination),
                    peer.port(),
                    destination.port,
                    nettrap_core::prelude::Protocol::Udp,
                ),
                nettrap_core::prelude::PacketDirection::Inbound,
                bytes::Bytes::copy_from_slice(data),
            );
            let _ = writer.write_packet(&packet);
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
            let packet = nettrap_core::prelude::Packet::new(
                nettrap_core::prelude::FiveTuple::new(
                    Self::pcap_destination_ip(destination),
                    peer.ip(),
                    destination.port,
                    peer.port(),
                    nettrap_core::prelude::Protocol::Tcp,
                ),
                nettrap_core::prelude::PacketDirection::Outbound,
                bytes::Bytes::copy_from_slice(data),
            );
            let _ = writer.write_packet(&packet);
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
            let packet = nettrap_core::prelude::Packet::new(
                nettrap_core::prelude::FiveTuple::new(
                    Self::pcap_destination_ip(destination),
                    peer.ip(),
                    destination.port,
                    peer.port(),
                    nettrap_core::prelude::Protocol::Udp,
                ),
                nettrap_core::prelude::PacketDirection::Outbound,
                bytes::Bytes::copy_from_slice(data),
            );
            let _ = writer.write_packet(&packet);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ASYNC METHODS
    // ═══════════════════════════════════════════════════════════════════════

    pub async fn apply_response_delay(&self) {
        if self.config.response_delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(
                self.config.response_delay_ms,
            ))
            .await;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ACCESSOR METHODS
    // ═══════════════════════════════════════════════════════════════════════

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

    // ═══════════════════════════════════════════════════════════════════════
    // RUNTIME DELEGATE METHODS
    // ═══════════════════════════════════════════════════════════════════════

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
            .unwrap_or_else(|| SessionDestination::unknown(self.config.port));

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
            let _ = self.runtime.flow_manager.update(&key, |flow| {
                if recv > 0 {
                    flow.update_received(recv, nettrap_core::prelude::PacketId::new_v4());
                }
                if sent > 0 {
                    flow.update_sent(sent, nettrap_core::prelude::PacketId::new_v4());
                }
                self.sync_flow_process_metadata(flow, src, protocol, destination);
            });
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener_runtime::{ListenerRuntime, ListenerSecurity};
    use crate::process_filter::ProcessFilter;
    use crate::session::{PortForwardTable, SessionTracker};

    #[test]
    fn register_session_uses_original_redirect_destination_when_available() {
        let tracker = Arc::new(SessionTracker::new());
        let port_forward_table = Arc::new(PortForwardTable::new());
        let ctx = ListenerContext::builder().name("raw").port(9000).build(
            ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                .expect("empty host rules should compile"),
            ListenerRuntime::new(
                None,
                Arc::new(nettrap_proxy::ProtocolRouter::new()),
                None,
                None,
                Arc::new(crate::nbi::NbiCollector::new(None)),
                Arc::clone(&tracker),
                Arc::clone(&port_forward_table),
                Arc::new(nettrap_flow::FlowManager::default()),
            ),
        );
        let src: std::net::SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let original_dst: std::net::SocketAddr = "10.0.0.7:4444".parse().unwrap();

        port_forward_table.record_original_dest(&src, "UDP", 9000, &original_dst);

        let destination = ctx.register_session(
            &src,
            "UDP",
            Some(SessionDestination::new("192.168.1.50", 9000)),
        );

        assert_eq!(destination, SessionDestination::new("10.0.0.7", 4444));
        assert_eq!(
            tracker.get_original_dest(&src, "UDP", &destination),
            Some((original_dst.ip().to_string(), 4444))
        );
    }

    #[test]
    fn register_session_uses_fallback_destination_when_not_redirected() {
        let tracker = Arc::new(SessionTracker::new());
        let port_forward_table = Arc::new(PortForwardTable::new());
        let ctx = ListenerContext::builder().name("raw").port(9000).build(
            ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                .expect("empty host rules should compile"),
            ListenerRuntime::new(
                None,
                Arc::new(nettrap_proxy::ProtocolRouter::new()),
                None,
                None,
                Arc::new(crate::nbi::NbiCollector::new(None)),
                Arc::clone(&tracker),
                Arc::clone(&port_forward_table),
                Arc::new(nettrap_flow::FlowManager::default()),
            ),
        );
        let src: std::net::SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let fallback = SessionDestination::new("192.168.1.50", 9000);

        let destination = ctx.register_session(&src, "UDP", Some(fallback.clone()));

        assert_eq!(destination, fallback);
        assert_eq!(
            tracker.get_original_dest(&src, "UDP", &destination),
            Some(("192.168.1.50".to_string(), 9000))
        );
    }

    #[test]
    fn register_session_state_marks_only_first_udp_packet_as_new() {
        let tracker = Arc::new(SessionTracker::new());
        let port_forward_table = Arc::new(PortForwardTable::new());
        let ctx = ListenerContext::builder().name("dns").port(53).build(
            ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                .expect("empty host rules should compile"),
            ListenerRuntime::new(
                None,
                Arc::new(nettrap_proxy::ProtocolRouter::new()),
                None,
                None,
                Arc::new(crate::nbi::NbiCollector::new(None)),
                Arc::clone(&tracker),
                Arc::clone(&port_forward_table),
                Arc::new(nettrap_flow::FlowManager::default()),
            ),
        );
        let src: std::net::SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let destination = SessionDestination::new("10.0.0.7", 53);

        let (first_destination, first_is_new) =
            ctx.register_session_state(&src, "UDP", Some(destination.clone()));
        let (second_destination, second_is_new) =
            ctx.register_session_state(&src, "UDP", Some(destination.clone()));

        assert_eq!(first_destination, destination);
        assert_eq!(second_destination, destination);
        assert!(first_is_new);
        assert!(!second_is_new);
    }

    #[test]
    fn resolve_session_destination_for_port_uses_tracked_destination() {
        let tracker = Arc::new(SessionTracker::new());
        let port_forward_table = Arc::new(PortForwardTable::new());
        let ctx = ListenerContext::builder().name("http").port(8080).build(
            ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                .expect("empty host rules should compile"),
            ListenerRuntime::new(
                None,
                Arc::new(nettrap_proxy::ProtocolRouter::new()),
                None,
                None,
                Arc::new(crate::nbi::NbiCollector::new(None)),
                Arc::clone(&tracker),
                Arc::clone(&port_forward_table),
                Arc::new(nettrap_flow::FlowManager::default()),
            ),
        );
        let src: std::net::SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let tracked = SessionDestination::new("10.0.0.7", 8080);

        ctx.register_session_state(&src, "TCP", Some(tracked.clone()));

        assert_eq!(
            ctx.resolve_session_destination_for_port(&src, "TCP", 8080),
            tracked
        );
    }

    #[test]
    fn session_process_for_destination_reads_existing_attribution() {
        let tracker = Arc::new(SessionTracker::new());
        let port_forward_table = Arc::new(PortForwardTable::new());
        let ctx = ListenerContext::builder()
            .name("http")
            .port(8080)
            .execute_cmd(Some("echo {procname}:{pid}".to_string()))
            .build(
                ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                    .expect("empty host rules should compile"),
                ListenerRuntime::new(
                    None,
                    Arc::new(nettrap_proxy::ProtocolRouter::new()),
                    None,
                    None,
                    Arc::new(crate::nbi::NbiCollector::new(None)),
                    Arc::clone(&tracker),
                    Arc::clone(&port_forward_table),
                    Arc::new(nettrap_flow::FlowManager::default()),
                ),
            );
        let src: std::net::SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let destination = SessionDestination::new("10.0.0.7", 8080);

        ctx.register_session_state(&src, "TCP", Some(destination.clone()));
        tracker.set_process(
            &src,
            "TCP",
            &destination,
            Some("curl".to_string()),
            Some(4242),
        );

        assert_eq!(
            ctx.session_process_for_destination(&src, "TCP", &destination),
            (Some("curl".to_string()), Some(4242))
        );
    }

    #[test]
    fn session_lifecycle_updates_flow_manager() {
        let tracker = Arc::new(SessionTracker::new());
        let port_forward_table = Arc::new(PortForwardTable::new());
        let flow_manager = Arc::new(nettrap_flow::FlowManager::default());
        let ctx = ListenerContext::builder().name("http").port(8080).build(
            ListenerSecurity::new(ProcessFilter::default(), Vec::new(), Vec::new())
                .expect("empty host rules should compile"),
            ListenerRuntime::new(
                None,
                Arc::new(nettrap_proxy::ProtocolRouter::new()),
                None,
                None,
                Arc::new(crate::nbi::NbiCollector::new(None)),
                Arc::clone(&tracker),
                Arc::clone(&port_forward_table),
                Arc::clone(&flow_manager),
            ),
        );
        let src: std::net::SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let destination = SessionDestination::new("10.0.0.7", 8080);

        ctx.register_session_state(&src, "TCP", Some(destination.clone()));

        let key = nettrap_core::prelude::FlowKey::from_five_tuple(
            &nettrap_core::prelude::FiveTuple::new(
                src.ip(),
                "10.0.0.7".parse().unwrap(),
                src.port(),
                destination.port,
                nettrap_core::prelude::Protocol::Tcp,
            ),
        );
        let flow = flow_manager.get(&key).expect("flow should be tracked");
        assert_eq!(flow.state, nettrap_core::prelude::FlowState::Established);
        assert_eq!(flow.direction, nettrap_flow::FlowDirection::Inbound);

        ctx.update_session_bytes(&src, "TCP", &destination, 64, 32);
        let updated_flow = flow_manager.get(&key).expect("flow should still exist");
        assert_eq!(updated_flow.metadata.bytes_received, 64);
        assert_eq!(updated_flow.metadata.bytes_sent, 32);

        ctx.remove_session(&src, "TCP", &destination);
        assert!(flow_manager.get(&key).is_none());
    }

    #[test]
    fn legacy_constructor_returns_error_for_invalid_host_rules() {
        let result = ListenerContext::legacy(
            "http".to_string(),
            80,
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            30_000,
            false,
            ProcessFilter::default(),
            vec!["definitely-not-a-real-nettrap-host.invalid".to_string()],
            Vec::new(),
            None,
            Arc::new(nettrap_proxy::ProtocolRouter::new()),
            None,
            None,
            0,
            None,
            Arc::new(crate::nbi::NbiCollector::new(None)),
            Arc::new(SessionTracker::new()),
            None,
            None,
            None,
            None,
            None,
            None,
            Some(100),
            None,
            Arc::new(ConnectionDedup::new()),
            Arc::new(PortForwardTable::new()),
            None,
            0,
            None,
            Arc::new(nettrap_flow::FlowManager::default()),
        );

        let err = match result {
            Ok(_) => panic!("invalid legacy host filters should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("failed to resolve host filter"));
    }
}
