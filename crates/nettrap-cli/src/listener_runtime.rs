use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::nbi::NbiCollector;
use crate::process_filter::ProcessFilter;
use crate::session::{PortForwardTable, SessionTracker};

/// Shared runtime resources for all listeners.
///
/// Contains references to services that are shared across all listeners:
/// - Protocol router for taste detection
/// - Attribution engine
/// - PCAP writer
/// - NBI collector
/// - Session tracker
/// - TLS certificate authority
#[derive(Clone)]
pub struct ListenerRuntime {
    pub router: Arc<nettrap_proxy::ProtocolRouter>,
    pub attribution: Option<Arc<nettrap_attribution::AttributionEngine>>,
    pub pcap_writer: Option<Arc<nettrap_pcap::PcapWriter>>,
    pub nbi_collector: Arc<NbiCollector>,
    pub session_tracker: Arc<SessionTracker>,
    pub port_forward_table: Arc<PortForwardTable>,
    pub flow_manager: Arc<nettrap_flow::FlowManager>,
    pub ca: Option<Arc<nettrap_tls_mitm::CertificateAuthority>>,
}

impl ListenerRuntime {
    pub fn new(
        ca: Option<Arc<nettrap_tls_mitm::CertificateAuthority>>,
        router: Arc<nettrap_proxy::ProtocolRouter>,
        attribution: Option<Arc<nettrap_attribution::AttributionEngine>>,
        pcap_writer: Option<Arc<nettrap_pcap::PcapWriter>>,
        nbi_collector: Arc<NbiCollector>,
        session_tracker: Arc<SessionTracker>,
        port_forward_table: Arc<PortForwardTable>,
        flow_manager: Arc<nettrap_flow::FlowManager>,
    ) -> Self {
        Self {
            ca,
            router,
            attribution,
            pcap_writer,
            nbi_collector,
            session_tracker,
            port_forward_table,
            flow_manager,
        }
    }
}

/// Per-listener security configuration.
///
/// Contains host and process filtering rules that determine whether
/// connections should be allowed.
#[derive(Clone)]
pub struct ListenerSecurity {
    pub process_filter: ProcessFilter,
    pub host_whitelist: Vec<String>,
    pub host_blacklist: Vec<String>,
}

impl ListenerSecurity {
    pub fn new(
        process_filter: ProcessFilter,
        host_whitelist: Vec<String>,
        host_blacklist: Vec<String>,
    ) -> Self {
        Self {
            process_filter,
            host_whitelist,
            host_blacklist,
        }
    }

    pub fn with_host_whitelist(mut self, whitelist: Vec<String>) -> Self {
        self.host_whitelist = whitelist;
        self
    }

    pub fn with_host_blacklist(mut self, blacklist: Vec<String>) -> Self {
        self.host_blacklist = blacklist;
        self
    }

    pub fn is_host_allowed(&self, host: &str) -> bool {
        if host == "127.0.0.1" || host == "::1" || host.starts_with("127.") {
            return true;
        }
        if !self.host_whitelist.is_empty() {
            return self.host_whitelist.iter().any(|h| h == host);
        }
        if !self.host_blacklist.is_empty() {
            return !self.host_blacklist.iter().any(|h| h == host);
        }
        true
    }

    pub fn is_process_allowed(&self, process_name: &str) -> bool {
        self.process_filter.is_process_allowed(process_name)
    }
}

/// Rate-limited connection logging deduplication.
///
/// Prevents log spam from repeated connections by tracking recently
/// logged connections within a time window.
pub struct ConnectionDedup {
    data: Mutex<(HashSet<String>, Instant)>,
}

impl ConnectionDedup {
    pub fn new() -> Self {
        Self {
            data: Mutex::new((HashSet::new(), Instant::now())),
        }
    }

    pub fn should_log(&self, key: &str) -> bool {
        let mut data = self.data.lock();
        let (seen, last_cleanup) = &mut *data;

        if last_cleanup.elapsed() > Duration::from_secs(60) {
            seen.clear();
            *last_cleanup = Instant::now();
        }

        seen.insert(key.to_string())
    }
}

impl Default for ConnectionDedup {
    fn default() -> Self {
        Self::new()
    }
}
