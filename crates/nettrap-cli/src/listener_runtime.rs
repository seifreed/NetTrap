use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::host_filter::{HostRule, compile_host_rules, is_host_allowed_with_rules};
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

pub struct ListenerRuntimeResources {
    pub ca: Option<Arc<nettrap_tls_mitm::CertificateAuthority>>,
    pub router: Arc<nettrap_proxy::ProtocolRouter>,
    pub attribution: Option<Arc<nettrap_attribution::AttributionEngine>>,
    pub pcap_writer: Option<Arc<nettrap_pcap::PcapWriter>>,
    pub nbi_collector: Arc<NbiCollector>,
    pub session_tracker: Arc<SessionTracker>,
    pub port_forward_table: Arc<PortForwardTable>,
    pub flow_manager: Arc<nettrap_flow::FlowManager>,
}

impl ListenerRuntime {
    pub fn new(resources: ListenerRuntimeResources) -> Self {
        Self {
            ca: resources.ca,
            router: resources.router,
            attribution: resources.attribution,
            pcap_writer: resources.pcap_writer,
            nbi_collector: resources.nbi_collector,
            session_tracker: resources.session_tracker,
            port_forward_table: resources.port_forward_table,
            flow_manager: resources.flow_manager,
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
    compiled_host_whitelist: Arc<Vec<HostRule>>,
    compiled_host_blacklist: Arc<Vec<HostRule>>,
}

impl ListenerSecurity {
    pub fn new(
        process_filter: ProcessFilter,
        host_whitelist: Vec<String>,
        host_blacklist: Vec<String>,
    ) -> crate::Result<Self> {
        let compiled_host_whitelist =
            Arc::new(compile_host_rules(&host_whitelist).map_err(crate::Error::Config)?);
        let compiled_host_blacklist =
            Arc::new(compile_host_rules(&host_blacklist).map_err(crate::Error::Config)?);

        Ok(Self {
            process_filter,
            compiled_host_whitelist,
            compiled_host_blacklist,
            host_whitelist,
            host_blacklist,
        })
    }

    pub fn with_host_whitelist(mut self, whitelist: Vec<String>) -> crate::Result<Self> {
        self.compiled_host_whitelist =
            Arc::new(compile_host_rules(&whitelist).map_err(crate::Error::Config)?);
        self.host_whitelist = whitelist;
        Ok(self)
    }

    pub fn with_host_blacklist(mut self, blacklist: Vec<String>) -> crate::Result<Self> {
        self.compiled_host_blacklist =
            Arc::new(compile_host_rules(&blacklist).map_err(crate::Error::Config)?);
        self.host_blacklist = blacklist;
        Ok(self)
    }

    pub fn is_host_allowed(&self, host: &str) -> bool {
        is_host_allowed_with_rules(
            host,
            &self.compiled_host_whitelist,
            &self.compiled_host_blacklist,
        )
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

#[cfg(test)]
mod tests {
    use super::ListenerSecurity;
    use crate::config::ListenerConfig;
    use crate::process_filter::ProcessFilter;

    #[test]
    fn runtime_allows_ipv4_mapped_loopback() {
        let security = ListenerSecurity::new(ProcessFilter::new(), Vec::new(), Vec::new())
            .expect("empty host rules should compile");

        assert!(security.is_host_allowed("::ffff:127.0.0.1"));
    }

    #[test]
    fn config_and_runtime_share_host_filter_semantics() {
        let mut config = ListenerConfig::new("http", 80);
        config.host_whitelist = vec!["10.0.0.1".to_string()];
        config.host_blacklist = vec!["10.0.0.2".to_string()];

        let security = ListenerSecurity::new(
            ProcessFilter::new(),
            config.host_whitelist.clone(),
            config.host_blacklist.clone(),
        )
        .expect("host rules should compile");

        for host in ["::ffff:127.0.0.1", "10.0.0.1", "10.0.0.2", "192.168.0.1"] {
            assert_eq!(
                config.is_host_allowed(host),
                security.is_host_allowed(host),
                "config/runtime mismatch for host {host}",
            );
        }
    }

    #[test]
    fn runtime_supports_cidr_host_filters() {
        let security = ListenerSecurity::new(
            ProcessFilter::new(),
            vec!["10.0.0.0/8".to_string()],
            Vec::new(),
        )
        .expect("cidr whitelist should compile");

        assert!(security.is_host_allowed("10.1.2.3"));
        assert!(!security.is_host_allowed("192.168.1.10"));
    }

    #[test]
    fn runtime_supports_resolved_hostname_host_filters() {
        let mut config = ListenerConfig::new("http", 80);
        config.host_whitelist = vec!["localhost".to_string()];
        config
            .refresh_host_filters()
            .expect("localhost should resolve during refresh");

        let security = ListenerSecurity::new(
            ProcessFilter::new(),
            config.host_whitelist.clone(),
            Vec::new(),
        )
        .expect("localhost should resolve");

        assert_eq!(
            config.is_host_allowed("127.0.0.1"),
            security.is_host_allowed("127.0.0.1")
        );
    }

    #[test]
    fn runtime_rejects_invalid_host_rules() {
        let err = match ListenerSecurity::new(
            ProcessFilter::new(),
            vec!["definitely-not-a-real-nettrap-host.invalid".to_string()],
            Vec::new(),
        ) {
            Ok(_) => panic!("invalid hostname should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("failed to resolve host filter"));
    }
}
