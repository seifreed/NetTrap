use std::collections::{HashSet, VecDeque};
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
/// - Attribution operation timeout
/// - PCAP writer
/// - NBI collector
/// - Session tracker
/// - TLS certificate authority
#[derive(Clone)]
pub struct ListenerRuntime {
    pub router: Arc<nettrap_proxy::ProtocolRouter>,
    pub attribution: Option<Arc<nettrap_attribution::AttributionEngine>>,
    pub attribution_timeout: Duration,
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
    pub attribution_timeout: Duration,
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
            attribution_timeout: resources.attribution_timeout,
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
    compiled_host_whitelist_source: Arc<Vec<String>>,
    compiled_host_blacklist_source: Arc<Vec<String>>,
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
            compiled_host_whitelist_source: Arc::new(host_whitelist.clone()),
            compiled_host_blacklist_source: Arc::new(host_blacklist.clone()),
            host_whitelist,
            host_blacklist,
        })
    }

    pub fn is_host_allowed(&self, host: &str) -> bool {
        match self.compiled_host_rules() {
            Ok((whitelist, blacklist)) => is_host_allowed_with_rules(host, &whitelist, &blacklist),
            Err(err) => {
                tracing::warn!("failed to evaluate listener host filters: {}", err);
                false
            }
        }
    }

    pub fn is_process_allowed(&self, process_name: &str) -> bool {
        self.process_filter.is_process_allowed(process_name)
    }

    fn compiled_host_rules(&self) -> crate::Result<(Vec<HostRule>, Vec<HostRule>)> {
        let whitelist = if self.host_whitelist.is_empty() {
            Vec::new()
        } else if self.compiled_host_whitelist_source.as_ref() == &self.host_whitelist {
            (*self.compiled_host_whitelist).clone()
        } else {
            compile_host_rules(&self.host_whitelist).map_err(crate::Error::Config)?
        };

        let blacklist = if self.host_blacklist.is_empty() {
            Vec::new()
        } else if self.compiled_host_blacklist_source.as_ref() == &self.host_blacklist {
            (*self.compiled_host_blacklist).clone()
        } else {
            compile_host_rules(&self.host_blacklist).map_err(crate::Error::Config)?
        };

        Ok((whitelist, blacklist))
    }
}

/// Rate-limited connection logging deduplication.
///
/// Prevents log spam from repeated connections by tracking recently
/// logged connections within a time window.
pub struct ConnectionDedup {
    data: Mutex<(HashSet<String>, VecDeque<String>, Instant)>,
}

const MAX_CONNECTION_DEDUP_KEYS: usize = 16_384;
const CONNECTION_DEDUP_WINDOW: Duration = Duration::from_secs(60);

impl ConnectionDedup {
    pub fn new() -> Self {
        Self {
            data: Mutex::new((HashSet::new(), VecDeque::new(), Instant::now())),
        }
    }

    pub fn should_log(&self, key: &str) -> bool {
        let mut data = self.data.lock();
        let (seen, order, last_cleanup) = &mut *data;

        if last_cleanup.elapsed() > CONNECTION_DEDUP_WINDOW {
            seen.clear();
            order.clear();
            *last_cleanup = Instant::now();
        }

        if seen.contains(key) {
            return false;
        }

        if seen.len() >= MAX_CONNECTION_DEDUP_KEYS
            && let Some(evicted) = order.pop_front()
        {
            seen.remove(&evicted);
        }

        seen.insert(key.to_string());
        order.push_back(key.to_string());
        true
    }
}

impl Default for ConnectionDedup {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectionDedup, ListenerSecurity, MAX_CONNECTION_DEDUP_KEYS};
    use crate::process_filter::ProcessFilter;

    #[test]
    fn connection_dedup_bounds_keys_within_window() {
        let dedup = ConnectionDedup::new();

        for index in 0..MAX_CONNECTION_DEDUP_KEYS {
            assert!(dedup.should_log(&format!("http:192.0.2.{index}")));
        }

        assert!(dedup.should_log("http:198.51.100.1"));
        assert!(dedup.should_log("http:192.0.2.0"));
        assert!(!dedup.should_log("http:192.0.2.0"));
    }

    #[test]
    fn connection_dedup_evicts_oldest_key_without_clearing_all_entries() {
        let dedup = ConnectionDedup::new();

        for index in 0..MAX_CONNECTION_DEDUP_KEYS {
            assert!(dedup.should_log(&format!("http:192.0.2.{index}")));
        }

        assert!(dedup.should_log("http:198.51.100.1"));
        assert!(dedup.should_log("http:192.0.2.0"));
        assert!(!dedup.should_log("http:192.0.2.0"));
        assert!(dedup.should_log("http:192.0.2.1"));
        assert!(!dedup.should_log("http:192.0.2.1"));
    }

    #[test]
    fn runtime_allows_ipv4_mapped_loopback() {
        let security = ListenerSecurity::new(ProcessFilter::new(), Vec::new(), Vec::new())
            .expect("empty host rules should compile");

        assert!(security.is_host_allowed("::ffff:127.0.0.1"));
    }

    #[test]
    fn runtime_host_filter_semantics_are_consistent() {
        let security = ListenerSecurity::new(
            ProcessFilter::new(),
            vec!["10.0.0.1".to_string()],
            vec!["10.0.0.2".to_string()],
        )
        .expect("host rules should compile");

        assert!(!security.is_host_allowed("::ffff:127.0.0.1"));
        assert!(security.is_host_allowed("10.0.0.1"));
        assert!(!security.is_host_allowed("10.0.0.2"));
        assert!(!security.is_host_allowed("192.168.0.1"));
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
        let security = ListenerSecurity::new(
            ProcessFilter::new(),
            vec!["localhost".to_string()],
            Vec::new(),
        )
        .expect("localhost should resolve");

        assert!(security.is_host_allowed("127.0.0.1"));
    }

    #[test]
    fn runtime_recompiles_mutated_host_filters() {
        let mut security = ListenerSecurity::new(
            ProcessFilter::new(),
            vec!["10.0.0.0/8".to_string()],
            Vec::new(),
        )
        .expect("initial host rules should compile");

        assert!(security.is_host_allowed("10.1.2.3"));

        security.host_whitelist = vec!["192.168.0.0/16".to_string()];

        assert!(!security.is_host_allowed("10.1.2.3"));
        assert!(security.is_host_allowed("192.168.1.10"));
    }

    #[test]
    fn runtime_respects_blacklisted_loopback_hostname() {
        let security = ListenerSecurity::new(
            ProcessFilter::new(),
            Vec::new(),
            vec!["localhost".to_string()],
        )
        .expect("localhost blacklist should resolve");

        assert!(!security.is_host_allowed("127.0.0.1"));
        assert!(!security.is_host_allowed("::ffff:127.0.0.1"));
    }

    #[test]
    fn runtime_blacklist_overrides_matching_whitelist() {
        let security = ListenerSecurity::new(
            ProcessFilter::new(),
            vec!["localhost".to_string()],
            vec!["localhost".to_string()],
        )
        .expect("localhost rules should resolve");

        assert!(!security.is_host_allowed("127.0.0.1"));
        assert!(!security.is_host_allowed("::ffff:127.0.0.1"));
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
