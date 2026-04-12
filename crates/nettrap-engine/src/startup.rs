//! Startup context for engine initialization.

use std::path::PathBuf;
use std::sync::Arc;

/// Context created during engine startup.
///
/// Contains all shared resources needed by listeners and handlers:
/// - TLS certificate authority
/// - Protocol router
/// - Attribution engine
/// - PCAP writer
/// - NBI collector
/// - Session tracker
/// - Database connection
pub struct StartupContext {
    /// TLS certificate authority for MITM
    pub ca: Option<Arc<nettrap_tls_mitm::CertificateAuthority>>,
    /// Protocol router for taste detection
    pub router: Arc<nettrap_proxy::ProtocolRouter>,
    /// Attribution engine for process attribution
    pub attribution: Option<Arc<nettrap_attribution::AttributionEngine>>,
    /// PCAP writer for packet capture
    pub pcap_writer: Option<Arc<nettrap_pcap::PcapWriter>>,
    /// Output file path
    pub output_path: Option<PathBuf>,
    /// NBI output path
    pub nbi_path: Option<PathBuf>,
    /// HTTP POST dump directory
    pub http_post_dump_dir: Option<String>,
    /// Log hexdump flag
    pub log_hexdump: bool,
    /// Global process whitelist
    pub global_process_whitelist: Vec<String>,
    /// Global process blacklist
    pub global_process_blacklist: Vec<String>,
}

impl StartupContext {
    /// Create a minimal startup context for testing.
    pub fn minimal() -> Self {
        Self {
            ca: None,
            router: Arc::new(nettrap_proxy::ProtocolRouter::new()),
            attribution: None,
            pcap_writer: None,
            output_path: None,
            nbi_path: None,
            http_post_dump_dir: None,
            log_hexdump: false,
            global_process_whitelist: Vec::new(),
            global_process_blacklist: Vec::new(),
        }
    }
}
