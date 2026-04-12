//! Shutdown context for engine cleanup.

use std::path::PathBuf;
use std::sync::Arc;

/// Context created during engine shutdown.
///
/// Contains resources that need cleanup:
/// - NBI path for report generation
/// - PCAP writer for closing
/// - Database for stats and closing
pub struct ShutdownContext {
    /// Path to NBI JSONL file
    pub nbi_path: Option<PathBuf>,
    /// PCAP writer to close
    pub pcap_writer: Option<Arc<nettrap_pcap::PcapWriter>>,
}

impl ShutdownContext {
    /// Create a new shutdown context.
    pub fn new(
        nbi_path: Option<PathBuf>,
        pcap_writer: Option<Arc<nettrap_pcap::PcapWriter>>,
    ) -> Self {
        Self {
            nbi_path,
            pcap_writer,
        }
    }

    /// Create a minimal shutdown context for testing.
    pub fn minimal() -> Self {
        Self {
            nbi_path: None,
            pcap_writer: None,
        }
    }
}
