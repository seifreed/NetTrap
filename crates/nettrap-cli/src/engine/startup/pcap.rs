use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::EngineConfig;

static DEFAULT_PCAP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(super) fn init_pcap_writer(
    config: &EngineConfig,
    pcap_override: Option<&Path>,
) -> crate::Result<Option<Arc<nettrap_pcap::PcapWriter>>> {
    if !config.pcap_enabled {
        return Ok(None);
    }

    config.validate_runtime_file_prefixes()?;

    let path = if let Some(path) = pcap_override {
        path.to_path_buf()
    } else if let Some(path) = config.pcap_path.as_deref() {
        PathBuf::from(path)
    } else {
        let prefix = config
            .pcap_prefix
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("packets");
        default_pcap_path(prefix)
    };

    let writer =
        Arc::new(nettrap_pcap::PcapWriter::new(&path)?.with_now(crate::faketime::fake_now));
    writer
        .open()
        .map_err(|e| crate::Error::Other(format!("PCAP open failed: {}", e)))?;
    tracing::info!("PCAP recording to {}", path.display());

    Ok(Some(writer))
}

pub(super) fn default_pcap_path(prefix: &str) -> PathBuf {
    let seq = DEFAULT_PCAP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nonce = uuid::Uuid::new_v4();
    PathBuf::from(format!("{}_{}_{}_{}.pcap", prefix, pid, nonce, seq))
}
