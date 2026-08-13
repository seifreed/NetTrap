//! Distributed deployment support for NetTrap.
//! All features are optional — standalone mode requires zero distributed config.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

mod fanout;
mod probe;
mod sinks;

pub use fanout::{EventFanout, FanoutSendOutcome, SendCompletion, build_event_fanout};
pub use probe::{
    bind_health_server, bind_metrics_server, run_health_server, run_metrics_server,
    serve_health_server, serve_metrics_server,
};
pub use sinks::{HttpSink, SyslogUdpSink, TcpSink};

/// Error type for the distributed subsystem.
///
/// Variant `Display` output is byte-identical to the binary crate's former
/// `Error` so existing call sites that format these errors keep producing the
/// exact same text.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Config(String),
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::Config(s) => write!(f, "Config error: {}", s),
            Error::Other(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

const HEARTBEAT_FAILURE_LIMIT: u32 = 3;
const HEARTBEAT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const DISTRIBUTED_EXPORT_FAILURE_LIMIT: u32 = 3;
pub(crate) const HTTP_SINK_MAX_BUFFERED_EVENTS: usize = 1024;
pub(crate) const HTTP_SINK_MAX_EVENT_BYTES: usize = 1024 * 1024;
pub(crate) const TCP_SINK_MAX_EVENT_BYTES: usize = 1024 * 1024;
pub(crate) const SYSLOG_UDP_MAX_DATAGRAM_BYTES: usize = 8192;
const MACHINE_ID_READ_LIMIT_BYTES: u64 = 4096;

/// Unique identity for this NetTrap node in a distributed fleet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub node_id: String,
    pub hostname: String,
    pub region: String,
    pub tags: Vec<String>,
    pub started_at: String,
}

impl NodeIdentity {
    pub fn generate(node_id: Option<String>, region: Option<String>, tags: Vec<String>) -> Self {
        Self::generate_with_now(node_id, region, tags, chrono::Utc::now)
    }

    pub fn generate_with_now(
        node_id: Option<String>,
        region: Option<String>,
        tags: Vec<String>,
        now: fn() -> chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let hostname = hostname::get()
            .ok()
            .as_deref()
            .map(resolve_hostname_label)
            .unwrap_or_else(|| "unknown".to_string());
        let effective_node_id = resolve_node_id(node_id, Some(hostname.as_str()));
        Self {
            node_id: effective_node_id,
            hostname,
            region: normalize_region(region),
            tags,
            started_at: now().to_rfc3339(),
        }
    }
}

fn resolve_node_id(configured: Option<String>, hostname: Option<&str>) -> String {
    if let Some(configured) = configured
        .as_deref()
        .and_then(normalize_fingerprint_component)
    {
        return configured.to_ascii_lowercase();
    }

    if let Some(hostname) = hostname.and_then(normalize_hostname_component)
        && hostname != "unknown"
    {
        return hostname.to_ascii_lowercase();
    }

    stable_machine_fingerprint()
}

fn resolve_hostname_label(hostname: &std::ffi::OsStr) -> String {
    hostname
        .to_str()
        .and_then(normalize_hostname_component)
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| "unknown".to_string())
}

fn normalize_hostname_component(value: &str) -> Option<&str> {
    let normalized = normalize_fingerprint_component(value)?;
    if let Some(normalized) = normalized.strip_suffix('.') {
        if normalized.is_empty() || normalized.ends_with('.') {
            return None;
        }
        Some(normalized)
    } else {
        Some(normalized)
    }
}

fn normalize_region(region: Option<String>) -> String {
    region
        .as_deref()
        .map(|value| value.trim_matches([' ', '\t']))
        .filter(|region| {
            !region.is_empty()
                && !region
                    .chars()
                    .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
        })
        .map(str::to_string)
        .unwrap_or_else(|| "default".to_string())
}

fn stable_machine_fingerprint() -> String {
    let mut candidates = Vec::new();

    for key in [
        "COMPUTERNAME",
        "HOSTNAME",
        "USER",
        "USERNAME",
        "HOME",
        "USERPROFILE",
    ] {
        if let Ok(value) = std::env::var(key)
            && let Some(trimmed) = normalize_fingerprint_component(&value)
        {
            candidates.push(format!("{key}={trimmed}"));
        }
    }

    for path in [
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
        "/sys/class/dmi/id/product_uuid",
    ] {
        if let Ok(value) = read_machine_id_file(path, MACHINE_ID_READ_LIMIT_BYTES)
            && let Some(trimmed) = normalize_fingerprint_component(&value)
        {
            candidates.push(format!("{path}={trimmed}"));
        }
    }

    if candidates.is_empty()
        && let Ok(exe) = std::env::current_exe()
    {
        candidates.push(format!("exe={}", exe.display()));
    }

    let seed = if candidates.is_empty() {
        "nettrap-fallback-machine-fingerprint".to_string()
    } else {
        candidates.join("|")
    };

    let mut hash = 0xcbf29ce484222325u64;
    for byte in seed.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }

    format!("node-{hash:016x}")
}

fn read_machine_id_file(
    path: impl AsRef<std::path::Path>,
    max_bytes: u64,
) -> std::io::Result<String> {
    use std::io::Read;

    let file = std::fs::File::open(path)?;
    let sentinel_limit = max_bytes.checked_add(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "machine identity file read limit is too large",
        )
    })?;
    let mut limited = file.take(sentinel_limit);
    let mut content = String::new();
    limited.read_to_string(&mut content)?;
    if content.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "machine identity file exceeds read limit ({} > {} bytes)",
                content.len(),
                max_bytes
            ),
        ));
    }
    Ok(content)
}

/// Trait for shipping events to external systems
#[async_trait::async_trait]
pub trait EventSink: Send + Sync {
    async fn send(&self, event: &nettrap_core::NetworkBehaviorIndicator) -> SinkSendResult;
    async fn flush(&self) -> std::result::Result<(), String>;
    async fn flush_stale(&self) -> std::result::Result<bool, String> {
        Ok(false)
    }
    fn name(&self) -> &'static str;
    fn buffered_events(&self) -> usize {
        0
    }

    fn buffered_event_ids(&self) -> Vec<String> {
        Vec::new()
    }

    fn drop_buffered_events(&self, _event_ids: &HashSet<String>) -> usize {
        0
    }

    fn take_unknown_event_ids(&self) -> Vec<String> {
        Vec::new()
    }
}

fn normalize_fingerprint_component(value: &str) -> Option<&str> {
    let trimmed = value.trim_matches([' ', '\t']);
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|ch| ch.is_control() || (ch.is_whitespace() && ch != ' '))
    {
        None
    } else {
        Some(trimmed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkDeliveryState {
    Delivered,
    Buffered,
    Lost,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct SinkSendResult {
    pub state: SinkDeliveryState,
    pub error: Option<String>,
}

impl SinkSendResult {
    pub fn delivered() -> Self {
        Self {
            state: SinkDeliveryState::Delivered,
            error: None,
        }
    }

    pub fn buffered(error: Option<String>) -> Self {
        Self {
            state: SinkDeliveryState::Buffered,
            error,
        }
    }

    pub fn lost(error: impl Into<String>) -> Self {
        Self {
            state: SinkDeliveryState::Lost,
            error: Some(error.into()),
        }
    }

    pub fn unknown(error: impl Into<String>) -> Self {
        Self {
            state: SinkDeliveryState::Unknown,
            error: Some(error.into()),
        }
    }
}

/// Periodically sends heartbeat to control plane
pub async fn run_heartbeat(
    control_url: String,
    token: Option<String>,
    node: Arc<NodeIdentity>,
    interval_secs: u64,
) -> Result<()> {
    run_heartbeat_with_now(control_url, token, node, interval_secs, chrono::Utc::now).await
}

pub async fn run_heartbeat_with_now(
    control_url: String,
    token: Option<String>,
    node: Arc<NodeIdentity>,
    interval_secs: u64,
    now: fn() -> chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    if interval_secs == 0 {
        return Ok(());
    }

    run_heartbeat_with_interval(
        control_url,
        token,
        node,
        std::time::Duration::from_secs(interval_secs),
        HEARTBEAT_FAILURE_LIMIT,
        HEARTBEAT_REQUEST_TIMEOUT,
        now,
    )
    .await
}

async fn run_heartbeat_with_interval(
    control_url: String,
    token: Option<String>,
    node: Arc<NodeIdentity>,
    interval: std::time::Duration,
    failure_limit: u32,
    request_timeout: std::time::Duration,
    now: fn() -> chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let client = reqwest::Client::new();
    let url = heartbeat_endpoint_url(&control_url)?;
    let mut consecutive_failures = 0u32;

    loop {
        let payload = heartbeat_payload(&node, now);

        let mut req = client.post(url.clone()).json(&payload);
        if let Some(ref t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }

        match tokio::time::timeout(request_timeout, req.send()).await {
            Err(_) => {
                consecutive_failures += 1;
                let message = format!(
                    "Control plane heartbeat timed out ({}/{}): waited {:?}",
                    consecutive_failures, failure_limit, request_timeout
                );
                tracing::warn!("{}", message);
                if consecutive_failures >= failure_limit {
                    return Err(Error::Other(format!(
                        "Control plane heartbeat failed {} consecutive times: request timed out after {:?}",
                        failure_limit, request_timeout
                    )));
                }
            }
            Ok(Ok(resp)) if resp.status().is_success() => {
                consecutive_failures = 0;
                tracing::debug!("Heartbeat sent to control plane");
            }
            Ok(Ok(resp)) => {
                consecutive_failures += 1;
                let message = format!(
                    "Control plane heartbeat rejected ({}/{}): {}",
                    consecutive_failures,
                    failure_limit,
                    resp.status()
                );
                tracing::warn!("{}", message);
                if consecutive_failures >= failure_limit {
                    return Err(Error::Other(format!(
                        "Control plane heartbeat failed {} consecutive times: {}",
                        failure_limit,
                        resp.status()
                    )));
                }
            }
            Ok(Err(e)) => {
                consecutive_failures += 1;
                let message = format!(
                    "Control plane heartbeat failed ({}/{}): {}",
                    consecutive_failures, failure_limit, e
                );
                tracing::warn!("{}", message);
                if consecutive_failures >= failure_limit {
                    return Err(Error::Other(format!(
                        "Control plane heartbeat failed {} consecutive times: {}",
                        failure_limit, e
                    )));
                }
            }
        }

        tokio::time::sleep(interval).await;
    }
}

fn heartbeat_payload(
    node: &NodeIdentity,
    now: fn() -> chrono::DateTime<chrono::Utc>,
) -> serde_json::Value {
    serde_json::json!({
        "node_id": node.node_id,
        "hostname": node.hostname,
        "region": node.region,
        "tags": node.tags,
        "timestamp": now().to_rfc3339(),
    })
}

fn heartbeat_endpoint_url(control_url: &str) -> Result<reqwest::Url> {
    let mut base = reqwest::Url::parse(control_url).map_err(|err| {
        Error::Config(format!(
            "invalid control plane URL '{}': {}",
            control_url, err
        ))
    })?;
    if !matches!(base.scheme(), "http" | "https") {
        return Err(Error::Config(format!(
            "invalid control plane URL '{}': unsupported scheme '{}'",
            control_url,
            base.scheme()
        )));
    }
    if !base.path().ends_with('/') {
        let mut path = base.path().to_string();
        path.push('/');
        base.set_path(&path);
    }
    base.join("api/v1/heartbeat").map_err(|err| {
        Error::Config(format!(
            "failed to build heartbeat endpoint from '{}': {}",
            control_url, err
        ))
    })
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
