use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::collections::VecDeque;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::time::Duration;

use nettrap_core::prelude::{FiveTuple, Protocol};

mod port_forward;

pub use port_forward::PortForwardTable;
#[cfg(test)]
pub(crate) use port_forward::{OriginalDestinationQueue, RedirectFlowKey};

/// Default session time-to-live in seconds
const DEFAULT_SESSION_TTL_SECS: u64 = 3600; // 1 hour
/// Default cleanup interval in seconds
const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 300; // 5 minutes
/// Default maximum active sessions retained in memory.
const DEFAULT_MAX_SESSIONS: usize = 100_000;
const MAX_ORIGINAL_DESTINATION_FLOWS: usize = DEFAULT_MAX_SESSIONS;
const MAX_ORIGINAL_DESTINATIONS_PER_FLOW: usize = 64;

/// Tracks active network sessions for connection state management.
///
/// `SessionTracker` maintains a map of active connections identified by source IP,
/// source port, destination port, and protocol. It provides TTL-based automatic
/// cleanup of stale sessions and supports background cleanup tasks for long-running
/// processes.
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// let tracker = Arc::new(SessionTracker::new());
/// let addr: std::net::SocketAddr = "192.168.1.1:12345".parse().unwrap();
/// tracker.register(&addr, 80, "http", "TCP");
/// ```
pub struct SessionTracker {
    sessions: RwLock<HashMap<SessionKey, SessionInfo>>,
    session_ttl_secs: u64,
    last_cleanup: RwLock<std::time::Instant>,
    cleanup_interval_secs: u64,
    max_sessions: usize,
}

/// Unique identifier for a network session.
///
/// Sessions are keyed by the combination of source IP, source port, destination
/// port, and protocol to distinguish between different connections from the same
/// client.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize)]
pub struct SessionKey {
    /// Source IP address as string (e.g., "192.168.1.1")
    src_ip: String,
    /// Source port number
    src_port: u16,
    /// Destination IP address as string (e.g., "10.0.0.5")
    dst_ip: String,
    /// Destination port number
    dst_port: u16,
    /// Protocol name (e.g., "TCP", "UDP")
    protocol: String,
}

#[derive(Deserialize)]
struct SessionKeySerde {
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    protocol: String,
}

impl SessionKey {
    pub fn src_ip(&self) -> &str {
        &self.src_ip
    }

    pub fn src_port(&self) -> u16 {
        self.src_port
    }

    pub fn dst_ip(&self) -> &str {
        &self.dst_ip
    }

    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }

    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    pub fn to_five_tuple(&self) -> Option<FiveTuple> {
        let protocol = match self.protocol.as_str() {
            value if value.eq_ignore_ascii_case("TCP") => Protocol::Tcp,
            value if value.eq_ignore_ascii_case("UDP") => Protocol::Udp,
            _ => return None,
        };

        Some(FiveTuple::new(
            parse_normalized_session_ip(&self.src_ip)?,
            parse_normalized_session_ip(&self.dst_ip)?,
            self.src_port,
            self.dst_port,
            protocol,
        ))
    }
}

impl<'de> Deserialize<'de> for SessionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = SessionKeySerde::deserialize(deserializer)?;
        let src_ip = helper.src_ip.parse::<std::net::IpAddr>().map_err(|err| {
            serde::de::Error::custom(format!(
                "invalid session source IP '{}': {}",
                helper.src_ip, err
            ))
        })?;
        let dst_ip = helper.dst_ip.parse::<std::net::IpAddr>().map_err(|err| {
            serde::de::Error::custom(format!(
                "invalid session destination IP '{}': {}",
                helper.dst_ip, err
            ))
        })?;
        let protocol =
            parse_session_protocol(&helper.protocol).map_err(serde::de::Error::custom)?;
        Ok(Self {
            src_ip: normalize_session_ip(src_ip).to_string(),
            src_port: helper.src_port,
            dst_ip: normalize_session_ip(dst_ip).to_string(),
            dst_port: helper.dst_port,
            protocol,
        })
    }
}

/// Resolved destination used to identify a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionDestination {
    ip: String,
    port: u16,
}

impl SessionDestination {
    pub fn new(ip: impl Into<String>, port: u16) -> crate::Result<Self> {
        let ip = ip.into();
        let Some(ip) = parse_normalized_session_ip(&ip) else {
            return Err(crate::Error::Other(format!(
                "invalid session destination IP '{}'",
                ip
            )));
        };

        Ok(Self {
            ip: ip.to_string(),
            port,
        })
    }

    pub(crate) fn new_unchecked(ip: impl Into<String>, port: u16) -> Self {
        Self {
            ip: ip.into(),
            port,
        }
    }

    #[cfg(test)]
    pub(crate) fn unknown(port: u16) -> Self {
        Self {
            ip: std::net::Ipv4Addr::UNSPECIFIED.to_string(),
            port,
        }
    }

    pub fn ip(&self) -> &str {
        &self.ip
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Deserialize)]
struct SessionDestinationSerde {
    ip: String,
    port: u16,
}

impl<'de> Deserialize<'de> for SessionDestination {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = SessionDestinationSerde::deserialize(deserializer)?;
        Self::new(helper.ip, helper.port).map_err(serde::de::Error::custom)
    }
}

/// Metadata for an active network session.
///
/// Contains connection details, attribution information (process name/PID),
/// timing data, and traffic statistics.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Destination IP address
    pub dst_ip: String,
    /// Destination port number
    pub dst_port: u16,
    /// Name of the listener that created this session
    pub listener: String,
    /// Process name attributed to this connection (if available)
    pub process_name: Option<String>,
    /// Process PID attributed to this connection (if available)
    pub process_pid: Option<u32>,
    /// ISO 8601 timestamp when session was created
    pub started_at: String,
    /// Last activity timestamp (used for TTL expiration)
    pub last_activity: std::time::Instant,
    /// Total bytes sent by the client
    pub bytes_sent: u64,
    /// Total bytes received by the client
    pub bytes_received: u64,
    /// Packet count
    pub packets: u64,
}

impl SessionTracker {
    fn session_key(
        src: &SocketAddr,
        destination: &SessionDestination,
        protocol: &str,
    ) -> SessionKey {
        SessionKey {
            src_ip: normalize_session_ip(src.ip()).to_string(),
            src_port: src.port(),
            dst_ip: normalize_session_destination_ip_for_peer(src, destination.ip()),
            dst_port: destination.port(),
            protocol: normalize_session_protocol(protocol),
        }
    }

    /// Creates a new session tracker with default TTL (1 hour).
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            last_cleanup: RwLock::new(std::time::Instant::now()),
            cleanup_interval_secs: DEFAULT_CLEANUP_INTERVAL_SECS,
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }

    pub fn ttl(&self) -> Duration {
        Duration::from_secs(self.session_ttl_secs)
    }

    pub fn cleanup_interval(&self) -> Duration {
        Duration::from_secs(self.cleanup_interval_secs)
    }

    /// Registers a new connection or updates an existing one.
    ///
    /// Returns `true` if this is a new session, `false` if updating an existing session.
    /// Automatically triggers cleanup of expired sessions periodically.
    ///
    /// # Arguments
    ///
    /// * `src` - Source socket address of the connection
    /// * `dst_port` - Destination port (listener port)
    /// * `listener` - Name of the listener handling this connection
    /// * `protocol` - Protocol name (e.g., "TCP", "UDP")
    pub fn register(
        &self,
        src: &SocketAddr,
        destination: &SessionDestination,
        listener: &str,
        protocol: &str,
    ) -> bool {
        let key = Self::session_key(src, destination, protocol);
        let now = std::time::Instant::now();

        let needs_cleanup =
            self.last_cleanup.read().elapsed() > Duration::from_secs(self.cleanup_interval_secs);

        let mut sessions = self.sessions.write();

        if needs_cleanup {
            let mut last = self.last_cleanup.write();
            if last.elapsed() > Duration::from_secs(self.cleanup_interval_secs) {
                self.cleanup_expired_keys(&mut sessions);
                *last = std::time::Instant::now();
            }
        }

        let expired = sessions
            .get(&key)
            .is_some_and(|session| now.duration_since(session.last_activity) >= self.ttl());

        if expired {
            sessions.remove(&key);
        } else if let Some(session) = sessions.get_mut(&key) {
            session.listener = listener.to_string();
            session.last_activity = now;
            return false;
        }

        Self::enforce_session_capacity(&mut sessions, self.max_sessions);
        sessions.insert(
            key,
            SessionInfo {
                dst_ip: normalize_session_destination_ip_for_peer(src, destination.ip()),
                dst_port: destination.port(),
                listener: listener.to_string(),
                process_name: None,
                process_pid: None,
                started_at: crate::faketime::fake_now().to_rfc3339(),
                last_activity: now,
                bytes_sent: 0,
                bytes_received: 0,
                packets: 0,
            },
        );
        true
    }

    fn enforce_session_capacity(
        sessions: &mut HashMap<SessionKey, SessionInfo>,
        max_sessions: usize,
    ) {
        if max_sessions == 0 || sessions.len() < max_sessions {
            return;
        }

        let Some(oldest_key) = sessions
            .iter()
            .min_by_key(|(_, info)| info.last_activity)
            .map(|(key, _)| key.clone())
        else {
            return;
        };

        sessions.remove(&oldest_key);
        tracing::warn!(
            "Session tracker capacity {} reached; evicted oldest {} session {}:{} -> {}:{}",
            max_sessions,
            oldest_key.protocol(),
            oldest_key.src_ip(),
            oldest_key.src_port(),
            oldest_key.dst_ip(),
            oldest_key.dst_port()
        );
    }

    /// Removes expired sessions from the tracker.
    ///
    /// Sessions that have not had activity for longer than `session_ttl_secs` are removed.
    fn cleanup_expired_keys(
        &self,
        sessions: &mut HashMap<SessionKey, SessionInfo>,
    ) -> Vec<SessionKey> {
        let now = std::time::Instant::now();
        let ttl = Duration::from_secs(self.session_ttl_secs);
        let mut expired = Vec::new();
        sessions.retain(|key, info| {
            let keep = now.duration_since(info.last_activity) < ttl;
            if !keep {
                expired.push(key.clone());
            }
            keep
        });
        let removed = expired.len();
        if removed > 0 {
            tracing::debug!("Cleaned up {} expired sessions", removed);
        }
        expired
    }

    /// Forces immediate cleanup and returns the expired session keys.
    pub fn cleanup_expired_sessions(&self) -> Vec<SessionKey> {
        let mut sessions = self.sessions.write();
        self.cleanup_expired_keys(&mut sessions)
    }

    /// Updates byte counters for a session.
    ///
    /// If the session does not exist, this is a no-op.
    ///
    /// # Arguments
    ///
    /// * `src` - Source socket address
    /// * `protocol` - Protocol name (e.g., "TCP", "UDP")
    /// * `received` - Bytes received from the client
    /// * `sent` - Bytes sent to the client
    pub fn update_bytes(
        &self,
        src: &SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
        received: u64,
        sent: u64,
    ) {
        let key = Self::session_key(src, destination, protocol);
        let now = std::time::Instant::now();

        let mut sessions = self.sessions.write();
        let expired = sessions
            .get(&key)
            .is_some_and(|session| now.duration_since(session.last_activity) >= self.ttl());

        if expired {
            sessions.remove(&key);
            return;
        }

        if let Some(session) = sessions.get_mut(&key) {
            session.bytes_received = session.bytes_received.saturating_add(received);
            session.bytes_sent = session.bytes_sent.saturating_add(sent);
            session.packets = session.packets.saturating_add(1);
            session.last_activity = now;
        }
    }

    /// Sets process attribution for a session.
    ///
    /// Used to associate a connection with the process that initiated it.
    pub fn set_process(
        &self,
        src: &SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
        name: Option<String>,
        pid: Option<u32>,
    ) {
        let key = Self::session_key(src, destination, protocol);
        let now = std::time::Instant::now();

        let mut sessions = self.sessions.write();
        let expired = sessions
            .get(&key)
            .is_some_and(|session| now.duration_since(session.last_activity) >= self.ttl());

        if expired {
            sessions.remove(&key);
            return;
        }

        if let Some(session) = sessions.get_mut(&key) {
            session.process_name = normalize_optional_process_name(name);
            session.process_pid = pid;
        }
    }

    /// Gets process attribution for a session if it exists.
    pub fn get_process(
        &self,
        src: &SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
    ) -> Option<(Option<String>, Option<u32>)> {
        let _ = self.cleanup_expired_sessions();
        let key = Self::session_key(src, destination, protocol);

        self.sessions
            .read()
            .get(&key)
            .map(|session| (session.process_name.clone(), session.process_pid))
    }

    /// Gets the unique destination for a source/protocol/port combination.
    ///
    /// Returns `None` when no session matches or the lookup would be ambiguous
    /// across multiple destination IPs.
    pub fn get_destination_for_port(
        &self,
        src: &SocketAddr,
        protocol: &str,
        dst_port: u16,
    ) -> Option<SessionDestination> {
        let _ = self.cleanup_expired_sessions();
        let sessions = self.sessions.read();
        let protocol = normalize_session_protocol(protocol);
        let mut matches = sessions.iter().filter(|(key, _)| {
            key.src_ip() == normalize_session_ip(src.ip()).to_string()
                && key.src_port() == src.port()
                && key.protocol() == protocol
                && key.dst_port() == dst_port
        });

        let (_, session) = matches.next()?;
        if matches.next().is_some() {
            return None;
        }

        Some(SessionDestination::new_unchecked(
            session.dst_ip.clone(),
            session.dst_port,
        ))
    }

    /// Removes a session from the tracker.
    ///
    /// Typically called when a connection is closed.
    pub fn remove(&self, src: &SocketAddr, protocol: &str, destination: &SessionDestination) {
        let key = Self::session_key(src, destination, protocol);
        self.sessions.write().remove(&key);
    }

    /// Returns the number of currently active sessions.
    pub fn active_count(&self) -> usize {
        let _ = self.cleanup_expired_sessions();
        self.sessions.read().len()
    }

    /// Gets the original destination (IP, port) for a session.
    ///
    /// Used when a connection was redirected and you need to know where it was
    /// originally headed.
    pub fn get_original_dest(
        &self,
        src: &SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
    ) -> Option<(String, u16)> {
        let _ = self.cleanup_expired_sessions();
        let key = Self::session_key(src, destination, protocol);
        self.sessions
            .read()
            .get(&key)
            .map(|s| (s.dst_ip.clone(), s.dst_port))
    }

    /// Exports all sessions as a JSON string.
    ///
    /// The export excludes the `last_activity` Instant field which cannot be serialized.
    pub fn export_sessions(&self) -> crate::Result<String> {
        let _ = self.cleanup_expired_sessions();
        let sessions = self.sessions.read();
        let export: BTreeMap<String, SessionInfoExport> = sessions
            .iter()
            .map(|(k, v)| {
                (
                    format!(
                        "{}:{}->{}:{}/{}",
                        k.src_ip, k.src_port, k.dst_ip, k.dst_port, k.protocol
                    ),
                    SessionInfoExport {
                        dst_ip: v.dst_ip.clone(),
                        dst_port: v.dst_port,
                        listener: v.listener.clone(),
                        process_name: v.process_name.clone(),
                        process_pid: v.process_pid,
                        started_at: v.started_at.clone(),
                        bytes_sent: v.bytes_sent,
                        bytes_received: v.bytes_received,
                        packets: v.packets,
                    },
                )
            })
            .collect();
        serde_json::to_string_pretty(&export)
            .map_err(|e| crate::Error::Other(format!("failed to serialize sessions: {}", e)))
    }
}

fn normalize_session_destination_ip_for_peer(peer: &SocketAddr, ip: &str) -> String {
    parse_normalized_session_ip(ip)
        .map(|normalized| normalized.to_string())
        .unwrap_or_else(|| unknown_session_destination_ip_for_peer(peer))
}

fn unknown_session_destination_ip_for_peer(peer: &SocketAddr) -> String {
    match normalize_session_ip(peer.ip()) {
        std::net::IpAddr::V4(_) => std::net::Ipv4Addr::UNSPECIFIED.to_string(),
        std::net::IpAddr::V6(_) => std::net::Ipv6Addr::UNSPECIFIED.to_string(),
    }
}

fn parse_session_protocol(protocol: &str) -> Result<String, String> {
    let protocol = protocol.trim_matches([' ', '\t']);
    if protocol.eq_ignore_ascii_case("TCP") {
        Ok("TCP".to_string())
    } else if protocol.eq_ignore_ascii_case("UDP") {
        Ok("UDP".to_string())
    } else {
        Err(format!(
            "invalid session protocol '{}': expected TCP or UDP",
            protocol
        ))
    }
}

pub(crate) fn normalize_session_protocol(protocol: &str) -> String {
    let protocol = protocol.trim_matches([' ', '\t']);
    if protocol.eq_ignore_ascii_case("TCP") {
        "TCP".to_string()
    } else if protocol.eq_ignore_ascii_case("UDP") {
        "UDP".to_string()
    } else {
        protocol.to_string()
    }
}

fn normalize_optional_process_name(name: Option<String>) -> Option<String> {
    name.and_then(|name| {
        let name = nettrap_core::sanitize::single_line(&name);
        if name.trim().is_empty() {
            None
        } else {
            Some(name)
        }
    })
}

fn parse_normalized_session_ip(ip: &str) -> Option<std::net::IpAddr> {
    let ip = ip.parse::<std::net::IpAddr>().ok()?;
    Some(normalize_session_ip(ip))
}

pub(crate) fn normalize_session_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V4(ip) => std::net::IpAddr::V4(ip),
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(ip), std::net::IpAddr::V4),
    }
}

pub(crate) fn is_usable_session_destination_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
        }
        std::net::IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_usable_session_destination_ip(std::net::IpAddr::V4(mapped));
            }

            !ip.is_unspecified() && !ip.is_multicast()
        }
    }
}

/// Serializable version of SessionInfo without Instant field.
///
/// Used for JSON export since `std::time::Instant` cannot be serialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionInfoExport {
    dst_ip: String,
    dst_port: u16,
    listener: String,
    process_name: Option<String>,
    process_pid: Option<u32>,
    started_at: String,
    bytes_sent: u64,
    bytes_received: u64,
    packets: u64,
}

impl Default for SessionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
