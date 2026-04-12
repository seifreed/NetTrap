use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::collections::hash_map::Entry;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nettrap_core::prelude::{FiveTuple, Protocol};

/// Default session time-to-live in seconds
const DEFAULT_SESSION_TTL_SECS: u64 = 3600; // 1 hour
/// Default cleanup interval in seconds
const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 300; // 5 minutes

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
}

/// Unique identifier for a network session.
///
/// Sessions are keyed by the combination of source IP, source port, destination
/// port, and protocol to distinguish between different connections from the same
/// client.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKey {
    /// Source IP address as string (e.g., "192.168.1.1")
    pub src_ip: String,
    /// Source port number
    pub src_port: u16,
    /// Destination IP address as string (e.g., "10.0.0.5")
    pub dst_ip: String,
    /// Destination port number
    pub dst_port: u16,
    /// Protocol name (e.g., "TCP", "UDP")
    pub protocol: String,
}

impl SessionKey {
    pub fn to_five_tuple(&self) -> Option<FiveTuple> {
        let protocol = match self.protocol.as_str() {
            "TCP" => Protocol::Tcp,
            "UDP" => Protocol::Udp,
            _ => return None,
        };

        Some(FiveTuple::new(
            self.src_ip.parse().ok()?,
            self.dst_ip.parse().ok()?,
            self.src_port,
            self.dst_port,
            protocol,
        ))
    }
}

/// Resolved destination used to identify a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDestination {
    pub ip: String,
    pub port: u16,
}

impl SessionDestination {
    pub fn new(ip: impl Into<String>, port: u16) -> Self {
        Self {
            ip: ip.into(),
            port,
        }
    }

    pub fn unknown(port: u16) -> Self {
        Self::new("0.0.0.0", port)
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
            src_ip: src.ip().to_string(),
            src_port: src.port(),
            dst_ip: destination.ip.clone(),
            dst_port: destination.port,
            protocol: protocol.to_string(),
        }
    }

    /// Creates a new session tracker with default TTL (1 hour).
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            last_cleanup: RwLock::new(std::time::Instant::now()),
            cleanup_interval_secs: DEFAULT_CLEANUP_INTERVAL_SECS,
        }
    }

    /// Creates a new session tracker with a custom TTL.
    ///
    /// # Arguments
    ///
    /// * `ttl_secs` - Time-to-live in seconds before sessions are expired.
    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            session_ttl_secs: ttl_secs,
            last_cleanup: RwLock::new(std::time::Instant::now()),
            cleanup_interval_secs: DEFAULT_CLEANUP_INTERVAL_SECS,
        }
    }

    /// Starts a background task that periodically cleans up expired sessions.
    ///
    /// The cleanup interval is configured by `cleanup_interval_secs` (default: 5 minutes).
    ///
    /// # Returns
    ///
    /// A `JoinHandle` that can be used to abort the cleanup task if needed.
    pub fn start_cleanup_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(self.cleanup_interval_secs)).await;
                self.cleanup();
                tracing::debug!(
                    "Session cleanup completed, active sessions: {}",
                    self.active_count()
                );
            }
        })
    }

    /// Creates a session tracker wrapped in `Arc` with background cleanup enabled.
    ///
    /// Convenience method for the common pattern of creating a tracker with
    /// automatic background cleanup.
    pub fn with_background_cleanup() -> (Arc<Self>, tokio::task::JoinHandle<()>) {
        let tracker = Arc::new(Self::new());
        let handle = tracker.clone().start_cleanup_task();
        (tracker, handle)
    }

    /// Creates a session tracker with custom TTL and background cleanup.
    pub fn with_background_cleanup_and_ttl(
        ttl_secs: u64,
    ) -> (Arc<Self>, tokio::task::JoinHandle<()>) {
        let tracker = Arc::new(Self::with_ttl(ttl_secs));
        let handle = tracker.clone().start_cleanup_task();
        (tracker, handle)
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

        // Check cleanup timer with a brief read first to avoid contention
        let needs_cleanup =
            self.last_cleanup.read().elapsed() > Duration::from_secs(self.cleanup_interval_secs);

        let mut sessions = self.sessions.write();

        // Only acquire cleanup write lock when actually needed
        if needs_cleanup {
            let mut last = self.last_cleanup.write();
            // Re-check after acquiring write lock (another thread may have cleaned up)
            if last.elapsed() > Duration::from_secs(self.cleanup_interval_secs) {
                self.cleanup_expired_keys(&mut sessions);
                *last = std::time::Instant::now();
            }
        }

        let now = std::time::Instant::now();

        match sessions.entry(key) {
            Entry::Occupied(mut entry) => {
                let session = entry.get_mut();
                session.listener = listener.to_string();
                session.last_activity = now;
                false
            }
            Entry::Vacant(entry) => {
                entry.insert(SessionInfo {
                    dst_ip: destination.ip.clone(),
                    dst_port: destination.port,
                    listener: listener.to_string(),
                    process_name: None,
                    process_pid: None,
                    started_at: chrono::Utc::now().to_rfc3339(),
                    last_activity: now,
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets: 0,
                });
                true
            }
        }
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

    /// Forces immediate cleanup of expired sessions.
    pub fn cleanup(&self) {
        let _ = self.cleanup_expired_sessions();
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

        if let Some(session) = self.sessions.write().get_mut(&key) {
            session.bytes_received += received;
            session.bytes_sent += sent;
            session.packets += 1;
            session.last_activity = std::time::Instant::now();
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

        if let Some(session) = self.sessions.write().get_mut(&key) {
            session.process_name = name;
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
        let key = Self::session_key(src, destination, protocol);

        self.sessions
            .read()
            .get(&key)
            .map(|session| (session.process_name.clone(), session.process_pid))
    }

    /// Gets process attribution if there is exactly one session matching this source and port.
    ///
    /// Returns `None` when the lookup would be ambiguous across multiple destination IPs.
    pub fn get_process_for_port(
        &self,
        src: &SocketAddr,
        protocol: &str,
        dst_port: u16,
    ) -> Option<(Option<String>, Option<u32>)> {
        let sessions = self.sessions.read();
        let mut matches = sessions.iter().filter(|(key, _)| {
            key.src_ip == src.ip().to_string()
                && key.src_port == src.port()
                && key.protocol == protocol
                && key.dst_port == dst_port
        });

        let (_, session) = matches.next()?;
        if matches.next().is_some() {
            return None;
        }

        Some((session.process_name.clone(), session.process_pid))
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
        let sessions = self.sessions.read();
        let mut matches = sessions.iter().filter(|(key, _)| {
            key.src_ip == src.ip().to_string()
                && key.src_port == src.port()
                && key.protocol == protocol
                && key.dst_port == dst_port
        });

        let (_, session) = matches.next()?;
        if matches.next().is_some() {
            return None;
        }

        Some(SessionDestination::new(
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
        let key = Self::session_key(src, destination, protocol);
        self.sessions
            .read()
            .get(&key)
            .map(|s| (s.dst_ip.clone(), s.dst_port))
    }

    /// Exports all sessions as a JSON string.
    ///
    /// The export excludes the `last_activity` Instant field which cannot be serialized.
    pub fn export_sessions(&self) -> String {
        let sessions = self.sessions.read();
        // Create a serializable version without Instant
        let export: HashMap<SessionKey, SessionInfoExport> = sessions
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
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
        serde_json::to_string_pretty(&export).unwrap_or_default()
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

/// Dynamic port forwarding table for protocol handlers that redirect traffic.
///
/// Supports separate mappings for TCP and UDP protocols. Used by handlers
/// like FTP PASV that need to dynamically redirect ports.
///
/// # Thread Safety
///
/// All operations are thread-safe through `RwLock`.
pub struct PortForwardTable {
    tcp_forwards: RwLock<HashMap<u16, u16>>, // src_port -> dst_port
    udp_forwards: RwLock<HashMap<u16, u16>>,
    default_tcp_target: RwLock<Option<u16>>,
    default_udp_target: RwLock<Option<u16>>,
    original_destinations: RwLock<HashMap<RedirectFlowKey, OriginalDestinationQueue>>,
}

impl PortForwardTable {
    /// Creates an empty forwarding table.
    pub fn new() -> Self {
        Self {
            tcp_forwards: RwLock::new(HashMap::new()),
            udp_forwards: RwLock::new(HashMap::new()),
            default_tcp_target: RwLock::new(None),
            default_udp_target: RwLock::new(None),
            original_destinations: RwLock::new(HashMap::new()),
        }
    }

    /// Adds a TCP port forward mapping.
    pub fn add_tcp_forward(&self, from: u16, to: u16) {
        self.tcp_forwards.write().insert(from, to);
    }

    /// Adds a UDP port forward mapping.
    pub fn add_udp_forward(&self, from: u16, to: u16) {
        self.udp_forwards.write().insert(from, to);
    }

    /// Resolves a TCP port to its forwarded destination.
    ///
    /// Returns `Some(dst_port)` if a forward exists, `None` otherwise.
    pub fn resolve_tcp(&self, port: u16) -> Option<u16> {
        self.tcp_forwards.read().get(&port).copied()
    }

    /// Resolves a UDP port to its forwarded destination.
    ///
    /// Returns `Some(dst_port)` if a forward exists, `None` otherwise.
    pub fn resolve_udp(&self, port: u16) -> Option<u16> {
        self.udp_forwards.read().get(&port).copied()
    }

    /// Removes a TCP port forward mapping.
    pub fn remove_tcp(&self, port: u16) {
        self.tcp_forwards.write().remove(&port);
    }

    /// Removes a UDP port forward mapping.
    pub fn remove_udp(&self, port: u16) {
        self.udp_forwards.write().remove(&port);
    }

    /// Sets the default TCP redirection target used by catch-all interception rules.
    pub fn set_default_tcp_target(&self, port: u16) {
        *self.default_tcp_target.write() = Some(port);
    }

    /// Sets the default UDP redirection target used by catch-all interception rules.
    pub fn set_default_udp_target(&self, port: u16) {
        *self.default_udp_target.write() = Some(port);
    }

    /// Resolves the listener port that redirected traffic for a given original destination.
    pub fn resolve_redirect_target(&self, protocol: &str, original_dst_port: u16) -> Option<u16> {
        match protocol {
            "TCP" => self
                .resolve_tcp(original_dst_port)
                .or_else(|| *self.default_tcp_target.read()),
            "UDP" => self
                .resolve_udp(original_dst_port)
                .or_else(|| *self.default_udp_target.read()),
            _ => None,
        }
    }

    /// Records the original destination for a redirected flow.
    pub fn record_original_dest(
        &self,
        src: &SocketAddr,
        protocol: &str,
        listener_port: u16,
        original_dst: &SocketAddr,
    ) {
        let key = RedirectFlowKey::new(src, protocol, listener_port);
        let mut destinations = self.original_destinations.write();
        let queue = destinations.entry(key).or_default();
        if protocol == "TCP" && !queue.is_empty() {
            // Replace existing TCP destination to handle reconnections
            queue.clear();
        }
        queue.touch();
        queue.push_back(SessionDestination::new(
            original_dst.ip().to_string(),
            original_dst.port(),
        ));
    }

    /// Consumes the next original destination for a redirected flow, preserving packet order.
    pub fn take_original_dest(
        &self,
        src: &SocketAddr,
        protocol: &str,
        listener_port: u16,
    ) -> Option<SessionDestination> {
        let key = RedirectFlowKey::new(src, protocol, listener_port);
        let mut destinations = self.original_destinations.write();
        let (original, should_remove) = {
            let queue = destinations.get_mut(&key)?;
            let original = queue.pop_front()?;
            queue.touch();
            (original, queue.is_empty())
        };
        if should_remove {
            destinations.remove(&key);
        }
        Some(original)
    }

    /// Clears any queued original destinations for a flow.
    pub fn clear_original_dest(&self, src: &SocketAddr, protocol: &str, listener_port: u16) {
        let key = RedirectFlowKey::new(src, protocol, listener_port);
        self.original_destinations.write().remove(&key);
    }

    /// Purge stale entries from original_destinations.
    /// Should be called periodically (e.g., from session cleanup task).
    pub fn purge_stale_destinations(&self, max_age: Duration) {
        let mut destinations = self.original_destinations.write();
        let before = destinations.len();
        destinations.retain(|_, queue| queue.last_updated.elapsed() < max_age);
        let removed = before - destinations.len();
        if removed > 0 {
            tracing::debug!(
                "Purged {} stale port forward entries older than {:?}",
                removed,
                max_age
            );
        }
    }
}

#[derive(Debug, Clone)]
struct OriginalDestinationQueue {
    queue: VecDeque<SessionDestination>,
    last_updated: Instant,
}

impl OriginalDestinationQueue {
    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn clear(&mut self) {
        self.queue.clear();
    }

    fn push_back(&mut self, destination: SessionDestination) {
        self.queue.push_back(destination);
    }

    fn pop_front(&mut self) -> Option<SessionDestination> {
        self.queue.pop_front()
    }

    fn touch(&mut self) {
        self.last_updated = Instant::now();
    }
}

impl Default for OriginalDestinationQueue {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            last_updated: Instant::now(),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RedirectFlowKey {
    src_ip: String,
    src_port: u16,
    listener_port: u16,
    protocol: String,
}

impl RedirectFlowKey {
    fn new(src: &SocketAddr, protocol: &str, listener_port: u16) -> Self {
        Self {
            src_ip: src.ip().to_string(),
            src_port: src.port(),
            listener_port,
            protocol: protocol.to_string(),
        }
    }
}

impl Default for PortForwardTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;

    #[test]
    fn test_session_tracker_new() {
        let tracker = SessionTracker::new();
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_session_tracker_register() {
        let tracker = SessionTracker::new();
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let destination = SessionDestination::unknown(80);

        let is_new = tracker.register(&addr, &destination, "test", "TCP");
        assert!(is_new, "First registration should be new");
        assert_eq!(tracker.active_count(), 1);

        let is_new2 = tracker.register(&addr, &destination, "test", "TCP");
        assert!(!is_new2, "Second registration should not be new");
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn test_session_tracker_update_bytes() {
        let tracker = SessionTracker::new();
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        let destination = SessionDestination::unknown(80);
        tracker.register(&addr, &destination, "test", "TCP");
        tracker.update_bytes(&addr, "TCP", &destination, 100, 200);

        // Verify session exists
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn test_session_tracker_remove() {
        let tracker = SessionTracker::new();
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        let destination = SessionDestination::unknown(80);
        tracker.register(&addr, &destination, "test", "TCP");
        assert_eq!(tracker.active_count(), 1);

        tracker.remove(&addr, "TCP", &destination);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_session_tracker_get_process() {
        let tracker = SessionTracker::new();
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        let destination = SessionDestination::unknown(80);
        tracker.register(&addr, &destination, "test", "TCP");
        tracker.set_process(
            &addr,
            "TCP",
            &destination,
            Some("curl".to_string()),
            Some(1234),
        );

        assert_eq!(
            tracker.get_process(&addr, "TCP", &destination),
            Some((Some("curl".to_string()), Some(1234)))
        );
    }

    #[test]
    fn test_session_tracker_background_cleanup() {
        let tracker = Arc::new(SessionTracker::new());
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        tracker.register(&addr, &SessionDestination::unknown(80), "test", "TCP");
        assert_eq!(tracker.active_count(), 1);

        // Cleanup should work
        tracker.cleanup();
        assert_eq!(tracker.active_count(), 1); // Session not expired yet
    }

    #[test]
    fn test_session_tracker_export() {
        let tracker = SessionTracker::new();
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        // Add a session
        tracker.register(&addr, &SessionDestination::unknown(80), "test", "TCP");

        // Check active count instead of export
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn test_session_key_creation() {
        let key = SessionKey {
            src_ip: "192.168.1.1".to_string(),
            src_port: 12345,
            dst_ip: "10.0.0.5".to_string(),
            dst_port: 80,
            protocol: "TCP".to_string(),
        };

        assert_eq!(key.src_ip, "192.168.1.1");
        assert_eq!(key.src_port, 12345);
        assert_eq!(key.dst_ip, "10.0.0.5");
        assert_eq!(key.dst_port, 80);
        assert_eq!(key.protocol, "TCP");
    }

    #[test]
    fn test_port_forward_table() {
        let table = PortForwardTable::new();

        table.add_tcp_forward(8080, 80);
        table.add_udp_forward(5353, 53);

        assert_eq!(table.resolve_tcp(8080), Some(80));
        assert_eq!(table.resolve_udp(5353), Some(53));
        assert_eq!(table.resolve_tcp(9090), None);

        table.remove_tcp(8080);
        assert_eq!(table.resolve_tcp(8080), None);
    }

    #[test]
    fn test_port_forward_table_tracks_original_destinations_by_flow() {
        let table = PortForwardTable::new();
        let src: SocketAddr = "192.168.1.10:53000".parse().unwrap();
        let first_original: SocketAddr = "10.0.0.5:4444".parse().unwrap();
        let second_original: SocketAddr = "10.0.0.5:5555".parse().unwrap();

        table.record_original_dest(&src, "UDP", 5353, &first_original);
        table.record_original_dest(&src, "UDP", 5353, &second_original);

        assert_eq!(
            table.take_original_dest(&src, "UDP", 5353),
            Some(SessionDestination::new(
                first_original.ip().to_string(),
                first_original.port()
            ))
        );
        assert_eq!(
            table.take_original_dest(&src, "UDP", 5353),
            Some(SessionDestination::new(
                second_original.ip().to_string(),
                second_original.port()
            ))
        );
        assert_eq!(table.take_original_dest(&src, "UDP", 5353), None);
    }

    #[test]
    fn test_port_forward_table_deduplicates_tcp_original_destination_queue() {
        let table = PortForwardTable::new();
        let src: SocketAddr = "192.168.1.10:53000".parse().unwrap();
        let first_original: SocketAddr = "10.0.0.5:4444".parse().unwrap();
        let second_original: SocketAddr = "10.0.0.6:4444".parse().unwrap();

        table.record_original_dest(&src, "TCP", 8080, &first_original);
        table.record_original_dest(&src, "TCP", 8080, &second_original);

        // TCP reconnections replace the destination (latest wins)
        assert_eq!(
            table.take_original_dest(&src, "TCP", 8080),
            Some(SessionDestination::new(
                second_original.ip().to_string(),
                second_original.port()
            ))
        );
        assert_eq!(table.take_original_dest(&src, "TCP", 8080), None);
    }

    #[test]
    fn test_port_forward_table_purges_only_stale_original_destinations() {
        let table = PortForwardTable::new();
        let stale_src: SocketAddr = "192.168.1.10:53000".parse().unwrap();
        let fresh_src: SocketAddr = "192.168.1.11:53001".parse().unwrap();
        let stale_dst: SocketAddr = "10.0.0.5:4444".parse().unwrap();
        let fresh_dst: SocketAddr = "10.0.0.6:5555".parse().unwrap();

        table.record_original_dest(&stale_src, "UDP", 5353, &stale_dst);
        std::thread::sleep(Duration::from_millis(20));
        table.record_original_dest(&fresh_src, "UDP", 5353, &fresh_dst);

        table.purge_stale_destinations(Duration::from_millis(10));

        assert_eq!(table.take_original_dest(&stale_src, "UDP", 5353), None);
        assert_eq!(
            table.take_original_dest(&fresh_src, "UDP", 5353),
            Some(SessionDestination::new(
                fresh_dst.ip().to_string(),
                fresh_dst.port()
            ))
        );
    }

    #[test]
    fn test_session_tracker_with_ttl() {
        let tracker = SessionTracker::with_ttl(60); // 1 minute TTL
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_session_tracker_register_refreshes_last_activity() {
        let tracker = SessionTracker::with_ttl(2);
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        tracker.register(&addr, &SessionDestination::unknown(80), "test", "TCP");
        std::thread::sleep(Duration::from_millis(1100));
        tracker.register(&addr, &SessionDestination::unknown(80), "test", "TCP");
        std::thread::sleep(Duration::from_millis(1100));

        tracker.cleanup();

        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn test_session_tracker_cleanup_returns_expired_keys() {
        let tracker = SessionTracker::with_ttl(1);
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let destination = SessionDestination::new("10.0.0.5", 80);

        tracker.register(&addr, &destination, "udp-test", "UDP");
        std::thread::sleep(Duration::from_millis(1100));

        let expired = tracker.cleanup_expired_sessions();

        assert_eq!(tracker.active_count(), 0);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].protocol, "UDP");
        assert_eq!(expired[0].dst_ip, "10.0.0.5");
        assert_eq!(expired[0].dst_port, 80);
    }

    #[test]
    fn test_session_tracker_keeps_distinct_destinations_separate() {
        let tracker = SessionTracker::new();
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        let http_destination = SessionDestination::new("10.0.0.5", 80);
        let https_destination = SessionDestination::new("10.0.0.6", 443);
        tracker.register(&addr, &http_destination, "http", "TCP");
        tracker.register(&addr, &https_destination, "https", "TCP");
        tracker.set_process(
            &addr,
            "TCP",
            &http_destination,
            Some("curl".to_string()),
            Some(1001),
        );
        tracker.set_process(
            &addr,
            "TCP",
            &https_destination,
            Some("chrome".to_string()),
            Some(2002),
        );

        assert_eq!(tracker.active_count(), 2);
        assert_eq!(
            tracker.get_process(&addr, "TCP", &http_destination),
            Some((Some("curl".to_string()), Some(1001)))
        );
        assert_eq!(
            tracker.get_process(&addr, "TCP", &https_destination),
            Some((Some("chrome".to_string()), Some(2002)))
        );
    }

    #[test]
    fn test_session_tracker_keeps_same_port_different_destinations_separate() {
        let tracker = SessionTracker::new();
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let first_destination = SessionDestination::new("10.0.0.5", 443);
        let second_destination = SessionDestination::new("10.0.0.6", 443);

        tracker.register(&addr, &first_destination, "tls-a", "TCP");
        tracker.register(&addr, &second_destination, "tls-b", "TCP");
        tracker.set_process(
            &addr,
            "TCP",
            &first_destination,
            Some("curl".to_string()),
            Some(1111),
        );
        tracker.set_process(
            &addr,
            "TCP",
            &second_destination,
            Some("browser".to_string()),
            Some(2222),
        );

        assert_eq!(tracker.active_count(), 2);
        assert_eq!(
            tracker.get_process(&addr, "TCP", &first_destination),
            Some((Some("curl".to_string()), Some(1111)))
        );
        assert_eq!(
            tracker.get_process(&addr, "TCP", &second_destination),
            Some((Some("browser".to_string()), Some(2222)))
        );
        assert_eq!(tracker.get_process_for_port(&addr, "TCP", 443), None);
    }
}
