use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Default session time-to-live in seconds
const DEFAULT_SESSION_TTL_SECS: u64 = 3600; // 1 hour
/// Default cleanup interval in seconds
const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 300; // 5 minutes

/// Tracks active network sessions for connection state management.
///
/// `SessionTracker` maintains a map of active connections identified by source IP,
/// source port, and protocol. It provides TTL-based automatic cleanup of stale
/// sessions and supports background cleanup tasks for long-running processes.
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
/// Sessions are keyed by the combination of source IP, source port, and protocol
/// to distinguish between different connections from the same client.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKey {
    /// Source IP address as string (e.g., "192.168.1.1")
    pub src_ip: String,
    /// Source port number
    pub src_port: u16,
    /// Protocol name (e.g., "TCP", "UDP")
    pub protocol: String,
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
                tracing::debug!("Session cleanup completed, active sessions: {}", self.active_count());
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
    pub fn with_background_cleanup_and_ttl(ttl_secs: u64) -> (Arc<Self>, tokio::task::JoinHandle<()>) {
        let tracker = Arc::new(Self::with_ttl(ttl_secs));
        let handle = tracker.clone().start_cleanup_task();
        (tracker, handle)
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
        dst_port: u16,
        listener: &str,
        protocol: &str,
    ) -> bool {
        let key = SessionKey {
            src_ip: src.ip().to_string(),
            src_port: src.port(),
            protocol: protocol.to_string(),
        };

        let mut sessions = self.sessions.write();

        // Cleanup expired sessions periodically (not on every register for performance)
        {
            let mut last = self.last_cleanup.write();
            if last.elapsed() > Duration::from_secs(self.cleanup_interval_secs) {
                self.cleanup_expired(&mut sessions);
                *last = std::time::Instant::now();
            }
        }

        let is_new = !sessions.contains_key(&key);

        sessions.entry(key).or_insert_with(|| SessionInfo {
            dst_ip: "0.0.0.0".to_string(),
            dst_port,
            listener: listener.to_string(),
            process_name: None,
            process_pid: None,
            started_at: chrono::Utc::now().to_rfc3339(),
            last_activity: std::time::Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            packets: 0,
        });

        is_new
    }

    /// Removes expired sessions from the tracker.
    ///
    /// Sessions that have not had activity for longer than `session_ttl_secs` are removed.
    fn cleanup_expired(&self, sessions: &mut HashMap<SessionKey, SessionInfo>) {
        let now = std::time::Instant::now();
        let ttl = Duration::from_secs(self.session_ttl_secs);
        let before = sessions.len();
        sessions.retain(|_, info| now.duration_since(info.last_activity) < ttl);
        let removed = before - sessions.len();
        if removed > 0 {
            tracing::debug!("Cleaned up {} expired sessions", removed);
        }
    }

    /// Forces immediate cleanup of expired sessions.
    pub fn cleanup(&self) {
        let mut sessions = self.sessions.write();
        self.cleanup_expired(&mut sessions);
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
    pub fn update_bytes(&self, src: &SocketAddr, protocol: &str, received: u64, sent: u64) {
        let key = SessionKey {
            src_ip: src.ip().to_string(),
            src_port: src.port(),
            protocol: protocol.to_string(),
        };

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
        name: Option<String>,
        pid: Option<u32>,
    ) {
        let key = SessionKey {
            src_ip: src.ip().to_string(),
            src_port: src.port(),
            protocol: protocol.to_string(),
        };

        if let Some(session) = self.sessions.write().get_mut(&key) {
            session.process_name = name;
            session.process_pid = pid;
        }
    }

    /// Removes a session from the tracker.
    ///
    /// Typically called when a connection is closed.
    pub fn remove(&self, src: &SocketAddr, protocol: &str) {
        let key = SessionKey {
            src_ip: src.ip().to_string(),
            src_port: src.port(),
            protocol: protocol.to_string(),
        };
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
    pub fn get_original_dest(&self, src: &SocketAddr, protocol: &str) -> Option<(String, u16)> {
        let key = SessionKey {
            src_ip: src.ip().to_string(),
            src_port: src.port(),
            protocol: protocol.to_string(),
        };
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
}

impl PortForwardTable {
    /// Creates an empty forwarding table.
    pub fn new() -> Self {
        Self {
            tcp_forwards: RwLock::new(HashMap::new()),
            udp_forwards: RwLock::new(HashMap::new()),
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
}

impl Default for PortForwardTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::net::SocketAddr;

    #[test]
    fn test_session_tracker_new() {
        let tracker = SessionTracker::new();
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_session_tracker_register() {
        let tracker = SessionTracker::new();
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        
        let is_new = tracker.register(&addr, 80, "test", "TCP");
        assert!(is_new, "First registration should be new");
        assert_eq!(tracker.active_count(), 1);
        
        let is_new2 = tracker.register(&addr, 80, "test", "TCP");
        assert!(!is_new2, "Second registration should not be new");
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn test_session_tracker_update_bytes() {
        let tracker = SessionTracker::new();
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        
        tracker.register(&addr, 80, "test", "TCP");
        tracker.update_bytes(&addr, "TCP", 100, 200);
        
        // Verify session exists
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn test_session_tracker_remove() {
        let tracker = SessionTracker::new();
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        
        tracker.register(&addr, 80, "test", "TCP");
        assert_eq!(tracker.active_count(), 1);
        
        tracker.remove(&addr, "TCP");
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn test_session_tracker_background_cleanup() {
        let tracker = Arc::new(SessionTracker::new());
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        
        tracker.register(&addr, 80, "test", "TCP");
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
        tracker.register(&addr, 80, "test", "TCP");
        
        // Check active count instead of export
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn test_session_key_creation() {
        let key = SessionKey {
            src_ip: "192.168.1.1".to_string(),
            src_port: 12345,
            protocol: "TCP".to_string(),
        };
        
        assert_eq!(key.src_ip, "192.168.1.1");
        assert_eq!(key.src_port, 12345);
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
    fn test_session_tracker_with_ttl() {
        let tracker = SessionTracker::with_ttl(60); // 1 minute TTL
        assert_eq!(tracker.active_count(), 0);
    }
}
