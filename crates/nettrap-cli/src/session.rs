use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Tracks active network sessions (sport -> connection metadata)
pub struct SessionTracker {
    sessions: RwLock<HashMap<SessionKey, SessionInfo>>,
    session_ttl_secs: u64,
    last_cleanup: RwLock<std::time::Instant>,
    cleanup_interval_secs: u64,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKey {
    pub src_ip: String,
    pub src_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub dst_ip: String,
    pub dst_port: u16,
    pub listener: String,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub started_at: String,
    pub last_activity: std::time::Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets: u64,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            session_ttl_secs: 3600, // Default 1 hour TTL
            last_cleanup: RwLock::new(std::time::Instant::now()),
            cleanup_interval_secs: 300, // Cleanup every 5 minutes
        }
    }

    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            session_ttl_secs: ttl_secs,
            last_cleanup: RwLock::new(std::time::Instant::now()),
            cleanup_interval_secs: 300,
        }
    }

    /// Start a background cleanup task that runs periodically
    pub fn start_cleanup_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(self.cleanup_interval_secs)).await;
                self.cleanup();
                tracing::debug!("Session cleanup completed, active sessions: {}", self.active_count());
            }
        })
    }

    /// Create a new SessionTracker wrapped in Arc with background cleanup
    pub fn with_background_cleanup() -> (Arc<Self>, tokio::task::JoinHandle<()>) {
        let tracker = Arc::new(Self::new());
        let handle = tracker.clone().start_cleanup_task();
        (tracker, handle)
    }

    /// Create a new SessionTracker with custom TTL and background cleanup
    pub fn with_background_cleanup_and_ttl(ttl_secs: u64) -> (Arc<Self>, tokio::task::JoinHandle<()>) {
        let tracker = Arc::new(Self::with_ttl(ttl_secs));
        let handle = tracker.clone().start_cleanup_task();
        (tracker, handle)
    }

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

    /// Remove expired sessions
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

    /// Force cleanup of expired sessions
    pub fn cleanup(&self) {
        let mut sessions = self.sessions.write();
        self.cleanup_expired(&mut sessions);
    }

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

    pub fn remove(&self, src: &SocketAddr, protocol: &str) {
        let key = SessionKey {
            src_ip: src.ip().to_string(),
            src_port: src.port(),
            protocol: protocol.to_string(),
        };
        self.sessions.write().remove(&key);
    }

    pub fn active_count(&self) -> usize {
        self.sessions.read().len()
    }

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

    /// Export all sessions as JSON
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

/// Serializable version of SessionInfo without Instant
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

/// Port forwarding table for dynamic port redirection
pub struct PortForwardTable {
    tcp_forwards: RwLock<HashMap<u16, u16>>, // src_port -> dst_port
    udp_forwards: RwLock<HashMap<u16, u16>>,
}

impl PortForwardTable {
    pub fn new() -> Self {
        Self {
            tcp_forwards: RwLock::new(HashMap::new()),
            udp_forwards: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_tcp_forward(&self, from: u16, to: u16) {
        self.tcp_forwards.write().insert(from, to);
    }

    pub fn add_udp_forward(&self, from: u16, to: u16) {
        self.udp_forwards.write().insert(from, to);
    }

    pub fn resolve_tcp(&self, port: u16) -> Option<u16> {
        self.tcp_forwards.read().get(&port).copied()
    }

    pub fn resolve_udp(&self, port: u16) -> Option<u16> {
        self.udp_forwards.read().get(&port).copied()
    }

    pub fn remove_tcp(&self, port: u16) {
        self.tcp_forwards.write().remove(&port);
    }

    pub fn remove_udp(&self, port: u16) {
        self.udp_forwards.write().remove(&port);
    }
}

impl Default for PortForwardTable {
    fn default() -> Self {
        Self::new()
    }
}
