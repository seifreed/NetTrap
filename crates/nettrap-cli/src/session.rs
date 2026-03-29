use std::collections::HashMap;
use std::net::SocketAddr;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

/// Tracks active network sessions (sport -> connection metadata)
pub struct SessionTracker {
    sessions: RwLock<HashMap<SessionKey, SessionInfo>>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKey {
    pub src_ip: String,
    pub src_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub dst_ip: String,
    pub dst_port: u16,
    pub listener: String,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub started_at: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets: u64,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    pub fn register(&self, src: &SocketAddr, dst_port: u16, listener: &str, protocol: &str) -> bool {
        let key = SessionKey {
            src_ip: src.ip().to_string(),
            src_port: src.port(),
            protocol: protocol.to_string(),
        };

        let mut sessions = self.sessions.write();
        let is_new = !sessions.contains_key(&key);

        sessions.entry(key).or_insert_with(|| SessionInfo {
            dst_ip: "0.0.0.0".to_string(),
            dst_port,
            listener: listener.to_string(),
            process_name: None,
            process_pid: None,
            started_at: chrono::Utc::now().to_rfc3339(),
            bytes_sent: 0,
            bytes_received: 0,
            packets: 0,
        });

        is_new
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
        }
    }

    pub fn set_process(&self, src: &SocketAddr, protocol: &str, name: Option<String>, pid: Option<u32>) {
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
        self.sessions.read().get(&key).map(|s| (s.dst_ip.clone(), s.dst_port))
    }

    /// Export all sessions as JSON
    pub fn export_sessions(&self) -> String {
        let sessions = self.sessions.read();
        serde_json::to_string_pretty(&*sessions).unwrap_or_default()
    }
}

impl Default for SessionTracker {
    fn default() -> Self { Self::new() }
}

/// Port forwarding table for dynamic port redirection
pub struct PortForwardTable {
    tcp_forwards: RwLock<HashMap<u16, u16>>,  // src_port -> dst_port
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
    fn default() -> Self { Self::new() }
}
