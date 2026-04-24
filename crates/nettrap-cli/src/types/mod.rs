//! Traits for dependency injection and testing.
//!
//! These traits allow components to be mocked for testing and enable
//! loose coupling between modules. They follow the Repository pattern
//! from Clean Architecture, abstracting data access behind interfaces.

use crate::session::SessionDestination;
use std::net::SocketAddr;
use std::path::Path;

use nettrap_core::prelude::FiveTuple;

// ═══════════════════════════════════════════════════════════════════════
// ATTRIBUTION TRAIT
// ═══════════════════════════════════════════════════════════════════════

/// Trait for attribution engine implementations.
///
/// Allows process attribution to be mocked for testing.
pub trait AttributionEngine: Send + Sync {
    /// Attribute a network flow to a process.
    fn attribute_flow(&self, five_tuple: &FiveTuple) -> Option<AttributionResult>;

    /// Get the configured timeout in milliseconds.
    fn timeout_ms(&self) -> u64;
}

/// Result of process attribution.
#[derive(Debug, Clone)]
pub struct AttributionResult {
    pub process_name: String,
    pub pid: u32,
    pub confidence: AttributionConfidence,
    pub command_line: Option<String>,
    pub executable_path: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AttributionConfidence {
    #[default]
    None,
    Low,
    Medium,
    High,
}

// ═══════════════════════════════════════════════════════════════════════
// PCAP WRITER TRAIT
// ═══════════════════════════════════════════════════════════════════════

/// Trait for PCAP packet writing.
///
/// Allows packet capture to be mocked for testing.
pub trait PcapWriterTrait: Send + Sync {
    /// Open the PCAP file for writing.
    fn open(&self) -> std::io::Result<()>;

    /// Write a packet to the PCAP file.
    fn write_packet(&self, timestamp: u64, data: &[u8]) -> std::io::Result<()>;

    /// Close the PCAP file.
    fn close(&self);
}

// ═══════════════════════════════════════════════════════════════════════
// EVENT BUS TRAIT
// ═══════════════════════════════════════════════════════════════════════

/// Trait for event bus implementations.
///
/// Allows event publishing to be mocked for testing.
#[async_trait::async_trait]
pub trait EventBus: Send + Sync {
    /// Publish an event to all subscribers.
    async fn publish(&self, event: &NetworkBehaviorIndicator);

    /// Subscribe to events.
    fn subscribe(&self) -> Box<dyn EventSubscriber>;
}

/// Subscriber for event bus.
#[async_trait::async_trait]
pub trait EventSubscriber: Send {
    /// Receive the next event.
    async fn recv(&mut self) -> Option<NetworkBehaviorIndicator>;
}

// ═══════════════════════════════════════════════════════════════════════
// SESSION REPOSITORY TRAIT (Clean Architecture)
// ═══════════════════════════════════════════════════════════════════════

/// Trait for session tracking (Repository pattern).
///
/// Abstracts session persistence, enabling:
/// - In-memory implementation for production
/// - Mock implementation for testing
/// - Database-backed implementation for persistence
///
/// This follows the Repository pattern from Clean Architecture,
/// separating business logic from data access.
pub trait SessionRepository: Send + Sync {
    /// Register a new session or update existing.
    /// Returns `true` if this was a new session.
    fn register(
        &self,
        src: &SocketAddr,
        destination: &SessionDestination,
        listener: &str,
        protocol: &str,
    ) -> bool;

    /// Remove a session.
    fn remove(&self, src: &SocketAddr, protocol: &str, destination: &SessionDestination);

    /// Update bytes transferred for a session.
    fn update_bytes(
        &self,
        src: &SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
        rx_bytes: u64,
        tx_bytes: u64,
    );

    /// Get session info.
    fn get(
        &self,
        src: &SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
    ) -> Option<SessionInfo>;

    /// Export all sessions for reporting.
    fn export_all(&self) -> Vec<SessionInfo>;

    /// Count active sessions.
    fn active_count(&self) -> usize;

    /// Cleanup expired sessions.
    fn cleanup(&self);
}

/// Session information.
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

// ═══════════════════════════════════════════════════════════════════════
// NBI REPOSITORY TRAIT (Clean Architecture)
// ═══════════════════════════════════════════════════════════════════════

/// Trait for NBI (Network Behavior Indicator) collection.
///
/// Abstracts NBI persistence, enabling:
/// - JSONL file storage (current implementation)
/// - Database storage (future)
/// - In-memory collection for testing
///
/// This follows the Repository pattern from Clean Architecture.
#[async_trait::async_trait]
pub trait NbiRepository: Send + Sync {
    /// Record a network behavior indicator.
    async fn record(&self, nbi: &NetworkBehaviorIndicator);

    /// Generate HTML report from collected NBIs.
    fn generate_html_report(&self, input: &Path, output: &Path, lang: &str) -> std::io::Result<()>;

    /// Get count of recorded NBIs (for testing/metrics).
    fn count(&self) -> usize;
}

// ═══════════════════════════════════════════════════════════════════════
// PORT FORWARD TABLE TRAIT
// ═══════════════════════════════════════════════════════════════════════

/// Trait for port forwarding table.
pub trait PortForwardRepository: Send + Sync {
    /// Add a port forward entry.
    fn add(&self, src_port: u16, dst_addr: SocketAddr);

    /// Remove a port forward entry.
    fn remove(&self, src_port: u16);

    /// Look up a port forward entry.
    fn lookup(&self, src_port: u16) -> Option<SocketAddr>;

    /// List all entries.
    fn list(&self) -> Vec<(u16, SocketAddr)>;
}

// ═══════════════════════════════════════════════════════════════════════
// NETWORK BEHAVIOR INDICATOR
// ═══════════════════════════════════════════════════════════════════════

/// Network behavior indicator for event bus.
#[derive(Debug, Clone)]
pub struct NetworkBehaviorIndicator {
    pub timestamp: String,
    pub listener: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub process_name: Option<String>,
    pub process_pid: Option<u32>,
    pub indicators: Vec<(String, String)>,
}

impl NetworkBehaviorIndicator {
    pub fn new(
        listener: impl Into<String>,
        src_ip: impl Into<String>,
        src_port: u16,
        destination: &SessionDestination,
        protocol: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            listener: listener.into(),
            src_ip: src_ip.into(),
            src_port,
            dst_ip: destination.ip.clone(),
            dst_port: destination.port,
            protocol: protocol.into(),
            process_name: None,
            process_pid: None,
            indicators: Vec::new(),
        }
    }

    pub fn add(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.indicators.push((key.into(), value.into()));
    }
}

// ═══════════════════════════════════════════════════════════════════════
// LEGACY TRAIT ALIASES (for backward compatibility)
// ═══════════════════════════════════════════════════════════════════════

/// Deprecated: Use `SessionRepository` instead.
#[deprecated(note = "Use SessionRepository instead for Clean Architecture compliance")]
pub trait SessionTrackerTrait: Send + Sync {
    fn register_session(
        &self,
        peer: &SocketAddr,
        destination: &SessionDestination,
        listener: &str,
        protocol: &str,
    );
    fn remove_session(&self, peer: &SocketAddr, protocol: &str, destination: &SessionDestination);
    fn update_session_bytes(
        &self,
        peer: &SocketAddr,
        protocol: &str,
        destination: &SessionDestination,
        rx: u64,
        tx: u64,
    );
}

/// Deprecated: Use `NbiRepository` instead.
#[deprecated(note = "Use NbiRepository instead for Clean Architecture compliance")]
#[async_trait::async_trait]
pub trait NbiCollectorTrait: Send + Sync {
    async fn record(&self, nbi: &NetworkBehaviorIndicator);
    fn generate_html_report(&self, input: &Path, output: &Path, lang: &str) -> std::io::Result<()>;
}

// ═══════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nbi_creation() {
        let destination = SessionDestination::new("10.0.0.7", 5353);
        let mut nbi = NetworkBehaviorIndicator::new("dns", "192.168.1.1", 53, &destination, "udp");
        nbi.add("query", "example.com");
        assert_eq!(nbi.listener, "dns");
        assert_eq!(nbi.dst_ip, "10.0.0.7");
        assert_eq!(nbi.dst_port, 5353);
        assert_eq!(nbi.indicators.len(), 1);
    }
}
