//! Dynamic port forwarding and original-destination tracking for redirected flows.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::SessionDestination;
use super::normalize_session_ip;
use super::normalize_session_protocol;
use super::{MAX_ORIGINAL_DESTINATION_FLOWS, MAX_ORIGINAL_DESTINATIONS_PER_FLOW};

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
        let protocol = normalize_session_protocol(protocol);
        match protocol.as_str() {
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
        if !destinations.contains_key(&key) {
            Self::enforce_original_destination_flow_capacity(
                &mut destinations,
                MAX_ORIGINAL_DESTINATION_FLOWS,
            );
        }
        let queue = destinations.entry(key).or_default();
        let protocol = normalize_session_protocol(protocol);
        if protocol == "TCP" && !queue.is_empty() {
            // Replace existing TCP destination to handle reconnections
            queue.clear();
        }
        queue.touch();
        queue.push_back_bounded(
            SessionDestination::new_unchecked(
                normalize_session_ip(original_dst.ip()).to_string(),
                original_dst.port(),
            ),
            MAX_ORIGINAL_DESTINATIONS_PER_FLOW,
        );
    }

    pub(crate) fn enforce_original_destination_flow_capacity(
        destinations: &mut HashMap<RedirectFlowKey, OriginalDestinationQueue>,
        max_flows: usize,
    ) {
        if max_flows == 0 || destinations.len() < max_flows {
            return;
        }

        let Some(oldest_key) = destinations
            .iter()
            .min_by_key(|(_, queue)| queue.last_updated)
            .map(|(key, _)| key.clone())
        else {
            return;
        };

        destinations.remove(&oldest_key);
        tracing::warn!(
            "Port forward table capacity {} reached; evicted oldest original-destination queue for {} {}:{} on listener {}",
            max_flows,
            oldest_key.protocol(),
            oldest_key.src_ip(),
            oldest_key.src_port(),
            oldest_key.listener_port()
        );
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
pub(crate) struct OriginalDestinationQueue {
    pub(crate) queue: VecDeque<SessionDestination>,
    pub(crate) last_updated: Instant,
}

impl OriginalDestinationQueue {
    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn clear(&mut self) {
        self.queue.clear();
    }

    fn push_back_bounded(&mut self, destination: SessionDestination, max_entries: usize) {
        if max_entries > 0 && self.queue.len() >= max_entries {
            self.queue.pop_front();
        }
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
pub(crate) struct RedirectFlowKey {
    src_ip: String,
    src_port: u16,
    listener_port: u16,
    protocol: String,
}

impl RedirectFlowKey {
    pub(crate) fn new(src: &SocketAddr, protocol: &str, listener_port: u16) -> Self {
        Self {
            src_ip: normalize_session_ip(src.ip()).to_string(),
            src_port: src.port(),
            listener_port,
            protocol: normalize_session_protocol(protocol),
        }
    }

    fn src_ip(&self) -> &str {
        &self.src_ip
    }

    fn src_port(&self) -> u16 {
        self.src_port
    }

    fn listener_port(&self) -> u16 {
        self.listener_port
    }

    fn protocol(&self) -> &str {
        &self.protocol
    }
}

impl Default for PortForwardTable {
    fn default() -> Self {
        Self::new()
    }
}
