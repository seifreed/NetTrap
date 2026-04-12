use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use std::collections::VecDeque;
use std::time::Instant;

use crate::prelude::*;

#[derive(Debug, Default, Clone)]
pub struct FlowManagerStats {
    pub total_flows_created: u64,
    pub total_flows_closed: u64,
    pub active_flows: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

#[derive(Debug, Clone)]
pub struct FlowManagerConfig {
    pub max_flows: usize,
    pub cleanup_interval: std::time::Duration,
    pub flow_timeout: std::time::Duration,
}

impl Default for FlowManagerConfig {
    fn default() -> Self {
        Self {
            max_flows: 100000,
            cleanup_interval: std::time::Duration::from_secs(30),
            flow_timeout: std::time::Duration::from_secs(300),
        }
    }
}

pub struct FlowManager {
    flows: DashMap<FlowKey, Flow>,
    flow_index: DashMap<FlowId, FlowKey>,
    recent_flows: RwLock<VecDeque<FlowId>>,
    flow_order: RwLock<VecDeque<FlowId>>,
    config: FlowManagerConfig,
    stats: RwLock<FlowManagerStats>,
    last_cleanup: RwLock<Instant>,
    insert_lock: Mutex<()>,
}

impl FlowManager {
    pub fn new(config: FlowManagerConfig) -> Self {
        Self {
            flows: DashMap::new(),
            flow_index: DashMap::new(),
            recent_flows: RwLock::new(VecDeque::with_capacity(1000)),
            flow_order: RwLock::new(VecDeque::new()),
            config,
            stats: RwLock::new(FlowManagerStats::default()),
            last_cleanup: RwLock::new(Instant::now()),
            insert_lock: Mutex::new(()),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let config = FlowManagerConfig {
            max_flows: capacity,
            ..Default::default()
        };
        Self::new(config)
    }

    pub fn get_or_create(&self, five_tuple: FiveTuple) -> Flow {
        self.maybe_cleanup();
        let key = FlowKey::from_five_tuple(&five_tuple);

        if let Some(flow) = self.flows.get(&key) {
            self.stats.write().cache_hits += 1;
            return flow.clone();
        }

        let _insert_guard = self.insert_lock.lock();
        self.maybe_cleanup();

        if let Some(flow) = self.flows.get(&key) {
            self.stats.write().cache_hits += 1;
            return flow.clone();
        }

        self.enforce_max_flows();

        let flow = Flow::new(five_tuple);
        let flow_id = flow.id;

        self.flows.insert(key, flow.clone());
        self.flow_index.insert(flow_id, key);
        self.record_new_flow(flow_id);

        {
            let mut stats = self.stats.write();
            stats.cache_misses += 1;
            stats.total_flows_created += 1;
            stats.active_flows = self.flows.len() as u64;
        }

        flow
    }

    pub fn get(&self, key: &FlowKey) -> Option<Flow> {
        self.maybe_cleanup();
        self.flows.get(key).map(|f| {
            self.stats.write().cache_hits += 1;
            f.clone()
        })
    }

    pub fn get_by_id(&self, id: &FlowId) -> Option<Flow> {
        self.maybe_cleanup();
        let key = *self.flow_index.get(id)?;
        self.get(&key)
    }

    pub fn update<F>(&self, key: &FlowKey, update: F) -> Option<Flow>
    where
        F: FnOnce(&mut Flow),
    {
        self.maybe_cleanup();
        let mut flow = self.flows.get_mut(key)?;
        update(&mut flow);
        Some(flow.clone())
    }

    pub fn remove(&self, key: &FlowKey) -> Option<Flow> {
        self.maybe_cleanup();
        self.remove_internal(key)
    }

    pub fn contains(&self, key: &FlowKey) -> bool {
        self.flows.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = Flow> {
        self.flows.iter().map(|f| f.clone())
    }

    pub fn iter_keys(&self) -> impl Iterator<Item = FlowKey> + '_ {
        self.flows.iter().map(|f| *f.key())
    }

    pub fn find_by_process(&self, pid: ProcessId) -> Vec<Flow> {
        self.maybe_cleanup();
        self.flows
            .iter()
            .filter(|f| {
                f.metadata
                    .process
                    .as_ref()
                    .map(|p| p.pid == pid)
                    .unwrap_or(false)
            })
            .map(|f| f.clone())
            .collect()
    }

    pub fn find_by_destination(&self, ip: std::net::IpAddr, port: Option<u16>) -> Vec<Flow> {
        self.maybe_cleanup();
        self.flows
            .iter()
            .filter(|f| {
                let matches_ip = f.five_tuple.dst_ip == ip;
                let matches_port = port.map(|p| f.five_tuple.dst_port == p).unwrap_or(true);
                matches_ip && matches_port
            })
            .map(|f| f.clone())
            .collect()
    }

    pub fn find_by_source(&self, ip: std::net::IpAddr, port: Option<u16>) -> Vec<Flow> {
        self.maybe_cleanup();
        self.flows
            .iter()
            .filter(|f| {
                let matches_ip = f.five_tuple.src_ip == ip;
                let matches_port = port.map(|p| f.five_tuple.src_port == p).unwrap_or(true);
                matches_ip && matches_port
            })
            .map(|f| f.clone())
            .collect()
    }

    pub fn cleanup_expired(&self, timeout: std::time::Duration) -> usize {
        let removed = self.cleanup_expired_internal(timeout);
        *self.last_cleanup.write() = Instant::now();
        removed
    }

    pub fn cleanup_expired_configured(&self) -> usize {
        let removed = self.cleanup_expired_internal(self.config.flow_timeout);
        *self.last_cleanup.write() = Instant::now();
        removed
    }

    fn cleanup_expired_internal(&self, timeout: std::time::Duration) -> usize {
        let now = chrono::Utc::now();
        let expired_keys: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|f| {
                let elapsed = (now - f.updated_at).to_std().unwrap_or_default();
                elapsed > timeout
            })
            .map(|f| *f.key())
            .collect();

        let count = expired_keys.len();
        // Collect flow IDs for batch history removal (avoids O(N²) retain per removal)
        let mut removed_ids = std::collections::HashSet::with_capacity(count);
        for key in &expired_keys {
            if let Some((_, flow)) = self.flows.remove(key) {
                self.flow_index.remove(&flow.id);
                removed_ids.insert(flow.id);
            }
        }
        if !removed_ids.is_empty() {
            self.flow_order.write().retain(|id| !removed_ids.contains(id));
            self.recent_flows.write().retain(|id| !removed_ids.contains(id));
            let mut stats = self.stats.write();
            stats.total_flows_closed += removed_ids.len() as u64;
            stats.active_flows = self.flows.len() as u64;
        }
        count
    }

    pub fn clear(&self) {
        self.flows.clear();
        self.flow_index.clear();
        self.recent_flows.write().clear();
        self.flow_order.write().clear();
        let mut stats = self.stats.write();
        stats.active_flows = 0;
    }

    pub fn stats(&self) -> FlowManagerStats {
        self.stats.read().clone()
    }

    pub fn active_count(&self) -> u64 {
        self.flows.len() as u64
    }

    pub fn recent_flows(&self) -> Vec<FlowId> {
        self.recent_flows.read().iter().copied().collect()
    }

    fn maybe_cleanup(&self) {
        if self.last_cleanup.read().elapsed() < self.config.cleanup_interval {
            return;
        }

        let mut last_cleanup = self.last_cleanup.write();
        if last_cleanup.elapsed() < self.config.cleanup_interval {
            return;
        }

        self.cleanup_expired_internal(self.config.flow_timeout);
        *last_cleanup = Instant::now();
    }

    fn enforce_max_flows(&self) {
        if self.config.max_flows == 0 {
            return;
        }

        while self.flows.len() >= self.config.max_flows {
            if self.evict_oldest_flow().is_none() {
                break;
            }
        }
    }

    fn evict_oldest_flow(&self) -> Option<Flow> {
        loop {
            let oldest_flow = self.flow_order.write().pop_front()?;
            let Some(key) = self.flow_index.get(&oldest_flow).map(|key| *key) else {
                continue;
            };
            if let Some(flow) = self.remove_internal(&key) {
                return Some(flow);
            }
        }
    }

    fn record_new_flow(&self, flow_id: FlowId) {
        self.flow_order.write().push_back(flow_id);

        let mut recent = self.recent_flows.write();
        recent.push_back(flow_id);
        while recent.len() > 1000 {
            recent.pop_front();
        }
    }

    fn remove_internal(&self, key: &FlowKey) -> Option<Flow> {
        let (_, flow) = self.flows.remove(key)?;
        self.flow_index.remove(&flow.id);
        self.remove_from_history(flow.id);

        let mut stats = self.stats.write();
        stats.total_flows_closed += 1;
        stats.active_flows = self.flows.len() as u64;
        Some(flow)
    }

    fn remove_from_history(&self, flow_id: FlowId) {
        self.flow_order.write().retain(|queued| *queued != flow_id);
        self.recent_flows
            .write()
            .retain(|queued| *queued != flow_id);
    }
}

impl Default for FlowManager {
    fn default() -> Self {
        Self::new(FlowManagerConfig::default())
    }
}

impl Clone for FlowManager {
    /// Clones all internal data structures.
    ///
    /// # Warning
    /// This is an expensive operation that clones the entire flow table,
    /// flow index, recent flows list, and statistics. Consider using
    /// `Arc<FlowManager>` for sharing instead of cloning.
    fn clone(&self) -> Self {
        Self {
            flows: self.flows.clone(),
            flow_index: self.flow_index.clone(),
            recent_flows: RwLock::new(self.recent_flows.read().clone()),
            flow_order: RwLock::new(self.flow_order.read().clone()),
            config: self.config.clone(),
            stats: RwLock::new(self.stats.read().clone()),
            last_cleanup: RwLock::new(*self.last_cleanup.read()),
            insert_lock: Mutex::new(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use super::*;

    fn test_flow(src_port: u16, dst_port: u16) -> FiveTuple {
        FiveTuple::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port,
            dst_port,
            Protocol::Tcp,
        )
    }

    #[test]
    fn update_is_atomic_under_concurrency() {
        let manager = Arc::new(FlowManager::default());
        let tuple = test_flow(40000, 443);
        let flow = manager.get_or_create(tuple);
        let key = flow.key();
        let workers = 8;
        let iterations = 250;

        thread::scope(|scope| {
            for _ in 0..workers {
                let manager = Arc::clone(&manager);
                scope.spawn(move || {
                    for _ in 0..iterations {
                        manager
                            .update(&key, |flow| {
                                flow.metadata.bytes_sent += 1;
                            })
                            .expect("flow must exist");
                    }
                });
            }
        });

        let updated = manager.get(&key).expect("flow must still exist");
        assert_eq!(updated.metadata.bytes_sent, (workers * iterations) as u64);
    }

    #[test]
    fn get_or_create_evicts_oldest_flow_when_capacity_is_reached() {
        let manager = FlowManager::new(FlowManagerConfig {
            max_flows: 2,
            ..Default::default()
        });

        let first = manager.get_or_create(test_flow(40001, 80));
        let second = manager.get_or_create(test_flow(40002, 81));
        let third = manager.get_or_create(test_flow(40003, 82));

        assert_eq!(manager.len(), 2);
        assert!(!manager.contains(&first.key()));
        assert!(manager.contains(&second.key()));
        assert!(manager.contains(&third.key()));
    }

    #[test]
    fn configured_cleanup_expires_flows_when_interval_has_elapsed() {
        let manager = FlowManager::new(FlowManagerConfig {
            cleanup_interval: Duration::from_millis(5),
            flow_timeout: Duration::from_millis(10),
            ..Default::default()
        });

        let flow = manager.get_or_create(test_flow(40004, 53));
        thread::sleep(Duration::from_millis(20));

        assert!(manager.get(&flow.key()).is_none());
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn explicit_cleanup_uses_passed_timeout() {
        let manager = FlowManager::new(FlowManagerConfig {
            cleanup_interval: Duration::from_secs(3600),
            flow_timeout: Duration::from_secs(3600),
            ..Default::default()
        });

        manager.get_or_create(test_flow(40005, 25));
        thread::sleep(Duration::from_millis(20));

        assert_eq!(manager.cleanup_expired(Duration::from_millis(1)), 1);
        assert_eq!(manager.active_count(), 0);
    }
}
