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
    now: fn() -> chrono::DateTime<chrono::Utc>,
    stats: RwLock<FlowManagerStats>,
    last_cleanup: RwLock<Instant>,
    insert_lock: Mutex<()>,
}

impl FlowManager {
    pub fn new(mut config: FlowManagerConfig) -> Self {
        config.max_flows = effective_max_flows(config.max_flows);
        Self {
            flows: DashMap::new(),
            flow_index: DashMap::new(),
            recent_flows: RwLock::new(VecDeque::with_capacity(1000)),
            flow_order: RwLock::new(VecDeque::new()),
            config,
            now: chrono::Utc::now,
            stats: RwLock::new(FlowManagerStats::default()),
            last_cleanup: RwLock::new(Instant::now()),
            insert_lock: Mutex::new(()),
        }
    }

    pub fn with_now(mut self, now: fn() -> chrono::DateTime<chrono::Utc>) -> Self {
        self.now = now;
        self
    }

    pub fn now(&self) -> chrono::DateTime<chrono::Utc> {
        (self.now)()
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
            if self.flow_is_expired(&flow) {
                let observed_updated_at = flow.updated_at;
                drop(flow);
                let _ = self.remove_expired_keys(vec![(key, observed_updated_at)]);
            } else {
                let mut stats = self.stats.write();
                stats.cache_hits = stats.cache_hits.saturating_add(1);
                return flow.clone();
            }
        }

        let _insert_guard = self.insert_lock.lock();
        self.maybe_cleanup();

        if let Some(flow) = self.flows.get(&key) {
            if self.flow_is_expired(&flow) {
                let observed_updated_at = flow.updated_at;
                drop(flow);
                let _ = self.remove_expired_keys(vec![(key, observed_updated_at)]);
            } else {
                let mut stats = self.stats.write();
                stats.cache_hits = stats.cache_hits.saturating_add(1);
                return flow.clone();
            }
        }

        self.enforce_max_flows();

        let now = self.now();
        let mut flow = Flow::new_with_now(five_tuple, now);
        flow.created_at = now;
        flow.updated_at = now;
        flow.metadata.first_seen = now;
        flow.metadata.last_seen = now;
        let flow_id = flow.id;

        self.flows.insert(key, flow.clone());
        self.flow_index.insert(flow_id, key);
        self.record_new_flow(flow_id);

        {
            let mut stats = self.stats.write();
            stats.cache_misses = stats.cache_misses.saturating_add(1);
            stats.total_flows_created = stats.total_flows_created.saturating_add(1);
            stats.active_flows = self.flows.len() as u64;
        }

        flow
    }

    pub fn get(&self, key: &FlowKey) -> Option<Flow> {
        self.maybe_cleanup();
        loop {
            let flow = self.flows.get(key)?;
            if self.flow_is_expired(&flow) {
                let observed_updated_at = flow.updated_at;
                drop(flow);
                if self.remove_expired_keys(vec![(*key, observed_updated_at)]) > 0 {
                    return None;
                }
                continue;
            }
            {
                let mut stats = self.stats.write();
                stats.cache_hits = stats.cache_hits.saturating_add(1);
            }
            return Some(flow.clone());
        }
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
        loop {
            let mut flow = self.flows.get_mut(key)?;
            if self.flow_is_expired(&flow) {
                let observed_updated_at = flow.updated_at;
                drop(flow);
                if self.remove_expired_keys(vec![(*key, observed_updated_at)]) > 0 {
                    return None;
                }
                continue;
            }
            let flow_id = flow.id;
            let five_tuple = flow.five_tuple;
            update(&mut flow);
            flow.id = flow_id;
            flow.five_tuple = five_tuple;
            let now = self.now();
            flow.updated_at = now;
            flow.metadata.last_seen = now;
            return Some(flow.clone());
        }
    }

    pub fn remove(&self, key: &FlowKey) -> Option<Flow> {
        self.maybe_cleanup();
        self.remove_internal(key)
    }

    pub fn contains(&self, key: &FlowKey) -> bool {
        self.maybe_cleanup();
        loop {
            let Some(flow) = self.flows.get(key) else {
                return false;
            };
            if self.flow_is_expired(&flow) {
                let observed_updated_at = flow.updated_at;
                drop(flow);
                if self.remove_expired_keys(vec![(*key, observed_updated_at)]) > 0 {
                    return false;
                }
                continue;
            }
            return true;
        }
    }

    pub fn len(&self) -> usize {
        self.cleanup_expired_internal(self.config.flow_timeout);
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cleanup_expired_internal(self.config.flow_timeout);
        self.flows.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = Flow> {
        self.cleanup_expired_internal(self.config.flow_timeout);
        self.flows.iter().map(|f| f.clone())
    }

    pub fn iter_keys(&self) -> impl Iterator<Item = FlowKey> + '_ {
        self.cleanup_expired_internal(self.config.flow_timeout);
        self.flows.iter().map(|f| *f.key())
    }

    pub fn find_by_process(&self, pid: ProcessId) -> Vec<Flow> {
        self.cleanup_expired_internal(self.config.flow_timeout);
        self.flows
            .iter()
            .filter(|f| {
                f.metadata
                    .process
                    .as_ref()
                    .map(|p| p.pid() == pid)
                    .unwrap_or(false)
            })
            .map(|f| f.clone())
            .collect()
    }

    pub fn find_by_destination(&self, ip: std::net::IpAddr, port: Option<u16>) -> Vec<Flow> {
        self.cleanup_expired_internal(self.config.flow_timeout);
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
        self.cleanup_expired_internal(self.config.flow_timeout);
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
        let now = (self.now)();
        let expired_keys = self.collect_expired_keys(now, timeout);
        self.remove_expired_keys(expired_keys)
    }

    fn collect_expired_keys(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        timeout: std::time::Duration,
    ) -> Vec<(FlowKey, chrono::DateTime<chrono::Utc>)> {
        self.flows
            .iter()
            .filter(|f| Self::flow_is_expired_at_with_now(now, f.updated_at, timeout))
            .map(|f| (*f.key(), f.updated_at))
            .collect()
    }

    fn remove_expired_keys(
        &self,
        expired_keys: Vec<(FlowKey, chrono::DateTime<chrono::Utc>)>,
    ) -> usize {
        let count = expired_keys.len();
        let mut removed_ids = std::collections::HashSet::with_capacity(count);
        for (key, observed_updated_at) in expired_keys {
            if let Some((_, flow)) = self
                .flows
                .remove_if(&key, |_, flow| flow.updated_at == observed_updated_at)
            {
                self.flow_index.remove(&flow.id);
                removed_ids.insert(flow.id);
            }
        }
        if !removed_ids.is_empty() {
            self.flow_order
                .write()
                .retain(|id| !removed_ids.contains(id));
            self.recent_flows
                .write()
                .retain(|id| !removed_ids.contains(id));
            let mut stats = self.stats.write();
            stats.total_flows_closed = stats
                .total_flows_closed
                .saturating_add(removed_ids.len() as u64);
            stats.active_flows = self.flows.len() as u64;
        }
        removed_ids.len()
    }

    fn flow_is_expired(&self, flow: &Flow) -> bool {
        Self::flow_is_expired_at_with_now((self.now)(), flow.updated_at, self.config.flow_timeout)
    }

    fn flow_is_expired_at_with_now(
        now: chrono::DateTime<chrono::Utc>,
        updated_at: chrono::DateTime<chrono::Utc>,
        timeout: std::time::Duration,
    ) -> bool {
        let elapsed = elapsed_since(now, updated_at);
        elapsed >= timeout
    }

    pub fn clear(&self) {
        let _insert_guard = self.insert_lock.lock();
        let keys = self
            .flows
            .iter()
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        let mut removed_flows = 0u64;
        for key in keys {
            if self.flows.remove(&key).is_some() {
                removed_flows = removed_flows.saturating_add(1);
            }
        }
        self.flow_index.clear();
        self.recent_flows.write().clear();
        self.flow_order.write().clear();
        let mut stats = self.stats.write();
        stats.total_flows_closed = stats.total_flows_closed.saturating_add(removed_flows);
        stats.active_flows = 0;
    }

    pub fn stats(&self) -> FlowManagerStats {
        self.cleanup_expired_internal(self.config.flow_timeout);
        self.stats.read().clone()
    }

    pub fn active_count(&self) -> u64 {
        self.cleanup_expired_internal(self.config.flow_timeout);
        self.flows.len() as u64
    }

    pub fn recent_flows(&self) -> Vec<FlowId> {
        self.cleanup_expired_internal(self.config.flow_timeout);
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
        while self.flows.len() >= self.config.max_flows {
            if self.evict_oldest_flow().is_none() {
                break;
            }
        }
    }

    fn evict_oldest_flow(&self) -> Option<Flow> {
        loop {
            let Some(oldest_flow) = self.flow_order.write().pop_front() else {
                let fallback_key = self.flows.iter().next().map(|entry| *entry.key())?;
                return self.remove_internal(&fallback_key);
            };
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
        stats.total_flows_closed = stats.total_flows_closed.saturating_add(1);
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

fn effective_max_flows(max_flows: usize) -> usize {
    max_flows.max(1)
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
            now: self.now,
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
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use super::*;

    static FLOW_LIVENESS_NOW_SECONDS: AtomicI64 = AtomicI64::new(0);

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
    fn update_preserves_flow_identity_indexes() {
        let manager = FlowManager::default();
        let flow = manager.get_or_create(test_flow(40020, 443));
        let key = flow.key();
        let flow_id = flow.id;

        let updated = manager
            .update(&key, |flow| {
                flow.id = FlowId::new_v4();
                flow.five_tuple = test_flow(40021, 8443);
                flow.metadata.bytes_sent = 42;
            })
            .expect("flow should exist");

        assert_eq!(updated.id, flow_id);
        assert_eq!(updated.five_tuple, flow.five_tuple);
        assert_eq!(updated.metadata.bytes_sent, 42);
        assert!(manager.get_by_id(&flow_id).is_some());
        assert!(manager.get(&key).is_some());
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
    fn zero_capacity_is_normalized_to_one_flow() {
        let manager = FlowManager::new(FlowManagerConfig {
            max_flows: 0,
            ..Default::default()
        });

        let first = manager.get_or_create(test_flow(40013, 80));
        let second = manager.get_or_create(test_flow(40014, 81));

        assert_eq!(manager.len(), 1);
        assert!(!manager.contains(&first.key()));
        assert!(manager.contains(&second.key()));
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

    #[test]
    fn get_or_create_uses_the_injected_clock_for_flow_timestamps() {
        fn fixed_now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant")
        }

        let manager = FlowManager::new(FlowManagerConfig::default()).with_now(fixed_now);
        let flow = manager.get_or_create(test_flow(40007, 53));

        assert_eq!(flow.created_at, fixed_now());
        assert_eq!(flow.updated_at, fixed_now());
        assert_eq!(flow.metadata.first_seen, fixed_now());
        assert_eq!(flow.metadata.last_seen, fixed_now());
    }

    #[test]
    fn update_uses_the_injected_clock_for_flow_metadata() {
        fn fixed_now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(1_704_067_200, 0).expect("valid instant")
        }

        let manager = FlowManager::new(FlowManagerConfig::default()).with_now(fixed_now);
        let flow = manager.get_or_create(test_flow(40008, 53));
        let key = flow.key();
        let updated = manager
            .update(&key, |flow| {
                flow.metadata.bytes_sent = 1;
                flow.update_sent(1, PacketId::nil());
            })
            .expect("flow should exist");

        assert_eq!(updated.updated_at, fixed_now());
        assert_eq!(updated.metadata.last_seen, fixed_now());
    }

    #[test]
    fn flow_is_expired_at_with_now_treats_exact_timeout_as_expired() {
        let now = chrono::Utc::now();

        assert!(FlowManager::flow_is_expired_at_with_now(
            now,
            now,
            Duration::ZERO
        ));
    }

    #[test]
    fn flow_is_expired_at_with_now_expires_future_timestamps() {
        let now = chrono::Utc::now();
        let future = now + chrono::Duration::seconds(1);

        assert!(FlowManager::flow_is_expired_at_with_now(
            now,
            future,
            Duration::from_secs(300)
        ));
    }

    #[test]
    fn read_methods_cleanup_expired_flows_before_reporting_state() {
        let manager = FlowManager::new(FlowManagerConfig {
            cleanup_interval: Duration::from_millis(5),
            flow_timeout: Duration::from_millis(10),
            ..Default::default()
        });

        let flow = manager.get_or_create(test_flow(40006, 443));
        let key = flow.key();
        thread::sleep(Duration::from_millis(20));

        assert_eq!(manager.len(), 0);
        assert!(manager.is_empty());
        assert_eq!(manager.active_count(), 0);
        assert!(!manager.contains(&key));
        assert!(manager.iter().next().is_none());
        assert!(manager.iter_keys().next().is_none());
        assert!(manager.recent_flows().is_empty());
        assert_eq!(manager.stats().active_flows, 0);
    }

    #[test]
    fn collection_reads_skip_expired_flows_before_cleanup_interval() {
        let manager = FlowManager::new(FlowManagerConfig {
            cleanup_interval: Duration::from_secs(3600),
            flow_timeout: Duration::from_millis(10),
            ..Default::default()
        });

        let flow = manager.get_or_create(test_flow(40012, 53));
        let key = flow.key();
        thread::sleep(Duration::from_millis(20));

        assert!(manager.iter().next().is_none());
        assert!(manager.iter_keys().next().is_none());
        assert!(
            manager
                .find_by_source(IpAddr::V4(Ipv4Addr::LOCALHOST), None)
                .is_empty()
        );
        assert!(
            manager
                .find_by_destination(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), Some(53))
                .is_empty()
        );
        assert!(manager.find_by_process(1234).is_empty());
        assert!(!manager.contains(&key));
        assert_eq!(manager.len(), 0);
        assert!(manager.is_empty());
        assert_eq!(manager.active_count(), 0);
        assert!(manager.recent_flows().is_empty());
        assert_eq!(manager.stats().active_flows, 0);
    }

    #[test]
    fn update_refreshes_flow_liveness_before_cleanup_interval() {
        fn liveness_now() -> chrono::DateTime<chrono::Utc> {
            chrono::DateTime::from_timestamp(
                1_700_000_000 + FLOW_LIVENESS_NOW_SECONDS.load(Ordering::SeqCst),
                0,
            )
            .expect("valid instant")
        }

        FLOW_LIVENESS_NOW_SECONDS.store(0, Ordering::SeqCst);
        let manager = FlowManager::new(FlowManagerConfig {
            cleanup_interval: Duration::from_secs(3600),
            flow_timeout: Duration::from_secs(10),
            ..Default::default()
        })
        .with_now(liveness_now);

        let flow = manager.get_or_create(test_flow(40009, 443));
        let key = flow.key();
        FLOW_LIVENESS_NOW_SECONDS.store(9, Ordering::SeqCst);

        manager
            .update(&key, |flow| {
                flow.metadata.bytes_sent = 1;
            })
            .expect("flow should exist");

        FLOW_LIVENESS_NOW_SECONDS.store(18, Ordering::SeqCst);

        let updated = manager
            .get(&key)
            .expect("updated flow should still be alive");
        assert_eq!(updated.metadata.bytes_sent, 1);
        assert_eq!(manager.active_count(), 1);
    }

    #[test]
    fn get_or_create_replaces_expired_flow_before_cleanup_interval() {
        let manager = FlowManager::new(FlowManagerConfig {
            cleanup_interval: Duration::from_secs(3600),
            flow_timeout: Duration::from_millis(10),
            ..Default::default()
        });

        let tuple = test_flow(40010, 443);
        let original = manager.get_or_create(tuple);
        thread::sleep(Duration::from_millis(20));

        let replaced = manager.get_or_create(tuple);

        assert_ne!(replaced.id, original.id);
        assert_eq!(manager.len(), 1);
        assert_eq!(manager.stats().total_flows_created, 2);
    }

    #[test]
    fn update_ignores_expired_flow_before_cleanup_interval() {
        let manager = FlowManager::new(FlowManagerConfig {
            cleanup_interval: Duration::from_secs(3600),
            flow_timeout: Duration::from_millis(10),
            ..Default::default()
        });

        let flow = manager.get_or_create(test_flow(40011, 443));
        let key = flow.key();
        thread::sleep(Duration::from_millis(20));

        assert!(
            manager
                .update(&key, |flow| flow.metadata.bytes_sent = 1)
                .is_none()
        );
        assert!(manager.get(&key).is_none());
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn clear_counts_removed_flows_as_closed() {
        let manager = FlowManager::default();
        manager.get_or_create(test_flow(40007, 80));
        manager.get_or_create(test_flow(40008, 81));

        assert_eq!(manager.stats().total_flows_created, 2);

        manager.clear();

        let stats = manager.stats();
        assert_eq!(stats.active_flows, 0);
        assert_eq!(stats.total_flows_closed, 2);
    }

    #[test]
    fn clear_serializes_with_inserts_to_keep_indexes_consistent() {
        let manager = Arc::new(FlowManager::default());
        let _insert_guard = manager.insert_lock.lock();
        let flow = Flow::new(test_flow(40018, 80));
        let key = flow.key();
        let flow_id = flow.id;

        manager.flows.insert(key, flow.clone());

        let cleared = {
            let manager = Arc::clone(&manager);
            thread::spawn(move || {
                manager.clear();
            })
        };

        thread::yield_now();

        manager.flow_index.insert(flow_id, key);
        manager.record_new_flow(flow_id);

        drop(_insert_guard);
        cleared.join().expect("clear should complete");

        assert!(manager.flows.is_empty());
        assert!(manager.flow_index.is_empty());
        assert!(manager.flow_order.read().is_empty());
        assert!(manager.recent_flows.read().is_empty());
        assert_eq!(manager.stats().active_flows, 0);
    }

    #[test]
    fn stats_counters_saturate_at_u64_max() {
        let manager = FlowManager::new(FlowManagerConfig {
            cleanup_interval: Duration::from_secs(3600),
            flow_timeout: Duration::from_secs(3600),
            ..Default::default()
        });
        let flow = manager.get_or_create(test_flow(40013, 443));
        let key = flow.key();

        {
            let mut stats = manager.stats.write();
            stats.total_flows_created = u64::MAX;
            stats.total_flows_closed = u64::MAX;
            stats.cache_hits = u64::MAX;
            stats.cache_misses = u64::MAX;
        }

        manager.get(&key).expect("flow should exist");
        manager.get_or_create(test_flow(40014, 443));
        manager.remove(&key).expect("flow should be removed");
        manager.clear();

        let stats = manager.stats();
        assert_eq!(stats.total_flows_created, u64::MAX);
        assert_eq!(stats.total_flows_closed, u64::MAX);
        assert_eq!(stats.cache_hits, u64::MAX);
        assert_eq!(stats.cache_misses, u64::MAX);
    }

    #[test]
    fn capacity_is_enforced_when_flow_order_is_empty() {
        let manager = FlowManager::with_capacity(1);
        manager.get_or_create(test_flow(40015, 80));
        manager.flow_order.write().clear();

        manager.get_or_create(test_flow(40016, 443));

        assert_eq!(manager.active_count(), 1);
        assert_eq!(manager.flow_index.len(), 1);
        assert_eq!(manager.flow_order.read().len(), 1);
    }

    #[test]
    fn cleanup_rechecks_flow_state_before_removing_expired_entries() {
        let manager = FlowManager::new(FlowManagerConfig {
            cleanup_interval: Duration::from_secs(3600),
            flow_timeout: Duration::from_millis(10),
            ..Default::default()
        });

        let flow = manager.get_or_create(test_flow(40017, 443));
        let key = flow.key();
        let now = chrono::Utc::now();
        {
            let mut updated = manager.flows.get_mut(&key).expect("flow should exist");
            updated.updated_at = now - chrono::Duration::seconds(1);
        }

        let expired_keys = manager.collect_expired_keys(now, Duration::from_millis(1));
        assert_eq!(
            expired_keys,
            vec![(key, now - chrono::Duration::seconds(1))]
        );

        {
            let mut refreshed = manager
                .flows
                .get_mut(&key)
                .expect("flow should still exist");
            refreshed.updated_at = chrono::Utc::now();
        }

        let removed = manager.remove_expired_keys(expired_keys);
        assert_eq!(removed, 0);
        assert!(manager.get(&key).is_some());
        assert_eq!(manager.active_count(), 1);
    }

    #[test]
    fn cleanup_uses_one_clock_snapshot_for_collection_and_removal() {
        static NOW_CALLS: AtomicUsize = AtomicUsize::new(0);

        fn scripted_now() -> chrono::DateTime<chrono::Utc> {
            match NOW_CALLS.fetch_add(1, Ordering::SeqCst) {
                0 => chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("valid instant"),
                1 => chrono::DateTime::from_timestamp(1_700_000_010, 0).expect("valid instant"),
                _ => chrono::DateTime::from_timestamp(1_700_000_002, 0).expect("valid instant"),
            }
        }

        NOW_CALLS.store(0, Ordering::SeqCst);

        let manager = FlowManager::new(FlowManagerConfig {
            cleanup_interval: Duration::from_secs(3600),
            flow_timeout: Duration::from_secs(5),
            ..Default::default()
        })
        .with_now(scripted_now);

        let flow = manager.get_or_create(test_flow(40019, 443));
        let key = flow.key();

        {
            let mut updated = manager.flows.get_mut(&key).expect("flow should exist");
            updated.updated_at =
                chrono::DateTime::from_timestamp(1_699_999_998, 0).expect("valid instant");
        }

        assert_eq!(manager.cleanup_expired(Duration::from_secs(5)), 1);
        assert!(manager.get(&key).is_none());
        assert_eq!(manager.active_count(), 0);
    }
}
