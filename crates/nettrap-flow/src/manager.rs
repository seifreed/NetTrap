use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::VecDeque;

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
    config: FlowManagerConfig,
    stats: RwLock<FlowManagerStats>,
}

impl FlowManager {
    pub fn new(config: FlowManagerConfig) -> Self {
        Self {
            flows: DashMap::new(),
            flow_index: DashMap::new(),
            recent_flows: RwLock::new(VecDeque::with_capacity(1000)),
            config,
            stats: RwLock::new(FlowManagerStats::default()),
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
        let key = FlowKey::from_five_tuple(&five_tuple);

        if let Some(flow) = self.flows.get(&key) {
            self.stats.write().cache_hits += 1;
            return flow.clone();
        }

        self.stats.write().cache_misses += 1;

        let flow = Flow::new(five_tuple);
        let flow_id = flow.id;

        self.flows.insert(key, flow.clone());
        self.flow_index.insert(flow_id, key);

        self.stats.write().total_flows_created += 1;
        self.stats.write().active_flows = self.flows.len() as u64;

        let mut recent = self.recent_flows.write();
        recent.push_back(flow_id);
        if recent.len() > 1000 {
            recent.pop_front();
        }

        flow
    }

    pub fn get(&self, key: &FlowKey) -> Option<Flow> {
        self.flows.get(key).map(|f| {
            self.stats.write().cache_hits += 1;
            f.clone()
        })
    }

    pub fn get_by_id(&self, id: &FlowId) -> Option<Flow> {
        let key = self.flow_index.get(id)?;
        self.get(&key)
    }

    pub fn update<F>(&self, key: &FlowKey, update: F) -> Option<Flow>
    where
        F: FnOnce(&mut Flow),
    {
        let flow = self.flows.get(key)?;
        let mut flow = flow.clone();
        update(&mut flow);
        self.flows.insert(*key, flow.clone());
        Some(flow)
    }

    pub fn remove(&self, key: &FlowKey) -> Option<Flow> {
        if let Some((_, flow)) = self.flows.remove(key) {
            self.flow_index.remove(&flow.id);
            self.stats.write().total_flows_closed += 1;
            self.stats.write().active_flows = self.flows.len() as u64;
            Some(flow)
        } else {
            None
        }
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
        for key in expired_keys {
            self.remove(&key);
        }
        count
    }

    pub fn clear(&self) {
        self.flows.clear();
        self.flow_index.clear();
        self.recent_flows.write().clear();
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
}

impl Default for FlowManager {
    fn default() -> Self {
        Self::new(FlowManagerConfig::default())
    }
}

impl Clone for FlowManager {
    fn clone(&self) -> Self {
        Self {
            flows: self.flows.clone(),
            flow_index: self.flow_index.clone(),
            recent_flows: RwLock::new(self.recent_flows.read().clone()),
            config: self.config.clone(),
            stats: RwLock::new(self.stats.read().clone()),
        }
    }
}
