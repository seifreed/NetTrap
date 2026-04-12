use dashmap::DashMap;
use parking_lot::RwLock;
use std::time::{Duration, Instant};

use nettrap_core::prelude::*;

pub struct AttributionEngine {
    cache: DashMap<FlowKey, (Attribution, Instant)>,
    cache_timeout: Duration,
    stats: RwLock<AttributionStats>,
}

#[derive(Debug, Default, Clone)]
pub struct AttributionStats {
    pub total_requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub successful_attributions: u64,
    pub failed_attributions: u64,
    pub cache_evictions: u64,
}

impl AttributionEngine {
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
            cache_timeout: Duration::from_secs(300),
            stats: RwLock::new(AttributionStats::default()),
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            cache: DashMap::new(),
            cache_timeout: timeout,
            stats: RwLock::new(AttributionStats::default()),
        }
    }

    pub fn attribute_flow(&self, five_tuple: &FiveTuple) -> Attribution {
        self.stats.write().total_requests += 1;

        let key = five_tuple.to_flow_key();
        let now = Instant::now();

        // Use DashMap's entry API for atomic check-and-remove
        // This prevents the race condition where another thread could insert
        // between checking and removing
        if let Some(entry) = self.cache.get(&key) {
            let (attribution, timestamp) = entry.value();
            if now.duration_since(*timestamp) < self.cache_timeout {
                self.stats.write().cache_hits += 1;
                return attribution.clone();
            }
            // Entry expired - atomically remove if it still exists and is expired
            drop(entry);
            self.cache.remove_if(&key, |_, (_, ts)| {
                now.duration_since(*ts) >= self.cache_timeout
            });
            self.stats.write().cache_evictions += 1;
        }

        self.stats.write().cache_misses += 1;

        let attribution = self.perform_attribution(five_tuple);

        if attribution.confidence != AttributionConfidence::None {
            self.stats.write().successful_attributions += 1;
            self.cache.insert(key, (attribution.clone(), now));
        } else {
            self.stats.write().failed_attributions += 1;
        }

        attribution
    }

    fn perform_attribution(&self, five_tuple: &FiveTuple) -> Attribution {
        // Try source socket first — for outbound flows from local processes,
        // the source is the local endpoint, giving higher confidence.
        let result = crate::process::get_process_for_socket(
            five_tuple.src_ip,
            five_tuple.src_port,
            five_tuple.protocol,
        );

        match result {
            Some(process) => Attribution::new(
                process,
                AttributionConfidence::High,
                AttributionMethod::ConnectionTable,
            ),
            None => {
                // Fallback to destination socket (e.g. for inbound connections
                // to a local listening process).
                let result = crate::process::get_process_for_socket(
                    five_tuple.dst_ip,
                    five_tuple.dst_port,
                    five_tuple.protocol,
                );

                match result {
                    Some(process) => Attribution::new(
                        process,
                        AttributionConfidence::Medium,
                        AttributionMethod::SocketTable,
                    ),
                    None => Attribution::unknown(),
                }
            }
        }
    }

    pub fn invalidate(&self, key: &FlowKey) {
        self.cache.remove(key);
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    pub fn stats(&self) -> AttributionStats {
        self.stats.read().clone()
    }

    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .cache
            .iter()
            .filter(|entry| {
                let (_, timestamp) = entry.value();
                now.duration_since(*timestamp) >= self.cache_timeout
            })
            .map(|entry| *entry.key())
            .collect();

        for key in expired {
            self.cache.remove(&key);
            self.stats.write().cache_evictions += 1;
        }
    }
}

impl Default for AttributionEngine {
    fn default() -> Self {
        Self::new()
    }
}
