use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use std::time::{Duration, Instant};

use nettrap_core::prelude::*;

const MAX_CACHE_ENTRIES: usize = 10_000;

pub struct AttributionEngine {
    cache: DashMap<FlowKey, (Attribution, Instant)>,
    cache_insert_lock: Mutex<()>,
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
            cache_insert_lock: Mutex::new(()),
            cache_timeout: Duration::from_secs(300),
            stats: RwLock::new(AttributionStats::default()),
        }
    }

    pub fn with_cache_timeout(timeout: Duration) -> Self {
        Self {
            cache: DashMap::new(),
            cache_insert_lock: Mutex::new(()),
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
            // Entry expired - atomically remove if it still exists and is expired.
            // Only count an eviction when this call actually removed the entry:
            // `remove_if` returns `None` when a concurrent thread already removed
            // or refreshed it, so incrementing unconditionally double-counts under
            // contention (or counts an eviction that never happened).
            drop(entry);
            let removed = self
                .cache
                .remove_if(&key, |_, (_, ts)| {
                    now.duration_since(*ts) >= self.cache_timeout
                })
                .is_some();
            if removed {
                self.stats.write().cache_evictions += 1;
            }
        }

        self.stats.write().cache_misses += 1;

        let attribution = self.perform_attribution(five_tuple);

        if attribution.confidence != AttributionConfidence::None {
            self.stats.write().successful_attributions += 1;
            self.insert_cache_entry(key, attribution.clone(), now);
        } else {
            self.stats.write().failed_attributions += 1;
        }

        attribution
    }

    fn insert_cache_entry(&self, key: FlowKey, attribution: Attribution, timestamp: Instant) {
        let _guard = self.cache_insert_lock.lock();
        while !self.cache.contains_key(&key) && self.cache.len() >= MAX_CACHE_ENTRIES {
            let Some(oldest_key) = self
                .cache
                .iter()
                .min_by_key(|entry| entry.value().1)
                .map(|entry| *entry.key())
            else {
                break;
            };
            if self.cache.remove(&oldest_key).is_some() {
                self.stats.write().cache_evictions += 1;
            }
        }
        self.cache.insert(key, (attribution, timestamp));
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
            .map(|entry| (*entry.key(), entry.value().1))
            .collect();

        for (key, timestamp) in expired {
            if self
                .cache
                .remove_if(&key, |_, (_, current_timestamp)| {
                    *current_timestamp == timestamp
                })
                .is_some()
            {
                self.stats.write().cache_evictions += 1;
            }
        }
    }
}

impl Default for AttributionEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_insert_evicts_oldest_entry_at_capacity() {
        let engine = AttributionEngine::new();
        let attribution = Attribution::unknown();

        for key in 0..=MAX_CACHE_ENTRIES {
            engine.insert_cache_entry(FlowKey(key as u64), attribution.clone(), Instant::now());
        }

        assert_eq!(engine.cache_size(), MAX_CACHE_ENTRIES);
        assert_eq!(engine.stats().cache_evictions, 1);
    }

    #[test]
    fn cleanup_does_not_remove_a_refreshed_entry() {
        let engine = AttributionEngine::with_cache_timeout(Duration::from_secs(1));
        let key = FlowKey(1);
        let attribution = Attribution::unknown();

        engine.insert_cache_entry(
            key,
            attribution.clone(),
            Instant::now() - Duration::from_secs(2),
        );
        engine.insert_cache_entry(key, attribution, Instant::now());
        engine.cleanup_expired();

        assert_eq!(engine.cache_size(), 1);
        assert_eq!(engine.stats().cache_evictions, 0);
    }
}
