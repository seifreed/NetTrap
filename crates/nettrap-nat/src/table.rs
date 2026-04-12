use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashMap;

use nettrap_core::prelude::*;

use crate::nat::NatEntry;

pub struct NatTable {
    entries: DashMap<FlowKey, NatEntry>,
    translated_index: DashMap<FlowKey, FlowKey>,
    port_pool: RwLock<PortPool>,
}

struct PortPool {
    next_port: u16,
    allocated: HashMap<u16, FlowKey>,
}

impl PortPool {
    fn new() -> Self {
        Self {
            next_port: 40000,
            allocated: HashMap::new(),
        }
    }

    fn allocate(&mut self, key: FlowKey) -> Result<u16> {
        const MAX_ATTEMPTS: u16 = (u16::MAX - 40000) + 1;
        for _ in 0..MAX_ATTEMPTS {
            let port = self.next_port;
            self.next_port = if self.next_port == u16::MAX {
                40000
            } else {
                self.next_port + 1
            };
            if let std::collections::hash_map::Entry::Vacant(e) = self.allocated.entry(port) {
                e.insert(key);
                return Ok(port);
            }
        }
        Err(Error::Nat("Port pool exhausted".to_string()))
    }

    fn release(&mut self, port: u16) {
        self.allocated.remove(&port);
    }
}

impl NatTable {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            translated_index: DashMap::new(),
            port_pool: RwLock::new(PortPool::new()),
        }
    }

    pub fn create_nat(&self, five_tuple: FiveTuple) -> Result<FiveTuple> {
        let port = self.port_pool.write().allocate(five_tuple.to_flow_key())?;

        let translated = FiveTuple::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 100, 1)),
            five_tuple.dst_ip,
            port,
            five_tuple.dst_port,
            five_tuple.protocol,
        );

        let entry = NatEntry::new(five_tuple, translated);
        let original_key = five_tuple.to_flow_key();
        self.translated_index
            .insert(translated.to_flow_key(), original_key);
        self.entries.insert(original_key, entry);

        Ok(translated)
    }

    pub fn translate_outbound(&self, five_tuple: &FiveTuple) -> Option<FiveTuple> {
        self.entries
            .get(&five_tuple.to_flow_key())
            .map(|e| e.translated)
    }

    pub fn translate_inbound(&self, five_tuple: &FiveTuple) -> Option<FiveTuple> {
        let translated_key = five_tuple.reverse().to_flow_key();
        let original_key = *self.translated_index.get(&translated_key)?;
        self.entries.get(&original_key).map(|e| e.original)
    }

    pub fn remove(&self, key: &FlowKey) {
        if let Some((_, entry)) = self.entries.remove(key) {
            self.translated_index
                .remove(&entry.translated.to_flow_key());
            self.port_pool.write().release(entry.translated.src_port);
        }
    }

    pub fn get(&self, key: &FlowKey) -> Option<NatEntry> {
        self.entries.get(key).map(|e| NatEntry {
            original: e.original,
            translated: e.translated,
            created_at: e.created_at,
            last_used: e.last_used,
            bytes_sent: e.bytes_sent,
            bytes_received: e.bytes_received,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&self) {
        self.entries.clear();
        self.translated_index.clear();
        self.port_pool.write().allocated.clear();
    }
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_inbound_resolves_via_translated_tuple() {
        let table = NatTable::new();
        let original = FiveTuple::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 10)),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
            42424,
            443,
            Protocol::Tcp,
        );

        let translated = table
            .create_nat(original)
            .expect("nat entry should be created");
        let inbound = FiveTuple::new(
            translated.dst_ip,
            translated.src_ip,
            translated.dst_port,
            translated.src_port,
            translated.protocol,
        );

        assert_eq!(table.translate_outbound(&original), Some(translated));
        assert_eq!(table.translate_inbound(&inbound), Some(original));
    }
}
