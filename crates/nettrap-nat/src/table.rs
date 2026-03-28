use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashMap;

use nettrap_core::prelude::*;

use crate::nat::NatEntry;

pub struct NatTable {
    entries: DashMap<FlowKey, NatEntry>,
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

    fn allocate(&mut self, key: FlowKey) -> u16 {
        let port = self.next_port;
        self.next_port = if self.next_port == u16::MAX {
            40000
        } else {
            self.next_port + 1
        };
        self.allocated.insert(port, key);
        port
    }

    fn release(&mut self, port: u16) {
        self.allocated.remove(&port);
    }
}

impl NatTable {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
            port_pool: RwLock::new(PortPool::new()),
        }
    }

    pub fn create_nat(&self, five_tuple: FiveTuple) -> FiveTuple {
        let port = self.port_pool.write().allocate(five_tuple.to_flow_key());

        let translated = FiveTuple::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 100, 1)),
            five_tuple.dst_ip,
            port,
            five_tuple.dst_port,
            five_tuple.protocol,
        );

        let entry = NatEntry::new(five_tuple, translated);
        self.entries.insert(five_tuple.to_flow_key(), entry);

        translated
    }

    pub fn translate_outbound(&self, five_tuple: &FiveTuple) -> Option<FiveTuple> {
        self.entries
            .get(&five_tuple.to_flow_key())
            .map(|e| e.translated)
    }

    pub fn translate_inbound(&self, five_tuple: &FiveTuple) -> Option<FiveTuple> {
        let reverse = five_tuple.reverse();
        self.entries
            .get(&reverse.to_flow_key())
            .map(|e| e.original)
    }

    pub fn remove(&self, key: &FlowKey) {
        if let Some((_, entry)) = self.entries.remove(key) {
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
        self.port_pool.write().allocated.clear();
    }
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new()
    }
}
