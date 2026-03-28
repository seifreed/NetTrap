use std::sync::Arc;
use parking_lot::RwLock;
use hashbrown::HashMap;

use crate::prelude::*;

pub type ListenerRef = Arc<dyn ListenerTrait + Send + Sync>;

pub struct ListenerRegistry {
    listeners: RwLock<HashMap<u16, Vec<ListenerRef>>>,
    port_index: RwLock<HashMap<u16, Vec<String>>>,
}

impl ListenerRegistry {
    pub fn new() -> Self {
        Self {
            listeners: RwLock::new(HashMap::new()),
            port_index: RwLock::new(HashMap::new()),
        }
    }
    
    pub fn register(&self, listener: ListenerRef) -> Result<()> {
        let port = listener.port();
        
        self.listeners
            .write()
            .entry(port)
            .or_default()
            .push(listener.clone());
        
        self.port_index
            .write()
            .entry(port)
            .or_default()
            .push(listener.name().to_string());
        
        tracing::debug!("Registered listener {} on port {}", listener.name(), port);
        Ok(())
    }
    
    pub fn unregister(&self, name: &str) -> Result<bool> {
        let mut removed = false;
        
        {
            let mut listeners = self.listeners.write();
            for (_port, listener_list) in listeners.iter_mut() {
                let before_len = listener_list.len();
                listener_list.retain(|l| l.name() != name);
                if listener_list.len() < before_len {
                    removed = true;
                }
            }
        }
        
        {
            let mut port_index = self.port_index.write();
            for (_, name_list) in port_index.iter_mut() {
                name_list.retain(|n| n != name);
            }
        }
        
        Ok(removed)
    }
    
    pub fn get(&self, port: u16) -> Option<Vec<ListenerRef>> {
        self.listeners.read().get(&port).cloned()
    }
    
    pub fn get_by_name(&self, name: &str) -> Option<ListenerRef> {
        for listeners in self.listeners.read().values() {
            for listener in listeners {
                if listener.name() == name {
                    return Some(listener.clone());
                }
            }
        }
        None
    }
    
    pub fn get_ports(&self) -> Vec<u16> {
        self.listeners.read().keys().copied().collect()
    }
    
    pub fn get_listeners(&self) -> Vec<ListenerRef> {
        self.listeners
            .read()
            .values()
            .flat_map(|v| v.iter().cloned())
            .collect()
    }
    
    pub async fn start_all(&self) -> Result<()> {
        for listener in self.get_listeners() {
            listener.start().await?;
        }
        Ok(())
    }
    
    pub async fn stop_all(&self) -> Result<()> {
        for listener in self.get_listeners() {
            listener.stop().await?;
        }
        Ok(())
    }
    
    pub fn count(&self) -> usize {
        self.listeners
            .read()
            .values()
            .map(|v| v.len())
            .sum()
    }
    
    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }
    
    pub fn clear(&self) {
        self.listeners.write().clear();
        self.port_index.write().clear();
    }
}

impl Default for ListenerRegistry {
    fn default() -> Self {
        Self::new()
    }
}