use crate::prelude::*;

pub type EventSender = crossbeam::channel::Sender<Event>;
pub type EventReceiver = crossbeam::channel::Receiver<Event>;

#[derive(Debug, Clone)]
pub struct EventBusConfig {
    pub buffer_size: usize,
    pub drop_on_full: bool,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            buffer_size: 10000,
            drop_on_full: false,
        }
    }
}

pub struct EventBus {
    config: EventBusConfig,
    sender: EventSender,
    receiver: EventReceiver,
    handlers: parking_lot::RwLock<hashbrown::HashMap<EventHandlerId, EventHandler>>,
    stats: parking_lot::RwLock<EventBusStats>,
}

pub type EventHandlerId = uuid::Uuid;

pub type EventHandler = std::sync::Arc<dyn EventHandlerTrait + Send + Sync>;

pub trait EventHandlerTrait {
    fn handle(&self, event: &Event) -> Result<()>;
    fn name(&self) -> &'static str;
    fn handles_event_type(&self, event_type: &str) -> bool;
}

impl EventBus {
    pub fn new(config: EventBusConfig) -> Self {
        let (sender, receiver) = crossbeam::channel::bounded(config.buffer_size);
        Self {
            config,
            sender,
            receiver,
            handlers: parking_lot::RwLock::new(hashbrown::HashMap::new()),
            stats: parking_lot::RwLock::new(EventBusStats::default()),
        }
    }
    
    pub fn new_unbounded() -> Self {
        let (sender, receiver) = crossbeam::channel::unbounded();
        Self {
            config: EventBusConfig::default(),
            sender,
            receiver,
            handlers: parking_lot::RwLock::new(hashbrown::HashMap::new()),
            stats: parking_lot::RwLock::new(EventBusStats::default()),
        }
    }
    
    pub fn emit(&self, event: Event) {
        if self.config.drop_on_full {
            let _ = self.sender.try_send(event);
        } else {
            let _ = self.sender.send(event);
        }
        self.stats.write().events_emitted += 1;
    }
    
    pub fn try_emit(&self, event: Event) -> bool {
        if self.sender.try_send(event).is_ok() {
            self.stats.write().events_emitted += 1;
            true
        } else {
            self.stats.write().events_dropped += 1;
            false
        }
    }
    
    pub fn subscribe(&self) -> EventReceiver {
        self.receiver.clone()
    }
    
    pub fn sender(&self) -> EventSender {
        self.sender.clone()
    }
    
    pub fn register_handler(&self, handler: EventHandler) -> EventHandlerId {
        let id = EventHandlerId::new_v4();
        self.handlers.write().insert(id, handler);
        id
    }
    
    pub fn unregister_handler(&self, id: EventHandlerId) {
        self.handlers.write().remove(&id);
    }
    
    pub async fn process(&self) -> Result<()> {
        while let Ok(event) = self.receiver.recv() {
            self.dispatch_to_handlers(&event)?;
            self.stats.write().events_processed += 1;
        }
        Ok(())
    }
    
    pub fn process_blocking(&self) -> Result<()> {
        while let Ok(event) = self.receiver.recv() {
            self.dispatch_to_handlers(&event)?;
            self.stats.write().events_processed += 1;
        }
        Ok(())
    }
    
    fn dispatch_to_handlers(&self, event: &Event) -> Result<()> {
        let handlers = self.handlers.read();
        for handler in handlers.values() {
            if handler.handles_event_type(event.event_type()) {
                if let Err(e) = handler.handle(event) {
                    tracing::warn!("Event handler '{}' failed: {}", handler.name(), e);
                }
            }
        }
        Ok(())
    }
    
    pub fn stats(&self) -> EventBusStats {
        self.stats.read().clone()
    }
    
    pub fn clear_handlers(&self) {
        self.handlers.write().clear();
    }
}

#[derive(Debug, Clone, Default)]
pub struct EventBusStats {
    pub events_emitted: u64,
    pub events_processed: u64,
    pub events_dropped: u64,
    pub handler_count: usize,
}

#[derive(Clone)]
pub struct BufferedEventBus {
    inner: std::sync::Arc<EventBus>,
}

impl BufferedEventBus {
    pub fn new(buffer_size: usize) -> Self {
        let config = EventBusConfig {
            buffer_size,
            drop_on_full: true,
        };
        Self {
            inner: std::sync::Arc::new(EventBus::new(config)),
        }
    }
    
    pub fn emit(&self, event: Event) {
        self.inner.try_emit(event);
    }
    
    pub fn subscribe(&self) -> EventReceiver {
        self.inner.subscribe()
    }
    
    pub fn sender(&self) -> EventSender {
        self.inner.sender()
    }
    
    pub fn stats(&self) -> EventBusStats {
        self.inner.stats()
    }
}