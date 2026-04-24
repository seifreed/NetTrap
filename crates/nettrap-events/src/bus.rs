use crate::prelude::*;

pub type EventSender = crossbeam::channel::Sender<Event>;
pub type EventReceiver = crossbeam::channel::Receiver<Event>;
type SubscriberId = uuid::Uuid;

#[derive(Debug, Clone)]
pub struct EventBusConfig {
    pub buffer_size: usize,
    pub drop_on_full: bool,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            buffer_size: 10000,
            drop_on_full: true,
        }
    }
}

pub struct EventBus {
    config: EventBusConfig,
    bounded: bool,
    sender: EventSender,
    receiver: EventReceiver,
    subscribers: parking_lot::RwLock<hashbrown::HashMap<SubscriberId, EventSender>>,
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
        let (sender, receiver) = Self::channel_pair(true, config.buffer_size);
        Self {
            config,
            bounded: true,
            sender,
            receiver,
            subscribers: parking_lot::RwLock::new(hashbrown::HashMap::new()),
            handlers: parking_lot::RwLock::new(hashbrown::HashMap::new()),
            stats: parking_lot::RwLock::new(EventBusStats::default()),
        }
    }

    /// Creates an unbounded event bus.
    ///
    /// # Warning
    /// Unbounded channels can grow without limit if producers outpace consumers,
    /// potentially causing memory exhaustion. Prefer `new()` with a bounded buffer
    /// for production use, or ensure consumers process events at least as fast as
    /// producers generate them.
    pub fn new_unbounded() -> Self {
        let (sender, receiver) = Self::channel_pair(false, 0);
        Self {
            config: EventBusConfig::default(),
            bounded: false,
            sender,
            receiver,
            subscribers: parking_lot::RwLock::new(hashbrown::HashMap::new()),
            handlers: parking_lot::RwLock::new(hashbrown::HashMap::new()),
            stats: parking_lot::RwLock::new(EventBusStats::default()),
        }
    }

    pub fn emit(&self, event: Event) {
        if let Err(err) = self.publish(&event, !self.config.drop_on_full) {
            tracing::warn!(
                "Event bus failed to publish '{}': {}",
                event.event_type(),
                err
            );
        }
    }

    pub fn emit_blocking(&self, event: Event) {
        if let Err(err) = self.publish(&event, true) {
            tracing::warn!(
                "Event bus failed to publish '{}': {}",
                event.event_type(),
                err
            );
        }
    }

    pub fn try_emit(&self, event: Event) -> bool {
        self.publish(&event, false).is_ok()
    }

    pub fn subscribe(&self) -> EventReceiver {
        let id = SubscriberId::new_v4();
        let (sender, receiver) = Self::channel_pair(self.bounded, self.config.buffer_size);
        self.subscribers.write().insert(id, sender);
        self.stats.write().subscriber_count = self.subscribers.read().len();
        receiver
    }

    pub fn sender(&self) -> EventSender {
        self.sender.clone()
    }

    pub fn register_handler(&self, handler: EventHandler) -> EventHandlerId {
        let id = EventHandlerId::new_v4();
        self.handlers.write().insert(id, handler);
        self.stats.write().handler_count += 1;
        id
    }

    pub fn unregister_handler(&self, id: EventHandlerId) {
        if self.handlers.write().remove(&id).is_some() {
            self.stats.write().handler_count -= 1;
        }
    }

    pub async fn process(&self) -> Result<()> {
        loop {
            match self.receiver.try_recv() {
                Ok(event) => {
                    self.publish(&event, false)?;
                    self.stats.write().events_processed += 1;
                }
                Err(crossbeam::channel::TryRecvError::Empty) => {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                Err(crossbeam::channel::TryRecvError::Disconnected) => {
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn process_blocking(&self) -> Result<()> {
        while let Ok(event) = self.receiver.recv() {
            self.publish(&event, true)?;
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
        self.stats.write().handler_count = 0;
    }

    fn channel_pair(bounded: bool, buffer_size: usize) -> (EventSender, EventReceiver) {
        if bounded {
            crossbeam::channel::bounded(buffer_size)
        } else {
            crossbeam::channel::unbounded()
        }
    }

    fn publish(&self, event: &Event, block_on_full: bool) -> Result<()> {
        self.dispatch_to_handlers(event)?;

        let mut delivered = 0u64;
        let mut dropped = 0u64;
        let mut disconnected = Vec::new();

        {
            let subscribers = self.subscribers.read();
            for (id, sender) in subscribers.iter() {
                match Self::send_to_subscriber(sender, event, block_on_full) {
                    Ok(()) => delivered += 1,
                    Err(SendOutcome::Full) => {
                        dropped += 1;
                    }
                    Err(SendOutcome::Disconnected) => {
                        dropped += 1;
                        disconnected.push(*id);
                    }
                }
            }
        }

        if !disconnected.is_empty() {
            let mut subscribers = self.subscribers.write();
            for id in disconnected {
                subscribers.remove(&id);
            }
            self.stats.write().subscriber_count = subscribers.len();
        }

        let mut stats = self.stats.write();
        stats.events_emitted += 1;
        stats.deliveries_attempted += delivered + dropped;
        stats.deliveries_completed += delivered;
        stats.deliveries_dropped += dropped;
        if dropped > 0 {
            stats.events_dropped += 1;
            if stats.deliveries_dropped % 1000 == 1 {
                drop(stats);
                tracing::warn!("Event bus dropping subscriber deliveries");
            }
        }

        Ok(())
    }

    fn send_to_subscriber(
        sender: &EventSender,
        event: &Event,
        block_on_full: bool,
    ) -> std::result::Result<(), SendOutcome> {
        match sender.try_send(event.clone()) {
            Ok(()) => Ok(()),
            Err(crossbeam::channel::TrySendError::Full(event)) if block_on_full => {
                sender.send(event).map_err(|_| SendOutcome::Disconnected)
            }
            Err(crossbeam::channel::TrySendError::Full(_)) => Err(SendOutcome::Full),
            Err(crossbeam::channel::TrySendError::Disconnected(_)) => {
                Err(SendOutcome::Disconnected)
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct EventBusStats {
    pub events_emitted: u64,
    pub events_processed: u64,
    pub events_dropped: u64,
    pub deliveries_attempted: u64,
    pub deliveries_completed: u64,
    pub deliveries_dropped: u64,
    pub handler_count: usize,
    pub subscriber_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendOutcome {
    Full,
    Disconnected,
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    fn warning_event(message: &str) -> Event {
        Event::Warning(WarningEvent {
            timestamp: nettrap_core::timestamp::now(),
            message: message.to_string(),
            flow_id: None,
        })
    }

    #[test]
    fn emit_drops_when_buffer_is_full_and_drop_mode_is_enabled() {
        let bus = EventBus::new(EventBusConfig {
            buffer_size: 1,
            drop_on_full: true,
        });
        let receiver = bus.subscribe();

        bus.emit(warning_event("first"));
        bus.emit(warning_event("second"));

        let first = receiver
            .recv_timeout(Duration::from_millis(200))
            .expect("first event should be delivered");
        assert_eq!(first.event_type(), "warning");
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());

        let stats = bus.stats();
        assert_eq!(stats.events_emitted, 2);
        assert_eq!(stats.events_dropped, 1);
        assert_eq!(stats.deliveries_completed, 1);
        assert_eq!(stats.deliveries_dropped, 1);
    }

    #[test]
    fn emit_applies_backpressure_when_drop_mode_is_disabled() {
        let bus = Arc::new(EventBus::new(EventBusConfig {
            buffer_size: 1,
            drop_on_full: false,
        }));
        let receiver = bus.subscribe();

        bus.emit(warning_event("first"));

        let producer = {
            let bus = Arc::clone(&bus);
            std::thread::spawn(move || bus.emit(warning_event("second")))
        };

        std::thread::sleep(Duration::from_millis(50));
        assert!(!producer.is_finished());

        let first = receiver
            .recv_timeout(Duration::from_millis(200))
            .expect("first event should be available");
        assert_eq!(first.event_type(), "warning");

        producer
            .join()
            .expect("producer should unblock once capacity frees");

        let second = receiver
            .recv_timeout(Duration::from_millis(200))
            .expect("second event should be delivered after backpressure");
        assert_eq!(second.event_type(), "warning");

        let stats = bus.stats();
        assert_eq!(stats.events_emitted, 2);
        assert_eq!(stats.events_dropped, 0);
        assert_eq!(stats.deliveries_completed, 2);
        assert_eq!(stats.deliveries_dropped, 0);
    }

    #[test]
    fn emit_blocking_applies_backpressure_without_tokio_runtime() {
        let bus = Arc::new(EventBus::new(EventBusConfig {
            buffer_size: 1,
            drop_on_full: false,
        }));
        let receiver = bus.subscribe();

        bus.emit_blocking(warning_event("first"));

        let producer = {
            let bus = Arc::clone(&bus);
            std::thread::spawn(move || bus.emit_blocking(warning_event("second")))
        };

        std::thread::sleep(Duration::from_millis(50));
        assert!(!producer.is_finished());

        let first = receiver
            .recv_timeout(Duration::from_millis(200))
            .expect("first event should be available");
        assert_eq!(first.event_type(), "warning");

        producer
            .join()
            .expect("producer should unblock once capacity frees");

        let second = receiver
            .recv_timeout(Duration::from_millis(200))
            .expect("second event should be delivered after backpressure");
        assert_eq!(second.event_type(), "warning");

        let stats = bus.stats();
        assert_eq!(stats.events_emitted, 2);
        assert_eq!(stats.events_dropped, 0);
    }

    #[test]
    fn subscribe_receives_broadcast_copy_for_each_subscriber() {
        let bus = EventBus::new(EventBusConfig {
            buffer_size: 4,
            drop_on_full: false,
        });
        let left = bus.subscribe();
        let right = bus.subscribe();

        bus.emit(warning_event("fanout"));

        let left_event = left
            .recv_timeout(Duration::from_millis(200))
            .expect("left subscriber should receive event");
        let right_event = right
            .recv_timeout(Duration::from_millis(200))
            .expect("right subscriber should receive event");

        assert_eq!(left_event.event_type(), "warning");
        assert_eq!(right_event.event_type(), "warning");

        let stats = bus.stats();
        assert_eq!(stats.events_emitted, 1);
        assert_eq!(stats.subscriber_count, 2);
        assert_eq!(stats.deliveries_attempted, 2);
        assert_eq!(stats.deliveries_completed, 2);
    }
}
