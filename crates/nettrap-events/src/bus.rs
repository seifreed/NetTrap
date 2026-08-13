use std::ops::Deref;
use std::sync::Arc;

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
    subscribers: Arc<parking_lot::RwLock<hashbrown::HashMap<SubscriberId, EventSender>>>,
    handlers: parking_lot::RwLock<hashbrown::HashMap<EventHandlerId, EventHandler>>,
    stats: Arc<parking_lot::RwLock<EventBusStats>>,
}

pub type EventHandlerId = uuid::Uuid;

pub type EventHandler = std::sync::Arc<dyn EventHandlerTrait + Send + Sync>;

pub trait EventHandlerTrait {
    fn handle(&self, event: &Event) -> Result<()>;
    fn name(&self) -> &'static str;
    fn handles_event_type(&self, event_type: &str) -> bool;
}

pub struct EventSubscription {
    id: SubscriberId,
    receiver: EventReceiver,
    subscribers: Arc<parking_lot::RwLock<hashbrown::HashMap<SubscriberId, EventSender>>>,
    stats: Arc<parking_lot::RwLock<EventBusStats>>,
}

impl Deref for EventSubscription {
    type Target = EventReceiver;

    fn deref(&self) -> &Self::Target {
        &self.receiver
    }
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        if self.subscribers.write().remove(&self.id).is_some() {
            self.stats.write().subscriber_count = self.subscribers.read().len();
        }
    }
}

impl EventBus {
    pub fn new(config: EventBusConfig) -> Self {
        let (sender, receiver) = Self::channel_pair(true, config.buffer_size);
        Self {
            config,
            bounded: true,
            sender,
            receiver,
            subscribers: Arc::new(parking_lot::RwLock::new(hashbrown::HashMap::new())),
            handlers: parking_lot::RwLock::new(hashbrown::HashMap::new()),
            stats: Arc::new(parking_lot::RwLock::new(EventBusStats::default())),
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
            subscribers: Arc::new(parking_lot::RwLock::new(hashbrown::HashMap::new())),
            handlers: parking_lot::RwLock::new(hashbrown::HashMap::new()),
            stats: Arc::new(parking_lot::RwLock::new(EventBusStats::default())),
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
        self.publish(&event, false)
            .is_ok_and(|outcome| outcome.dropped == 0)
    }

    pub fn subscribe(&self) -> EventSubscription {
        let id = SubscriberId::new_v4();
        let (sender, receiver) = Self::channel_pair(self.bounded, self.config.buffer_size);
        self.subscribers.write().insert(id, sender);
        self.stats.write().subscriber_count = self.subscribers.read().len();
        EventSubscription {
            id,
            receiver,
            subscribers: Arc::clone(&self.subscribers),
            stats: Arc::clone(&self.stats),
        }
    }

    pub fn sender(&self) -> EventSender {
        self.sender.clone()
    }

    pub fn register_handler(&self, handler: EventHandler) -> EventHandlerId {
        let id = EventHandlerId::new_v4();
        self.handlers.write().insert(id, handler);
        self.stats.write().handler_count = self.handlers.read().len();
        id
    }

    pub fn unregister_handler(&self, id: EventHandlerId) {
        if self.handlers.write().remove(&id).is_some() {
            self.stats.write().handler_count = self.handlers.read().len();
        }
    }

    pub async fn process(&self) -> Result<()> {
        loop {
            match self.receiver.try_recv() {
                Ok(event) => {
                    self.publish(&event, false)?;
                    self.record_processed_event();
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
            self.record_processed_event();
        }
        Ok(())
    }

    fn dispatch_to_handlers(&self, event: &Event) -> Result<()> {
        let handlers = self.handlers.read().values().cloned().collect::<Vec<_>>();
        for handler in handlers {
            if handler.handles_event_type(event.event_type())
                && let Err(e) = handler.handle(event)
            {
                tracing::warn!("Event handler '{}' failed: {}", handler.name(), e);
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

    fn record_processed_event(&self) {
        let mut stats = self.stats.write();
        stats.events_processed = stats.events_processed.saturating_add(1);
    }

    fn channel_pair(bounded: bool, buffer_size: usize) -> (EventSender, EventReceiver) {
        if bounded {
            crossbeam::channel::bounded(effective_bounded_buffer_size(buffer_size))
        } else {
            crossbeam::channel::unbounded()
        }
    }

    fn publish(&self, event: &Event, block_on_full: bool) -> Result<PublishOutcome> {
        self.dispatch_to_handlers(event)?;

        let mut delivered = 0u64;
        let mut dropped = 0u64;
        let mut disconnected = Vec::new();

        let subscribers = self
            .subscribers
            .read()
            .iter()
            .map(|(id, sender)| (*id, sender.clone()))
            .collect::<Vec<_>>();
        for (id, sender) in subscribers {
            match Self::send_to_subscriber(&sender, event, block_on_full) {
                Ok(()) => delivered += 1,
                Err(SendOutcome::Full) => {
                    dropped += 1;
                }
                Err(SendOutcome::Disconnected) => {
                    dropped += 1;
                    disconnected.push(id);
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
        stats.events_emitted = stats.events_emitted.saturating_add(1);
        stats.deliveries_attempted = stats
            .deliveries_attempted
            .saturating_add(delivered.saturating_add(dropped));
        stats.deliveries_completed = stats.deliveries_completed.saturating_add(delivered);
        stats.deliveries_dropped = stats.deliveries_dropped.saturating_add(dropped);
        if dropped > 0 {
            stats.events_dropped = stats.events_dropped.saturating_add(1);
            if stats.deliveries_dropped % 1000 == 1 {
                drop(stats);
                tracing::warn!("Event bus dropping subscriber deliveries");
            }
        }

        Ok(PublishOutcome { dropped })
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

fn effective_bounded_buffer_size(buffer_size: usize) -> usize {
    buffer_size.max(1)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PublishOutcome {
    dropped: u64,
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

    pub fn subscribe(&self) -> EventSubscription {
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

    struct NoopHandler;

    impl EventHandlerTrait for NoopHandler {
        fn handle(&self, _event: &Event) -> Result<()> {
            Ok(())
        }

        fn name(&self) -> &'static str {
            "noop"
        }

        fn handles_event_type(&self, _event_type: &str) -> bool {
            true
        }
    }

    struct RegisteringHandler {
        bus: Arc<EventBus>,
    }

    impl EventHandlerTrait for RegisteringHandler {
        fn handle(&self, _event: &Event) -> Result<()> {
            self.bus.register_handler(Arc::new(NoopHandler));
            Ok(())
        }

        fn name(&self) -> &'static str {
            "registering"
        }

        fn handles_event_type(&self, _event_type: &str) -> bool {
            true
        }
    }

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
    fn zero_buffer_is_normalized_to_one_slot_for_drop_mode() {
        let bus = EventBus::new(EventBusConfig {
            buffer_size: 0,
            drop_on_full: true,
        });
        let receiver = bus.subscribe();

        bus.emit(warning_event("first"));
        bus.emit(warning_event("second"));

        let first = receiver
            .recv_timeout(Duration::from_millis(200))
            .expect("first event should be buffered");
        assert_eq!(first.event_type(), "warning");
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());

        let stats = bus.stats();
        assert_eq!(stats.events_emitted, 2);
        assert_eq!(stats.events_dropped, 1);
        assert_eq!(stats.deliveries_completed, 1);
        assert_eq!(stats.deliveries_dropped, 1);
    }

    #[test]
    fn buffered_event_bus_zero_buffer_still_delivers_one_event() {
        let bus = BufferedEventBus::new(0);
        let receiver = bus.subscribe();

        bus.emit(warning_event("first"));
        bus.emit(warning_event("second"));

        let first = receiver
            .recv_timeout(Duration::from_millis(200))
            .expect("first event should be buffered");
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
    fn try_emit_reports_false_when_delivery_is_dropped() {
        let bus = EventBus::new(EventBusConfig {
            buffer_size: 1,
            drop_on_full: true,
        });
        let _receiver = bus.subscribe();

        assert!(bus.try_emit(warning_event("first")));
        assert!(!bus.try_emit(warning_event("second")));

        let stats = bus.stats();
        assert_eq!(stats.events_emitted, 2);
        assert_eq!(stats.events_dropped, 1);
        assert_eq!(stats.deliveries_dropped, 1);
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
    fn dropping_full_subscription_unblocks_blocking_emit() {
        let bus = Arc::new(EventBus::new(EventBusConfig {
            buffer_size: 1,
            drop_on_full: false,
        }));
        let receiver = bus.subscribe();
        bus.emit_blocking(warning_event("first"));

        let (producer_done_tx, producer_done_rx) = std::sync::mpsc::channel();
        let producer = {
            let bus = Arc::clone(&bus);
            std::thread::spawn(move || {
                bus.emit_blocking(warning_event("second"));
                producer_done_tx.send(()).ok();
            })
        };

        std::thread::sleep(Duration::from_millis(50));
        assert!(producer_done_rx.try_recv().is_err());

        let (drop_done_tx, drop_done_rx) = std::sync::mpsc::channel();
        let dropper = std::thread::spawn(move || {
            drop(receiver);
            drop_done_tx.send(()).ok();
        });

        drop_done_rx
            .recv_timeout(Duration::from_millis(200))
            .expect("subscription drop should not wait behind a blocking publish");
        producer_done_rx
            .recv_timeout(Duration::from_millis(200))
            .expect("blocked publisher should finish after receiver closes");
        dropper.join().expect("dropper should finish");
        producer.join().expect("producer should finish");

        let stats = bus.stats();
        assert_eq!(stats.subscriber_count, 0);
        assert_eq!(stats.events_emitted, 2);
        assert_eq!(stats.events_dropped, 1);
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

    #[test]
    fn dropping_subscription_updates_subscriber_count_without_publish() {
        let bus = EventBus::new(EventBusConfig {
            buffer_size: 4,
            drop_on_full: false,
        });

        {
            let _subscription = bus.subscribe();
            assert_eq!(bus.stats().subscriber_count, 1);
        }

        assert_eq!(bus.stats().subscriber_count, 0);
    }

    #[test]
    fn handler_can_register_handler_without_deadlocking_dispatch() {
        let bus = Arc::new(EventBus::new(EventBusConfig {
            buffer_size: 4,
            drop_on_full: false,
        }));
        bus.register_handler(Arc::new(RegisteringHandler {
            bus: Arc::clone(&bus),
        }));

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let dispatcher = {
            let bus = Arc::clone(&bus);
            std::thread::spawn(move || {
                bus.emit(warning_event("reentrant"));
                done_tx.send(()).ok();
            })
        };

        done_rx
            .recv_timeout(Duration::from_millis(200))
            .expect("handler registration should not deadlock dispatch");
        dispatcher.join().expect("dispatcher should finish");
        assert_eq!(bus.stats().handler_count, 2);
    }

    #[test]
    fn emit_saturates_stats_counters_at_u64_max() {
        let bus = EventBus::new(EventBusConfig {
            buffer_size: 1,
            drop_on_full: true,
        });
        let _subscription = bus.subscribe();

        {
            let mut stats = bus.stats.write();
            stats.events_emitted = u64::MAX;
            stats.events_dropped = u64::MAX;
            stats.deliveries_attempted = u64::MAX - 1;
            stats.deliveries_completed = u64::MAX;
            stats.deliveries_dropped = u64::MAX;
        }

        bus.emit(warning_event("first"));
        bus.emit(warning_event("second"));

        let stats = bus.stats();
        assert_eq!(stats.events_emitted, u64::MAX);
        assert_eq!(stats.events_dropped, u64::MAX);
        assert_eq!(stats.deliveries_attempted, u64::MAX);
        assert_eq!(stats.deliveries_completed, u64::MAX);
        assert_eq!(stats.deliveries_dropped, u64::MAX);
    }

    #[test]
    fn record_processed_event_saturates_processed_counter_at_u64_max() {
        let bus = EventBus::new(EventBusConfig {
            buffer_size: 1,
            drop_on_full: true,
        });
        bus.stats.write().events_processed = u64::MAX;

        bus.record_processed_event();

        assert_eq!(bus.stats().events_processed, u64::MAX);
    }
}
