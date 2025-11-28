//! Event bus for publishing and subscribing to events.

use crate::{Event, EventType, IntegrationError, IntegrationResult};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info};

/// Event bus configuration.
#[derive(Debug, Clone)]
pub struct EventBusConfig {
    /// Channel capacity.
    pub channel_capacity: usize,
    /// Enable event persistence.
    pub persist_events: bool,
    /// Max events to retain in memory.
    pub max_retained_events: usize,
    /// Enable debug logging.
    pub debug_logging: bool,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 10000,
            persist_events: false,
            max_retained_events: 1000,
            debug_logging: false,
        }
    }
}

/// Event receiver handle.
pub type EventReceiver = broadcast::Receiver<Arc<Event>>;

/// Event bus for distributing events.
pub struct EventBus {
    /// Configuration.
    config: EventBusConfig,
    /// Broadcast sender.
    sender: broadcast::Sender<Arc<Event>>,
    /// Category-specific senders.
    category_senders: RwLock<HashMap<String, broadcast::Sender<Arc<Event>>>>,
    /// Recent events (for replay).
    recent_events: RwLock<Vec<Arc<Event>>>,
    /// Event counters.
    counters: RwLock<EventCounters>,
}

/// Event counters for metrics.
#[derive(Debug, Default)]
struct EventCounters {
    /// Total events published.
    published: u64,
    /// Events by type.
    by_type: HashMap<EventType, u64>,
    /// Events dropped due to no receivers.
    dropped: u64,
}

impl EventBus {
    /// Creates a new event bus.
    pub fn new(config: EventBusConfig) -> Self {
        let (sender, _) = broadcast::channel(config.channel_capacity);
        Self {
            config,
            sender,
            category_senders: RwLock::new(HashMap::new()),
            recent_events: RwLock::new(Vec::new()),
            counters: RwLock::new(EventCounters::default()),
        }
    }

    /// Creates with default configuration.
    pub fn default_config() -> Self {
        Self::new(EventBusConfig::default())
    }

    /// Publishes an event.
    pub fn publish(&self, event: Event) -> IntegrationResult<()> {
        let event = Arc::new(event);

        if self.config.debug_logging {
            debug!(
                event_id = %event.id(),
                event_type = %event.event_type(),
                "Publishing event"
            );
        }

        // Update counters
        {
            let mut counters = self.counters.write();
            counters.published += 1;
            *counters.by_type.entry(event.event_type()).or_default() += 1;
        }

        // Store in recent events
        if self.config.max_retained_events > 0 {
            let mut recent = self.recent_events.write();
            if recent.len() >= self.config.max_retained_events {
                recent.remove(0);
            }
            recent.push(Arc::clone(&event));
        }

        // Send to main channel
        match self.sender.send(Arc::clone(&event)) {
            Ok(count) => {
                if self.config.debug_logging {
                    debug!(
                        event_id = %event.id(),
                        receivers = count,
                        "Event delivered to receivers"
                    );
                }
            }
            Err(_) => {
                // No receivers, but that's okay
                self.counters.write().dropped += 1;
            }
        }

        // Send to category channel
        let category = event.event_type().category();
        let category_senders = self.category_senders.read();
        if let Some(sender) = category_senders.get(category) {
            let _ = sender.send(event);
        }

        Ok(())
    }

    /// Subscribes to all events.
    pub fn subscribe(&self) -> EventReceiver {
        self.sender.subscribe()
    }

    /// Subscribes to events of a specific category.
    pub fn subscribe_category(&self, category: &str) -> EventReceiver {
        let mut senders = self.category_senders.write();

        if let Some(sender) = senders.get(category) {
            return sender.subscribe();
        }

        // Create new category channel
        let (sender, receiver) = broadcast::channel(self.config.channel_capacity);
        senders.insert(category.to_string(), sender);
        receiver
    }

    /// Gets recent events (for replay).
    pub fn recent_events(&self) -> Vec<Arc<Event>> {
        self.recent_events.read().clone()
    }

    /// Gets recent events filtered by type.
    pub fn recent_events_by_type(&self, event_type: EventType) -> Vec<Arc<Event>> {
        self.recent_events
            .read()
            .iter()
            .filter(|e| e.event_type() == event_type)
            .cloned()
            .collect()
    }

    /// Gets event statistics.
    pub fn stats(&self) -> EventBusStats {
        let counters = self.counters.read();
        EventBusStats {
            total_published: counters.published,
            by_type: counters.by_type.clone(),
            dropped: counters.dropped,
            subscriber_count: self.sender.receiver_count(),
            retained_events: self.recent_events.read().len(),
        }
    }

    /// Clears retained events.
    pub fn clear_retained(&self) {
        self.recent_events.write().clear();
    }
}

/// Event bus statistics.
#[derive(Debug, Clone)]
pub struct EventBusStats {
    /// Total events published.
    pub total_published: u64,
    /// Events by type.
    pub by_type: HashMap<EventType, u64>,
    /// Events dropped.
    pub dropped: u64,
    /// Current subscriber count.
    pub subscriber_count: usize,
    /// Retained events count.
    pub retained_events: usize,
}

/// Typed event channel for specific event types.
pub struct TypedEventChannel<T> {
    sender: broadcast::Sender<Arc<T>>,
}

impl<T: Clone + Send + 'static> TypedEventChannel<T> {
    /// Creates a new typed channel.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Publishes a typed event.
    pub fn publish(&self, event: T) -> usize {
        self.sender.send(Arc::new(event)).unwrap_or(0)
    }

    /// Subscribes to typed events.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<T>> {
        self.sender.subscribe()
    }

    /// Returns current subscriber count.
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

/// Multi-producer single-consumer event queue.
pub struct EventQueue {
    sender: tokio::sync::mpsc::Sender<Event>,
    receiver: parking_lot::Mutex<Option<tokio::sync::mpsc::Receiver<Event>>>,
}

impl EventQueue {
    /// Creates a new event queue.
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(capacity);
        Self {
            sender,
            receiver: parking_lot::Mutex::new(Some(receiver)),
        }
    }

    /// Enqueues an event.
    pub async fn enqueue(&self, event: Event) -> IntegrationResult<()> {
        self.sender
            .send(event)
            .await
            .map_err(|_| IntegrationError::ChannelClosed)
    }

    /// Takes the receiver (can only be called once).
    pub fn take_receiver(&self) -> Option<tokio::sync::mpsc::Receiver<Event>> {
        self.receiver.lock().take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{DatasetEventPayload, EventMetadata, EventPayload};

    fn create_test_event() -> Event {
        Event::new(
            EventMetadata::new(EventType::DatasetCreated, "test"),
            EventPayload::Dataset(DatasetEventPayload {
                dataset_id: "ds-123".to_string(),
                name: Some("test".to_string()),
                schema_version: None,
                record_count: None,
                size_bytes: None,
                previous: None,
            }),
        )
    }

    #[tokio::test]
    async fn test_event_bus_publish_subscribe() {
        let bus = EventBus::default_config();
        let mut receiver = bus.subscribe();

        let event = create_test_event();
        bus.publish(event.clone()).unwrap();

        let received = receiver.recv().await.unwrap();
        assert_eq!(received.id(), event.id());
    }

    #[tokio::test]
    async fn test_event_bus_category_subscribe() {
        let bus = EventBus::default_config();
        let mut dataset_receiver = bus.subscribe_category("dataset");
        let mut access_receiver = bus.subscribe_category("access");

        let event = create_test_event();
        bus.publish(event).unwrap();

        // Dataset receiver should get it
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            dataset_receiver.recv(),
        )
        .await;
        assert!(result.is_ok());

        // Access receiver should NOT get it (different category)
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            access_receiver.recv(),
        )
        .await;
        assert!(result.is_err()); // Timeout
    }

    #[test]
    fn test_event_bus_stats() {
        let bus = EventBus::default_config();

        for _ in 0..10 {
            bus.publish(create_test_event()).unwrap();
        }

        let stats = bus.stats();
        assert_eq!(stats.total_published, 10);
        assert_eq!(stats.by_type.get(&EventType::DatasetCreated), Some(&10));
    }

    #[test]
    fn test_event_bus_recent_events() {
        let config = EventBusConfig {
            max_retained_events: 5,
            ..Default::default()
        };
        let bus = EventBus::new(config);

        for _ in 0..10 {
            bus.publish(create_test_event()).unwrap();
        }

        let recent = bus.recent_events();
        assert_eq!(recent.len(), 5);
    }

    #[tokio::test]
    async fn test_event_queue() {
        let queue = EventQueue::new(100);

        queue.enqueue(create_test_event()).await.unwrap();
        queue.enqueue(create_test_event()).await.unwrap();

        let mut receiver = queue.take_receiver().unwrap();

        let event1 = receiver.recv().await.unwrap();
        let event2 = receiver.recv().await.unwrap();

        assert_eq!(event1.event_type(), EventType::DatasetCreated);
        assert_eq!(event2.event_type(), EventType::DatasetCreated);
    }
}
