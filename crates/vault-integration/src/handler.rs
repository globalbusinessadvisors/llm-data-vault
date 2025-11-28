//! Event handlers and registry.

use crate::{Event, EventType, IntegrationError, IntegrationResult};
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info};

/// Event handler trait.
#[async_trait]
pub trait EventHandler: Send + Sync {
    /// Returns the handler name.
    fn name(&self) -> &str;

    /// Returns the event types this handler processes.
    fn handles(&self) -> Vec<EventType>;

    /// Handles an event.
    async fn handle(&self, event: &Event) -> IntegrationResult<()>;

    /// Returns the priority (higher = processed first).
    fn priority(&self) -> i32 {
        0
    }

    /// Returns true if the handler should continue processing on error.
    fn continue_on_error(&self) -> bool {
        true
    }
}

/// Handler registration.
struct HandlerRegistration {
    /// Handler instance.
    handler: Arc<dyn EventHandler>,
    /// Is enabled.
    enabled: bool,
}

/// Handler registry for managing event handlers.
pub struct HandlerRegistry {
    /// Handlers by name.
    handlers: RwLock<HashMap<String, HandlerRegistration>>,
    /// Handlers by event type (for fast lookup).
    by_event_type: RwLock<HashMap<EventType, Vec<String>>>,
}

impl HandlerRegistry {
    /// Creates a new handler registry.
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
            by_event_type: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a handler.
    pub fn register(&self, handler: Arc<dyn EventHandler>) -> IntegrationResult<()> {
        let name = handler.name().to_string();
        let event_types = handler.handles();

        info!(handler = %name, "Registering event handler");

        // Index by event type
        {
            let mut by_type = self.by_event_type.write();
            for event_type in event_types {
                by_type
                    .entry(event_type)
                    .or_default()
                    .push(name.clone());
            }
        }

        // Store handler
        self.handlers.write().insert(
            name,
            HandlerRegistration {
                handler,
                enabled: true,
            },
        );

        Ok(())
    }

    /// Unregisters a handler.
    pub fn unregister(&self, name: &str) -> Option<Arc<dyn EventHandler>> {
        let registration = self.handlers.write().remove(name)?;

        // Remove from event type index
        let mut by_type = self.by_event_type.write();
        for handlers in by_type.values_mut() {
            handlers.retain(|n| n != name);
        }

        info!(handler = %name, "Unregistered event handler");
        Some(registration.handler)
    }

    /// Enables a handler.
    pub fn enable(&self, name: &str) -> IntegrationResult<()> {
        let mut handlers = self.handlers.write();
        let registration = handlers
            .get_mut(name)
            .ok_or_else(|| IntegrationError::HandlerError(format!("Handler not found: {}", name)))?;
        registration.enabled = true;
        Ok(())
    }

    /// Disables a handler.
    pub fn disable(&self, name: &str) -> IntegrationResult<()> {
        let mut handlers = self.handlers.write();
        let registration = handlers
            .get_mut(name)
            .ok_or_else(|| IntegrationError::HandlerError(format!("Handler not found: {}", name)))?;
        registration.enabled = false;
        Ok(())
    }

    /// Gets handlers for an event type.
    fn get_handlers_for_event(&self, event_type: EventType) -> Vec<Arc<dyn EventHandler>> {
        let by_type = self.by_event_type.read();
        let handlers = self.handlers.read();

        let mut result: Vec<Arc<dyn EventHandler>> = by_type
            .get(&event_type)
            .map(|names| {
                names
                    .iter()
                    .filter_map(|name| {
                        handlers.get(name).and_then(|reg| {
                            if reg.enabled {
                                Some(Arc::clone(&reg.handler))
                            } else {
                                None
                            }
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Sort by priority (higher first)
        result.sort_by(|a, b| b.priority().cmp(&a.priority()));

        result
    }

    /// Dispatches an event to all registered handlers.
    pub async fn dispatch(&self, event: &Event) -> Vec<HandlerResult> {
        let handlers = self.get_handlers_for_event(event.event_type());
        let mut results = Vec::new();

        for handler in handlers {
            debug!(
                handler = %handler.name(),
                event_id = %event.id(),
                "Dispatching event to handler"
            );

            let start = std::time::Instant::now();
            let result = handler.handle(event).await;
            let duration_ms = start.elapsed().as_millis() as u64;

            let handler_result = HandlerResult {
                handler_name: handler.name().to_string(),
                success: result.is_ok(),
                error: result.err().map(|e| e.to_string()),
                duration_ms,
            };

            if !handler_result.success {
                error!(
                    handler = %handler_result.handler_name,
                    error = ?handler_result.error,
                    "Handler failed"
                );

                if !handler.continue_on_error() {
                    results.push(handler_result);
                    break;
                }
            }

            results.push(handler_result);
        }

        results
    }

    /// Lists all registered handlers.
    pub fn list(&self) -> Vec<HandlerInfo> {
        self.handlers
            .read()
            .iter()
            .map(|(name, reg)| HandlerInfo {
                name: name.clone(),
                enabled: reg.enabled,
                event_types: reg.handler.handles(),
                priority: reg.handler.priority(),
            })
            .collect()
    }

    /// Returns the number of registered handlers.
    pub fn count(&self) -> usize {
        self.handlers.read().len()
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Handler execution result.
#[derive(Debug, Clone)]
pub struct HandlerResult {
    /// Handler name.
    pub handler_name: String,
    /// Success flag.
    pub success: bool,
    /// Error message (if failed).
    pub error: Option<String>,
    /// Execution duration in milliseconds.
    pub duration_ms: u64,
}

/// Handler information.
#[derive(Debug, Clone)]
pub struct HandlerInfo {
    /// Handler name.
    pub name: String,
    /// Is enabled.
    pub enabled: bool,
    /// Event types handled.
    pub event_types: Vec<EventType>,
    /// Priority.
    pub priority: i32,
}

/// A simple logging handler for debugging.
pub struct LoggingHandler {
    /// Handler name.
    name: String,
    /// Event types to handle.
    event_types: Vec<EventType>,
}

impl LoggingHandler {
    /// Creates a new logging handler.
    pub fn new(name: impl Into<String>, event_types: Vec<EventType>) -> Self {
        Self {
            name: name.into(),
            event_types,
        }
    }

    /// Creates a handler that logs all events.
    pub fn all(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            event_types: vec![],
        }
    }
}

#[async_trait]
impl EventHandler for LoggingHandler {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self) -> Vec<EventType> {
        self.event_types.clone()
    }

    async fn handle(&self, event: &Event) -> IntegrationResult<()> {
        info!(
            handler = %self.name,
            event_id = %event.id(),
            event_type = %event.event_type(),
            "Event received"
        );
        Ok(())
    }
}

/// A metrics handler that counts events.
pub struct MetricsHandler {
    /// Handler name.
    name: String,
    /// Event counts by type.
    counts: parking_lot::Mutex<HashMap<EventType, u64>>,
}

impl MetricsHandler {
    /// Creates a new metrics handler.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            counts: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Gets the count for an event type.
    pub fn count(&self, event_type: EventType) -> u64 {
        *self.counts.lock().get(&event_type).unwrap_or(&0)
    }

    /// Gets all counts.
    pub fn all_counts(&self) -> HashMap<EventType, u64> {
        self.counts.lock().clone()
    }

    /// Resets all counts.
    pub fn reset(&self) {
        self.counts.lock().clear();
    }
}

#[async_trait]
impl EventHandler for MetricsHandler {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self) -> Vec<EventType> {
        // Handle all event types
        vec![]
    }

    async fn handle(&self, event: &Event) -> IntegrationResult<()> {
        *self.counts.lock().entry(event.event_type()).or_default() += 1;
        Ok(())
    }

    fn priority(&self) -> i32 {
        // High priority to ensure metrics are captured first
        100
    }
}

/// A filtering handler that wraps another handler.
pub struct FilteringHandler<H: EventHandler> {
    /// Inner handler.
    inner: H,
    /// Filter function.
    filter: Box<dyn Fn(&Event) -> bool + Send + Sync>,
}

impl<H: EventHandler> FilteringHandler<H> {
    /// Creates a new filtering handler.
    pub fn new<F>(inner: H, filter: F) -> Self
    where
        F: Fn(&Event) -> bool + Send + Sync + 'static,
    {
        Self {
            inner,
            filter: Box::new(filter),
        }
    }
}

#[async_trait]
impl<H: EventHandler> EventHandler for FilteringHandler<H> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn handles(&self) -> Vec<EventType> {
        self.inner.handles()
    }

    async fn handle(&self, event: &Event) -> IntegrationResult<()> {
        if (self.filter)(event) {
            self.inner.handle(event).await
        } else {
            Ok(())
        }
    }

    fn priority(&self) -> i32 {
        self.inner.priority()
    }

    fn continue_on_error(&self) -> bool {
        self.inner.continue_on_error()
    }
}

/// A batching handler that collects events and processes them in batches.
pub struct BatchingHandler {
    /// Handler name.
    name: String,
    /// Event types to handle.
    event_types: Vec<EventType>,
    /// Batch size.
    batch_size: usize,
    /// Pending events.
    pending: parking_lot::Mutex<Vec<Event>>,
    /// Batch processor.
    processor: Box<dyn Fn(Vec<Event>) -> IntegrationResult<()> + Send + Sync>,
}

impl BatchingHandler {
    /// Creates a new batching handler.
    pub fn new<F>(
        name: impl Into<String>,
        event_types: Vec<EventType>,
        batch_size: usize,
        processor: F,
    ) -> Self
    where
        F: Fn(Vec<Event>) -> IntegrationResult<()> + Send + Sync + 'static,
    {
        Self {
            name: name.into(),
            event_types,
            batch_size,
            pending: parking_lot::Mutex::new(Vec::new()),
            processor: Box::new(processor),
        }
    }

    /// Flushes pending events.
    pub fn flush(&self) -> IntegrationResult<()> {
        let events: Vec<Event> = self.pending.lock().drain(..).collect();
        if !events.is_empty() {
            (self.processor)(events)?;
        }
        Ok(())
    }

    /// Returns the number of pending events.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }
}

#[async_trait]
impl EventHandler for BatchingHandler {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self) -> Vec<EventType> {
        self.event_types.clone()
    }

    async fn handle(&self, event: &Event) -> IntegrationResult<()> {
        let should_flush = {
            let mut pending = self.pending.lock();
            pending.push(event.clone());
            pending.len() >= self.batch_size
        };

        if should_flush {
            self.flush()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{DatasetEventPayload, EventMetadata, EventPayload};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn create_test_event(event_type: EventType) -> Event {
        Event::new(
            EventMetadata::new(event_type, "test"),
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

    /// Test handler that counts invocations.
    struct CountingHandler {
        name: String,
        event_types: Vec<EventType>,
        count: AtomicUsize,
    }

    impl CountingHandler {
        fn new(name: &str, event_types: Vec<EventType>) -> Self {
            Self {
                name: name.to_string(),
                event_types,
                count: AtomicUsize::new(0),
            }
        }

        fn count(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl EventHandler for CountingHandler {
        fn name(&self) -> &str {
            &self.name
        }

        fn handles(&self) -> Vec<EventType> {
            self.event_types.clone()
        }

        async fn handle(&self, _event: &Event) -> IntegrationResult<()> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_handler_registry_register() {
        let registry = HandlerRegistry::new();

        let handler = Arc::new(CountingHandler::new(
            "test-handler",
            vec![EventType::DatasetCreated],
        ));

        registry.register(handler).unwrap();

        assert_eq!(registry.count(), 1);
    }

    #[tokio::test]
    async fn test_handler_registry_dispatch() {
        let registry = HandlerRegistry::new();

        let handler = Arc::new(CountingHandler::new(
            "test-handler",
            vec![EventType::DatasetCreated],
        ));
        let handler_clone = Arc::clone(&handler);

        registry.register(handler).unwrap();

        let event = create_test_event(EventType::DatasetCreated);
        let results = registry.dispatch(&event).await;

        assert_eq!(results.len(), 1);
        assert!(results[0].success);
        assert_eq!(handler_clone.count(), 1);
    }

    #[tokio::test]
    async fn test_handler_registry_event_type_filtering() {
        let registry = HandlerRegistry::new();

        let dataset_handler = Arc::new(CountingHandler::new(
            "dataset-handler",
            vec![EventType::DatasetCreated],
        ));
        let record_handler = Arc::new(CountingHandler::new(
            "record-handler",
            vec![EventType::RecordCreated],
        ));

        let dataset_clone = Arc::clone(&dataset_handler);
        let record_clone = Arc::clone(&record_handler);

        registry.register(dataset_handler).unwrap();
        registry.register(record_handler).unwrap();

        // Dispatch dataset event
        let event = create_test_event(EventType::DatasetCreated);
        registry.dispatch(&event).await;

        assert_eq!(dataset_clone.count(), 1);
        assert_eq!(record_clone.count(), 0);
    }

    #[tokio::test]
    async fn test_handler_enable_disable() {
        let registry = HandlerRegistry::new();

        let handler = Arc::new(CountingHandler::new(
            "test-handler",
            vec![EventType::DatasetCreated],
        ));
        let handler_clone = Arc::clone(&handler);

        registry.register(handler).unwrap();

        // Disable handler
        registry.disable("test-handler").unwrap();

        let event = create_test_event(EventType::DatasetCreated);
        registry.dispatch(&event).await;

        // Should not be called
        assert_eq!(handler_clone.count(), 0);

        // Re-enable
        registry.enable("test-handler").unwrap();
        registry.dispatch(&event).await;

        // Should be called now
        assert_eq!(handler_clone.count(), 1);
    }

    #[tokio::test]
    async fn test_metrics_handler() {
        let handler = MetricsHandler::new("metrics");

        handler.handle(&create_test_event(EventType::DatasetCreated)).await.unwrap();
        handler.handle(&create_test_event(EventType::DatasetCreated)).await.unwrap();
        handler.handle(&create_test_event(EventType::RecordCreated)).await.unwrap();

        assert_eq!(handler.count(EventType::DatasetCreated), 2);
        assert_eq!(handler.count(EventType::RecordCreated), 1);
        assert_eq!(handler.count(EventType::DatasetDeleted), 0);
    }

    #[test]
    fn test_batching_handler() {
        let processed = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let processed_clone = Arc::clone(&processed);

        let handler = BatchingHandler::new(
            "batch",
            vec![EventType::DatasetCreated],
            3,
            move |events| {
                processed_clone.lock().push(events.len());
                Ok(())
            },
        );

        // Add events below batch size
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            handler.handle(&create_test_event(EventType::DatasetCreated)).await.unwrap();
            handler.handle(&create_test_event(EventType::DatasetCreated)).await.unwrap();
        });

        assert_eq!(handler.pending_count(), 2);
        assert!(processed.lock().is_empty());

        // Add third event to trigger batch
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            handler.handle(&create_test_event(EventType::DatasetCreated)).await.unwrap();
        });

        assert_eq!(handler.pending_count(), 0);
        assert_eq!(*processed.lock(), vec![3]);
    }
}
