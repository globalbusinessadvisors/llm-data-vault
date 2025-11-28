//! Event subscription management.

use crate::{EventType, IntegrationError, IntegrationResult, Webhook};
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Event filter for subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFilter {
    /// Event types to include.
    pub event_types: Option<HashSet<EventType>>,
    /// Event categories to include.
    pub categories: Option<HashSet<String>>,
    /// Tenant ID filter.
    pub tenant_id: Option<String>,
    /// Dataset ID filter.
    pub dataset_id: Option<String>,
    /// User ID filter.
    pub user_id: Option<String>,
    /// Custom filter expression.
    pub expression: Option<String>,
}

impl EventFilter {
    /// Creates a filter that accepts all events.
    pub fn all() -> Self {
        Self {
            event_types: None,
            categories: None,
            tenant_id: None,
            dataset_id: None,
            user_id: None,
            expression: None,
        }
    }

    /// Creates a filter for specific event types.
    pub fn for_events(events: impl IntoIterator<Item = EventType>) -> Self {
        Self {
            event_types: Some(events.into_iter().collect()),
            ..Self::all()
        }
    }

    /// Creates a filter for a category.
    pub fn for_category(category: impl Into<String>) -> Self {
        let mut categories = HashSet::new();
        categories.insert(category.into());
        Self {
            categories: Some(categories),
            ..Self::all()
        }
    }

    /// Adds a tenant filter.
    #[must_use]
    pub fn for_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Adds a dataset filter.
    #[must_use]
    pub fn for_dataset(mut self, dataset_id: impl Into<String>) -> Self {
        self.dataset_id = Some(dataset_id.into());
        self
    }

    /// Adds a user filter.
    #[must_use]
    pub fn for_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Checks if an event matches this filter.
    pub fn matches(&self, event_type: EventType, metadata: &FilterContext) -> bool {
        // Check event type
        if let Some(ref types) = self.event_types {
            if !types.contains(&event_type) {
                return false;
            }
        }

        // Check category
        if let Some(ref categories) = self.categories {
            if !categories.contains(event_type.category()) {
                return false;
            }
        }

        // Check tenant
        if let Some(ref tenant) = self.tenant_id {
            if metadata.tenant_id.as_ref() != Some(tenant) {
                return false;
            }
        }

        // Check dataset
        if let Some(ref dataset) = self.dataset_id {
            if metadata.dataset_id.as_ref() != Some(dataset) {
                return false;
            }
        }

        // Check user
        if let Some(ref user) = self.user_id {
            if metadata.user_id.as_ref() != Some(user) {
                return false;
            }
        }

        true
    }
}

/// Context for filter evaluation.
#[derive(Debug, Clone, Default)]
pub struct FilterContext {
    /// Tenant ID.
    pub tenant_id: Option<String>,
    /// Dataset ID.
    pub dataset_id: Option<String>,
    /// User ID.
    pub user_id: Option<String>,
    /// Additional fields.
    pub fields: HashMap<String, String>,
}

impl FilterContext {
    /// Creates a new filter context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the tenant ID.
    #[must_use]
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Sets the dataset ID.
    #[must_use]
    pub fn with_dataset(mut self, dataset_id: impl Into<String>) -> Self {
        self.dataset_id = Some(dataset_id.into());
        self
    }

    /// Sets the user ID.
    #[must_use]
    pub fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }
}

/// A subscription to events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    /// Subscription ID.
    pub id: String,
    /// Subscription name.
    pub name: String,
    /// Subscriber ID (webhook ID, handler ID, etc.).
    pub subscriber_id: String,
    /// Subscriber type.
    pub subscriber_type: SubscriberType,
    /// Event filter.
    pub filter: EventFilter,
    /// Is active.
    pub active: bool,
    /// Created timestamp.
    pub created_at: DateTime<Utc>,
    /// Updated timestamp.
    pub updated_at: DateTime<Utc>,
    /// Priority (higher = processed first).
    pub priority: i32,
    /// Metadata.
    pub metadata: HashMap<String, String>,
}

/// Subscriber type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubscriberType {
    /// Webhook subscriber.
    Webhook,
    /// Internal handler.
    Handler,
    /// Queue subscriber.
    Queue,
    /// External system.
    External,
}

impl Subscription {
    /// Creates a new subscription.
    pub fn new(
        name: impl Into<String>,
        subscriber_id: impl Into<String>,
        subscriber_type: SubscriberType,
        filter: EventFilter,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.into(),
            subscriber_id: subscriber_id.into(),
            subscriber_type,
            filter,
            active: true,
            created_at: now,
            updated_at: now,
            priority: 0,
            metadata: HashMap::new(),
        }
    }

    /// Creates a webhook subscription.
    pub fn for_webhook(webhook: &Webhook, filter: EventFilter) -> Self {
        Self::new(&webhook.name, &webhook.id, SubscriberType::Webhook, filter)
    }

    /// Sets the priority.
    #[must_use]
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Adds metadata.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Activates the subscription.
    pub fn activate(&mut self) {
        self.active = true;
        self.updated_at = Utc::now();
    }

    /// Deactivates the subscription.
    pub fn deactivate(&mut self) {
        self.active = false;
        self.updated_at = Utc::now();
    }

    /// Checks if this subscription should receive an event.
    pub fn should_receive(&self, event_type: EventType, context: &FilterContext) -> bool {
        self.active && self.filter.matches(event_type, context)
    }
}

/// Subscription manager.
pub struct SubscriptionManager {
    /// Subscriptions by ID.
    subscriptions: RwLock<HashMap<String, Subscription>>,
    /// Subscriptions by subscriber.
    by_subscriber: RwLock<HashMap<String, Vec<String>>>,
    /// Subscriptions by event type (for fast lookup).
    by_event_type: RwLock<HashMap<EventType, Vec<String>>>,
}

impl SubscriptionManager {
    /// Creates a new subscription manager.
    pub fn new() -> Self {
        Self {
            subscriptions: RwLock::new(HashMap::new()),
            by_subscriber: RwLock::new(HashMap::new()),
            by_event_type: RwLock::new(HashMap::new()),
        }
    }

    /// Adds a subscription.
    pub fn add(&self, subscription: Subscription) -> IntegrationResult<String> {
        let id = subscription.id.clone();
        let subscriber_id = subscription.subscriber_id.clone();

        // Index by event types
        if let Some(ref event_types) = subscription.filter.event_types {
            let mut by_type = self.by_event_type.write();
            for event_type in event_types {
                by_type
                    .entry(*event_type)
                    .or_default()
                    .push(id.clone());
            }
        }

        // Index by subscriber
        self.by_subscriber
            .write()
            .entry(subscriber_id)
            .or_default()
            .push(id.clone());

        // Store subscription
        self.subscriptions.write().insert(id.clone(), subscription);

        Ok(id)
    }

    /// Gets a subscription by ID.
    pub fn get(&self, id: &str) -> Option<Subscription> {
        self.subscriptions.read().get(id).cloned()
    }

    /// Removes a subscription.
    pub fn remove(&self, id: &str) -> Option<Subscription> {
        let subscription = self.subscriptions.write().remove(id)?;

        // Remove from subscriber index
        if let Some(subs) = self.by_subscriber.write().get_mut(&subscription.subscriber_id) {
            subs.retain(|s| s != id);
        }

        // Remove from event type index
        let mut by_type = self.by_event_type.write();
        for subs in by_type.values_mut() {
            subs.retain(|s| s != id);
        }

        Some(subscription)
    }

    /// Updates a subscription.
    pub fn update(&self, id: &str, mut f: impl FnMut(&mut Subscription)) -> IntegrationResult<()> {
        let mut subscriptions = self.subscriptions.write();
        let subscription = subscriptions
            .get_mut(id)
            .ok_or_else(|| IntegrationError::SubscriptionNotFound(id.to_string()))?;

        f(subscription);
        subscription.updated_at = Utc::now();

        Ok(())
    }

    /// Lists all subscriptions.
    pub fn list(&self) -> Vec<Subscription> {
        self.subscriptions.read().values().cloned().collect()
    }

    /// Lists subscriptions for a subscriber.
    pub fn list_for_subscriber(&self, subscriber_id: &str) -> Vec<Subscription> {
        let by_subscriber = self.by_subscriber.read();
        let subscriptions = self.subscriptions.read();

        by_subscriber
            .get(subscriber_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| subscriptions.get(id).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Finds subscriptions matching an event.
    pub fn find_matching(
        &self,
        event_type: EventType,
        context: &FilterContext,
    ) -> Vec<Subscription> {
        let subscriptions = self.subscriptions.read();

        // Check event type index first
        let by_type = self.by_event_type.read();
        if let Some(subscription_ids) = by_type.get(&event_type) {
            return subscription_ids
                .iter()
                .filter_map(|id| subscriptions.get(id))
                .filter(|s| s.should_receive(event_type, context))
                .cloned()
                .collect();
        }

        // Fall back to checking all subscriptions
        subscriptions
            .values()
            .filter(|s| s.should_receive(event_type, context))
            .cloned()
            .collect()
    }

    /// Activates a subscription.
    pub fn activate(&self, id: &str) -> IntegrationResult<()> {
        self.update(id, |s| s.activate())
    }

    /// Deactivates a subscription.
    pub fn deactivate(&self, id: &str) -> IntegrationResult<()> {
        self.update(id, |s| s.deactivate())
    }

    /// Returns the number of subscriptions.
    pub fn count(&self) -> usize {
        self.subscriptions.read().len()
    }

    /// Returns the number of active subscriptions.
    pub fn active_count(&self) -> usize {
        self.subscriptions.read().values().filter(|s| s.active).count()
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_filter_all() {
        let filter = EventFilter::all();
        let context = FilterContext::new();

        assert!(filter.matches(EventType::DatasetCreated, &context));
        assert!(filter.matches(EventType::RecordUpdated, &context));
    }

    #[test]
    fn test_event_filter_by_type() {
        let filter = EventFilter::for_events([EventType::DatasetCreated, EventType::DatasetUpdated]);
        let context = FilterContext::new();

        assert!(filter.matches(EventType::DatasetCreated, &context));
        assert!(filter.matches(EventType::DatasetUpdated, &context));
        assert!(!filter.matches(EventType::RecordCreated, &context));
    }

    #[test]
    fn test_event_filter_by_tenant() {
        let filter = EventFilter::all().for_tenant("tenant-123");

        let context1 = FilterContext::new().with_tenant("tenant-123");
        let context2 = FilterContext::new().with_tenant("tenant-456");
        let context3 = FilterContext::new();

        assert!(filter.matches(EventType::DatasetCreated, &context1));
        assert!(!filter.matches(EventType::DatasetCreated, &context2));
        assert!(!filter.matches(EventType::DatasetCreated, &context3));
    }

    #[test]
    fn test_subscription_creation() {
        let filter = EventFilter::for_events([EventType::DatasetCreated]);
        let subscription = Subscription::new(
            "test-subscription",
            "webhook-123",
            SubscriberType::Webhook,
            filter,
        );

        assert!(subscription.active);
        assert_eq!(subscription.subscriber_type, SubscriberType::Webhook);
    }

    #[test]
    fn test_subscription_should_receive() {
        let filter = EventFilter::for_events([EventType::DatasetCreated]);
        let subscription = Subscription::new(
            "test",
            "webhook-123",
            SubscriberType::Webhook,
            filter,
        );

        let context = FilterContext::new();

        assert!(subscription.should_receive(EventType::DatasetCreated, &context));
        assert!(!subscription.should_receive(EventType::RecordCreated, &context));
    }

    #[test]
    fn test_subscription_manager_add_get() {
        let manager = SubscriptionManager::new();

        let subscription = Subscription::new(
            "test",
            "webhook-123",
            SubscriberType::Webhook,
            EventFilter::all(),
        );

        let id = manager.add(subscription.clone()).unwrap();

        let retrieved = manager.get(&id).unwrap();
        assert_eq!(retrieved.name, "test");
    }

    #[test]
    fn test_subscription_manager_find_matching() {
        let manager = SubscriptionManager::new();

        let sub1 = Subscription::new(
            "dataset-events",
            "webhook-1",
            SubscriberType::Webhook,
            EventFilter::for_events([EventType::DatasetCreated]),
        );

        let sub2 = Subscription::new(
            "record-events",
            "webhook-2",
            SubscriberType::Webhook,
            EventFilter::for_events([EventType::RecordCreated]),
        );

        manager.add(sub1).unwrap();
        manager.add(sub2).unwrap();

        let context = FilterContext::new();
        let matching = manager.find_matching(EventType::DatasetCreated, &context);

        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].name, "dataset-events");
    }

    #[test]
    fn test_subscription_manager_activate_deactivate() {
        let manager = SubscriptionManager::new();

        let subscription = Subscription::new(
            "test",
            "webhook-123",
            SubscriberType::Webhook,
            EventFilter::all(),
        );

        let id = manager.add(subscription).unwrap();

        manager.deactivate(&id).unwrap();
        assert!(!manager.get(&id).unwrap().active);

        manager.activate(&id).unwrap();
        assert!(manager.get(&id).unwrap().active);
    }
}
