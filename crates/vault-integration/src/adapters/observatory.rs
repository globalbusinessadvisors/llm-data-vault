//! LLM-Observatory adapter for consuming telemetry traces.
//!
//! This adapter provides runtime consumption of telemetry from the
//! LLM-Observatory service for:
//! - Vault operation traces
//! - Performance events and metrics
//! - Storage health signals
//!
//! # Usage
//!
//! ```ignore
//! use vault_integration::adapters::ObservatoryAdapter;
//!
//! let adapter = ObservatoryAdapter::new(config);
//! adapter.initialize().await?;
//!
//! // Emit a vault operation trace
//! adapter.trace_operation(OperationTrace::new("dataset.create")).await?;
//! ```

use super::{AdapterConfig, AdapterHealth, EcosystemAdapter};
use crate::{IntegrationError, IntegrationResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{debug, info, warn};
use chrono::{DateTime, Utc};

/// Operation trace for vault operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationTrace {
    /// Trace ID.
    pub trace_id: String,
    /// Span ID.
    pub span_id: String,
    /// Parent span ID (if nested).
    pub parent_span_id: Option<String>,
    /// Operation name.
    pub operation: String,
    /// Operation kind.
    pub kind: OperationKind,
    /// Start time.
    pub start_time: DateTime<Utc>,
    /// End time (if completed).
    pub end_time: Option<DateTime<Utc>>,
    /// Duration in milliseconds.
    pub duration_ms: Option<u64>,
    /// Operation status.
    pub status: OperationStatus,
    /// Trace attributes.
    pub attributes: HashMap<String, String>,
    /// Resource attributes.
    pub resource: ResourceAttributes,
}

impl OperationTrace {
    /// Creates a new operation trace.
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            trace_id: uuid::Uuid::new_v4().to_string(),
            span_id: uuid::Uuid::new_v4().to_string(),
            parent_span_id: None,
            operation: operation.into(),
            kind: OperationKind::Internal,
            start_time: Utc::now(),
            end_time: None,
            duration_ms: None,
            status: OperationStatus::InProgress,
            attributes: HashMap::new(),
            resource: ResourceAttributes::default(),
        }
    }

    /// Sets the operation kind.
    pub fn with_kind(mut self, kind: OperationKind) -> Self {
        self.kind = kind;
        self
    }

    /// Sets the parent span ID.
    pub fn with_parent(mut self, parent_span_id: impl Into<String>) -> Self {
        self.parent_span_id = Some(parent_span_id.into());
        self
    }

    /// Adds an attribute.
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Marks the operation as complete.
    pub fn complete(mut self) -> Self {
        self.end_time = Some(Utc::now());
        self.duration_ms = Some(
            (self.end_time.unwrap() - self.start_time).num_milliseconds() as u64
        );
        self.status = OperationStatus::Ok;
        self
    }

    /// Marks the operation as failed.
    pub fn fail(mut self, error: impl Into<String>) -> Self {
        self.end_time = Some(Utc::now());
        self.duration_ms = Some(
            (self.end_time.unwrap() - self.start_time).num_milliseconds() as u64
        );
        self.status = OperationStatus::Error;
        self.attributes.insert("error.message".to_string(), error.into());
        self
    }
}

/// Operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// Internal operation.
    Internal,
    /// Client-facing operation.
    Client,
    /// Server-side operation.
    Server,
    /// Producer operation.
    Producer,
    /// Consumer operation.
    Consumer,
}

/// Operation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    /// Operation in progress.
    InProgress,
    /// Operation completed successfully.
    Ok,
    /// Operation failed.
    Error,
}

/// Resource attributes for traces.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceAttributes {
    /// Service name.
    pub service_name: Option<String>,
    /// Service version.
    pub service_version: Option<String>,
    /// Host name.
    pub host_name: Option<String>,
    /// Environment (dev, staging, prod).
    pub environment: Option<String>,
}

/// Performance event for vault metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceEvent {
    /// Event ID.
    pub id: String,
    /// Event name.
    pub name: String,
    /// Event category.
    pub category: PerformanceCategory,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
    /// Metric value.
    pub value: f64,
    /// Unit of measurement.
    pub unit: MetricUnit,
    /// Event dimensions.
    pub dimensions: HashMap<String, String>,
}

impl PerformanceEvent {
    /// Creates a new performance event.
    pub fn new(name: impl Into<String>, category: PerformanceCategory, value: f64) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            category,
            timestamp: Utc::now(),
            value,
            unit: MetricUnit::Count,
            dimensions: HashMap::new(),
        }
    }

    /// Sets the metric unit.
    pub fn with_unit(mut self, unit: MetricUnit) -> Self {
        self.unit = unit;
        self
    }

    /// Adds a dimension.
    pub fn with_dimension(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.dimensions.insert(key.into(), value.into());
        self
    }
}

/// Performance event categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceCategory {
    /// Latency metrics.
    Latency,
    /// Throughput metrics.
    Throughput,
    /// Error rates.
    ErrorRate,
    /// Resource utilization.
    Utilization,
    /// Cache metrics.
    Cache,
    /// Database metrics.
    Database,
}

/// Metric units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricUnit {
    /// Count.
    Count,
    /// Milliseconds.
    Milliseconds,
    /// Bytes.
    Bytes,
    /// Percentage.
    Percent,
    /// Requests per second.
    RequestsPerSecond,
}

/// Storage health signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageHealthSignal {
    /// Signal ID.
    pub id: String,
    /// Backend name.
    pub backend: String,
    /// Health status.
    pub status: HealthStatus,
    /// Timestamp.
    pub timestamp: DateTime<Utc>,
    /// Latency to backend in milliseconds.
    pub latency_ms: Option<u64>,
    /// Available space in bytes.
    pub available_space_bytes: Option<u64>,
    /// Total space in bytes.
    pub total_space_bytes: Option<u64>,
    /// Object count.
    pub object_count: Option<u64>,
    /// Error message (if unhealthy).
    pub error: Option<String>,
    /// Additional details.
    pub details: HashMap<String, String>,
}

impl StorageHealthSignal {
    /// Creates a healthy signal.
    pub fn healthy(backend: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            backend: backend.into(),
            status: HealthStatus::Healthy,
            timestamp: Utc::now(),
            latency_ms: None,
            available_space_bytes: None,
            total_space_bytes: None,
            object_count: None,
            error: None,
            details: HashMap::new(),
        }
    }

    /// Creates an unhealthy signal.
    pub fn unhealthy(backend: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            backend: backend.into(),
            status: HealthStatus::Unhealthy,
            timestamp: Utc::now(),
            latency_ms: None,
            available_space_bytes: None,
            total_space_bytes: None,
            object_count: None,
            error: Some(error.into()),
            details: HashMap::new(),
        }
    }

    /// Sets the latency.
    pub fn with_latency(mut self, latency_ms: u64) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }

    /// Sets storage capacity.
    pub fn with_capacity(mut self, available: u64, total: u64) -> Self {
        self.available_space_bytes = Some(available);
        self.total_space_bytes = Some(total);
        self
    }
}

/// Health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Healthy.
    Healthy,
    /// Degraded but operational.
    Degraded,
    /// Unhealthy.
    Unhealthy,
    /// Unknown status.
    Unknown,
}

/// LLM-Observatory adapter for consuming telemetry.
pub struct ObservatoryAdapter {
    /// Adapter configuration.
    config: AdapterConfig,
    /// Trace buffer for batching.
    trace_buffer: Arc<RwLock<Vec<OperationTrace>>>,
    /// Performance event buffer.
    perf_buffer: Arc<RwLock<Vec<PerformanceEvent>>>,
    /// Health signal buffer.
    health_buffer: Arc<RwLock<Vec<StorageHealthSignal>>>,
    /// Buffer size limit.
    buffer_limit: usize,
    /// Initialization state.
    initialized: Arc<RwLock<bool>>,
}

impl ObservatoryAdapter {
    /// Creates a new Observatory adapter.
    pub fn new(config: AdapterConfig) -> Self {
        Self {
            config,
            trace_buffer: Arc::new(RwLock::new(Vec::new())),
            perf_buffer: Arc::new(RwLock::new(Vec::new())),
            health_buffer: Arc::new(RwLock::new(Vec::new())),
            buffer_limit: 1000,
            initialized: Arc::new(RwLock::new(false)),
        }
    }

    /// Creates an adapter with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(AdapterConfig::default())
    }

    /// Emits an operation trace to the Observatory.
    pub async fn trace_operation(&self, trace: OperationTrace) -> IntegrationResult<()> {
        if !self.config.enabled {
            return Ok(()); // Silently skip if disabled
        }

        debug!(
            trace_id = %trace.trace_id,
            operation = %trace.operation,
            "Emitting operation trace to LLM-Observatory"
        );

        let mut buffer = self.trace_buffer.write();
        buffer.push(trace);

        // Flush if buffer is full
        if buffer.len() >= self.buffer_limit {
            drop(buffer); // Release lock before flush
            self.flush_traces().await?;
        }

        Ok(())
    }

    /// Emits a performance event to the Observatory.
    pub async fn emit_performance_event(&self, event: PerformanceEvent) -> IntegrationResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        debug!(
            event_id = %event.id,
            event_name = %event.name,
            "Emitting performance event to LLM-Observatory"
        );

        let mut buffer = self.perf_buffer.write();
        buffer.push(event);

        if buffer.len() >= self.buffer_limit {
            drop(buffer);
            self.flush_performance_events().await?;
        }

        Ok(())
    }

    /// Emits a storage health signal to the Observatory.
    pub async fn emit_health_signal(&self, signal: StorageHealthSignal) -> IntegrationResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        debug!(
            signal_id = %signal.id,
            backend = %signal.backend,
            status = ?signal.status,
            "Emitting storage health signal to LLM-Observatory"
        );

        let mut buffer = self.health_buffer.write();
        buffer.push(signal);

        if buffer.len() >= self.buffer_limit {
            drop(buffer);
            self.flush_health_signals().await?;
        }

        Ok(())
    }

    /// Flushes buffered traces to the Observatory.
    pub async fn flush_traces(&self) -> IntegrationResult<usize> {
        let traces: Vec<OperationTrace> = self.trace_buffer.write().drain(..).collect();
        let count = traces.len();

        if count > 0 {
            debug!(count = count, "Flushing traces to LLM-Observatory");
            // In production, this would send to the Observatory service
        }

        Ok(count)
    }

    /// Flushes buffered performance events.
    pub async fn flush_performance_events(&self) -> IntegrationResult<usize> {
        let events: Vec<PerformanceEvent> = self.perf_buffer.write().drain(..).collect();
        let count = events.len();

        if count > 0 {
            debug!(count = count, "Flushing performance events to LLM-Observatory");
        }

        Ok(count)
    }

    /// Flushes buffered health signals.
    pub async fn flush_health_signals(&self) -> IntegrationResult<usize> {
        let signals: Vec<StorageHealthSignal> = self.health_buffer.write().drain(..).collect();
        let count = signals.len();

        if count > 0 {
            debug!(count = count, "Flushing health signals to LLM-Observatory");
        }

        Ok(count)
    }

    /// Flushes all buffers.
    pub async fn flush_all(&self) -> IntegrationResult<()> {
        self.flush_traces().await?;
        self.flush_performance_events().await?;
        self.flush_health_signals().await?;
        Ok(())
    }

    /// Returns buffer statistics.
    pub fn buffer_stats(&self) -> BufferStats {
        BufferStats {
            traces: self.trace_buffer.read().len(),
            performance_events: self.perf_buffer.read().len(),
            health_signals: self.health_buffer.read().len(),
            buffer_limit: self.buffer_limit,
        }
    }
}

/// Buffer statistics.
#[derive(Debug, Clone)]
pub struct BufferStats {
    /// Number of buffered traces.
    pub traces: usize,
    /// Number of buffered performance events.
    pub performance_events: usize,
    /// Number of buffered health signals.
    pub health_signals: usize,
    /// Buffer size limit.
    pub buffer_limit: usize,
}

#[async_trait]
impl EcosystemAdapter for ObservatoryAdapter {
    fn name(&self) -> &str {
        "llm-observatory"
    }

    fn version(&self) -> &str {
        "0.1.1"
    }

    async fn health_check(&self) -> IntegrationResult<AdapterHealth> {
        if !self.config.enabled {
            return Ok(AdapterHealth::unhealthy("Adapter is disabled"));
        }

        if !*self.initialized.read() {
            return Ok(AdapterHealth::unhealthy("Adapter not initialized"));
        }

        Ok(AdapterHealth::healthy("Observatory adapter is healthy"))
    }

    async fn initialize(&self) -> IntegrationResult<()> {
        if *self.initialized.read() {
            warn!("Observatory adapter already initialized");
            return Ok(());
        }

        info!(
            base_url = ?self.config.base_url,
            "Initializing LLM-Observatory adapter"
        );

        *self.initialized.write() = true;

        info!("LLM-Observatory adapter initialized successfully");
        Ok(())
    }

    async fn shutdown(&self) -> IntegrationResult<()> {
        info!("Shutting down LLM-Observatory adapter");

        // Flush all pending telemetry
        self.flush_all().await?;

        *self.initialized.write() = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_adapter_creation() {
        let adapter = ObservatoryAdapter::with_defaults();
        assert_eq!(adapter.name(), "llm-observatory");
    }

    #[tokio::test]
    async fn test_operation_trace() {
        let adapter = ObservatoryAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        let trace = OperationTrace::new("dataset.create")
            .with_kind(OperationKind::Client)
            .with_attribute("dataset_id", "ds-123")
            .complete();

        adapter.trace_operation(trace).await.unwrap();

        let stats = adapter.buffer_stats();
        assert_eq!(stats.traces, 1);
    }

    #[tokio::test]
    async fn test_performance_event() {
        let adapter = ObservatoryAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        let event = PerformanceEvent::new("request_latency", PerformanceCategory::Latency, 45.5)
            .with_unit(MetricUnit::Milliseconds)
            .with_dimension("endpoint", "/api/datasets");

        adapter.emit_performance_event(event).await.unwrap();

        let stats = adapter.buffer_stats();
        assert_eq!(stats.performance_events, 1);
    }

    #[tokio::test]
    async fn test_health_signal() {
        let adapter = ObservatoryAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        let signal = StorageHealthSignal::healthy("s3-primary")
            .with_latency(25)
            .with_capacity(500_000_000_000, 1_000_000_000_000);

        adapter.emit_health_signal(signal).await.unwrap();

        let stats = adapter.buffer_stats();
        assert_eq!(stats.health_signals, 1);
    }

    #[tokio::test]
    async fn test_flush_all() {
        let adapter = ObservatoryAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        adapter.trace_operation(OperationTrace::new("test")).await.unwrap();
        adapter.emit_performance_event(
            PerformanceEvent::new("test", PerformanceCategory::Latency, 1.0)
        ).await.unwrap();
        adapter.emit_health_signal(StorageHealthSignal::healthy("test")).await.unwrap();

        adapter.flush_all().await.unwrap();

        let stats = adapter.buffer_stats();
        assert_eq!(stats.traces, 0);
        assert_eq!(stats.performance_events, 0);
        assert_eq!(stats.health_signals, 0);
    }
}
