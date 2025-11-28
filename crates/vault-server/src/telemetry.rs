//! Telemetry initialization.

use anyhow::Result;
use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

use crate::config::TelemetryConfig;

/// Initializes telemetry (logging and tracing).
pub fn init_telemetry(config: &TelemetryConfig) -> Result<()> {
    // Build env filter
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    // Build subscriber based on format
    match config.log_format.as_str() {
        "json" => {
            let subscriber = tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().json());

            subscriber.init();
        }
        _ => {
            let subscriber = tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().pretty());

            subscriber.init();
        }
    }

    Ok(())
}

/// Initializes OpenTelemetry tracing.
#[cfg(feature = "otlp")]
pub fn init_otlp_tracing(endpoint: &str) -> Result<()> {
    use opentelemetry::global;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::{runtime, trace as sdktrace};
    use tracing_opentelemetry::OpenTelemetryLayer;

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(endpoint),
        )
        .with_trace_config(sdktrace::config().with_resource(
            opentelemetry_sdk::Resource::new(vec![
                opentelemetry::KeyValue::new("service.name", "llm-data-vault"),
                opentelemetry::KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            ]),
        ))
        .install_batch(runtime::Tokio)?;

    let telemetry_layer = OpenTelemetryLayer::new(tracer);

    tracing_subscriber::registry()
        .with(telemetry_layer)
        .init();

    Ok(())
}

/// Shuts down telemetry.
pub fn shutdown_telemetry() {
    #[cfg(feature = "otlp")]
    {
        opentelemetry::global::shutdown_tracer_provider();
    }
}
