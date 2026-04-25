use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::{runtime, trace as sdktrace};
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub mod spans;

pub fn init_tracing(
    service_name: &str,
    otlp_endpoint: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tracer = if let Some(endpoint) = otlp_endpoint {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic(opentelemetry_otlp::TonicConfig::default().with_timeout(Duration::from_secs(10)))
            .with_endpoint(endpoint)
            .build()?;

        let provider = opentelemetry_sdk::trace::TracerProvider::builder()
            .with_batch_exporter(exporter, runtime::Tokio)
            .with_resource(opentelemetry_sdk::Resource::new(vec![
                opentelemetry::KeyValue::new("service.name", service_name),
            ]))
            .build();

        provider.versioned_tracer(
            "grey",
            Some(env!("CARGO_PKG_VERSION")),
            Some(opentelemetry::trace::SchemaUrl::PREFIX),
        )
    } else {
        let provider = opentelemetry_sdk::trace::TracerProvider::default();
        provider.versioned_tracer(
            "grey",
            Some(env!("CARGO_PKG_VERSION")),
            Some(opentelemetry::trace::SchemaUrl::PREFIX),
        )
    };

    let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .with(telemetry_layer)
        .try_init()
        .map_err(|e| format!("failed to init tracing subscriber: {}", e))?;

    Ok(())
}

pub fn shutdown_tracing() {
    opentelemetry::global::shutdown_tracer_provider();
}
