use std::time::Duration;

use anyhow::Context;
use auth1::{http, Config};
use clap::Parser;
use gethostname::gethostname;
use opentelemetry::{
    global,
    sdk::{
        export::{
            self,
            metrics::{
                aggregation::{self, cumulative_temporality_selector},
                StdoutExporter,
            },
        },
        metrics::{
            controllers::{self, BasicController},
            processors, selectors,
        },
        propagation::TraceContextPropagator,
        trace, Resource,
    },
    KeyValue,
};
use opentelemetry_otlp::{ExportConfig, WithExportConfig};
use sqlx::postgres::PgPoolOptions;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

fn resource() -> Resource {
    use opentelemetry_semantic_conventions::resource::{HOST_NAME, SERVICE_NAME, SERVICE_VERSION};

    let hostname = gethostname()
        .into_string()
        .unwrap_or_else(|_| "unknown".to_owned());

    Resource::new(vec![
        KeyValue::new(SERVICE_NAME, env!("CARGO_PKG_NAME")),
        KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
        KeyValue::new(HOST_NAME, hostname),
    ])
}

fn init_telemetry(otlp_endpoint: impl Into<String>) -> anyhow::Result<()> {
    let resource = resource();
    let otlp_endpoint = otlp_endpoint.into();
    let rt = opentelemetry::runtime::Tokio;

    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(otlp_endpoint.clone());

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(trace::config().with_resource(resource.clone()))
        .install_batch(rt.clone())?;

    tracing_subscriber::registry()
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with(fmt::layer())
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .init();

    // metrics

    let controller = opentelemetry_otlp::new_pipeline()
        .metrics(
            selectors::simple::inexpensive(),
            cumulative_temporality_selector(),
            rt.clone(),
        )
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(otlp_endpoint),
        )
        .with_resource(resource)
        .build()?;

    controller.start(&opentelemetry::Context::new(), rt)?;

    global::set_meter_provider(controller);

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenv::dotenv();

    let config = Config::parse();

    init_telemetry(config.otlp_endpoint.clone())?;

    let db = PgPoolOptions::new()
        .min_connections(config.min_database_connections)
        .max_connections(config.max_database_connections)
        .connect(&config.database_url)
        .await
        .context("failed to connect to database")?;

    sqlx::migrate!().run(&db).await?;

    http::serve(config, db).await
}
