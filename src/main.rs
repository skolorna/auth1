use anyhow::Context;
use auth1::{http, Config};
use clap::Parser;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenv::dotenv();

    let config = Config::parse();

    let _guard = sentry::init(sentry::ClientOptions {
        traces_sample_rate: config.traces_sample_rate,
        dsn: config.sentry_dsn.clone(),
        environment: config.sentry_environment.clone().map(Into::into),
        ..Default::default()
    });

    tracing_subscriber::registry()
        .with(fmt::layer().with_filter(EnvFilter::from_default_env()))
        .with(sentry_tracing::layer())
        .init();

    let db = PgPoolOptions::new()
        .min_connections(config.min_database_connections)
        .max_connections(config.max_database_connections)
        .connect(&config.database_url)
        .await
        .context("failed to connect to database")?;

    sqlx::migrate!().run(&db).await?;

    http::serve(config, db).await
}
