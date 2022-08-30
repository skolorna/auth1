use anyhow::Context;
use auth1::{http, Config};
use clap::Parser;
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenv::dotenv();

    tracing_subscriber::fmt::init();

    let config = Config::parse();

    let db = PgPoolOptions::new()
        .max_connections(config.max_database_connections)
        .connect(&config.database_url)
        .await
        .context("failed to connect to database")?;

    sqlx::migrate!().run(&db).await?;

    http::serve(config, db).await
}
