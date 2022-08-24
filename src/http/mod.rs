use anyhow::Context;
use axum::{response::IntoResponse, routing::get, Extension, Json, Router};
use lettre::{AsyncSmtpTransport, Tokio1Executor};
use serde::Serialize;
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};

use crate::Config;

mod error;
mod users;

pub use error::Error;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Clone)]
struct ApiContext {
    config: Arc<Config>,
    db: PgPool,
    smtp: AsyncSmtpTransport<Tokio1Executor>,
}

pub async fn serve(config: Config, db: PgPool) -> anyhow::Result<()> {
    let smtp = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)?
        .credentials(config.smtp_credentials())
        .build();

    let app = app(config, db, smtp);

    axum::Server::bind(&SocketAddr::from(([0, 0, 0, 0], 8000)))
        .serve(app.into_make_service())
        .await
        .context("serve failed")
}

pub fn app(config: Config, db: PgPool, smtp: AsyncSmtpTransport<Tokio1Executor>) -> Router {
    Router::new()
        .route("/health", get(health))
        .nest("/users", users::routes())
        .layer(Extension(ApiContext {
            config: Arc::new(config),
            db,
            smtp,
        }))
}

#[derive(Debug, Serialize)]
struct Health {
    version: &'static str,
}

async fn health() -> impl IntoResponse {
    let health = Health {
        version: env!("CARGO_PKG_VERSION"),
    };

    ([("cache-control", "no-cache")], Json(health))
}
