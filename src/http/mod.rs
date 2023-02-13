use anyhow::Context;
use axum::{response::IntoResponse, routing::get, Extension, Json, Router};

use axum_tracing_opentelemetry::opentelemetry_tracing_layer;
use serde::Serialize;
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

use crate::{email, x509, Config};

mod account;
mod error;
mod extract;
mod keys;
mod login;
mod token;
mod users;

pub use error::Error;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Clone)]
struct ApiContext {
    db: PgPool,
    email: Arc<email::Client>,
    ca: Arc<RwLock<x509::Authority>>,
}

pub async fn serve(config: Config, db: PgPool) -> anyhow::Result<()> {
    let client = config.email_client()?;
    let ca = config.ca()?;

    let app = app(db, client, ca);

    axum::Server::bind(&SocketAddr::from(([0, 0, 0, 0], 8000)))
        .serve(app.into_make_service())
        .await
        .context("serve failed")
}

pub fn app(db: PgPool, email: email::Client, ca: Arc<RwLock<x509::Authority>>) -> Router {
    Router::new()
        .nest("/account", account::routes())
        .nest("/keys", keys::routes())
        .nest("/users", users::routes())
        .nest("/token", token::routes())
        .nest("/login", login::routes())
        .layer(Extension(ApiContext {
            db,
            email: Arc::new(email),
            ca,
        }))
        .layer(opentelemetry_tracing_layer())
        .route("/health", get(health))
        .layer(CorsLayer::very_permissive())
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
