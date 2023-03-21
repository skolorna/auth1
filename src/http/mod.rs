use anyhow::Context;
use axum::{extract::FromRef, response::IntoResponse, routing::get, Json, Router};

use axum_tracing_opentelemetry::opentelemetry_tracing_layer;
use opentelemetry::metrics::Counter;
use serde::Serialize;
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

use crate::{email, oidc::Oidc, x509, Config};

mod account;
mod error;
mod extract;
mod keys;
mod login;
mod token;
mod users;

pub use error::Error;

pub use token::TokenResponse;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(FromRef, Clone)]
pub struct AppState {
    db: PgPool,
    email: Arc<email::Client>,
    ca: Arc<RwLock<x509::Authority>>,
    oidc: Arc<Oidc>,
    issued_tokens: Counter<u64>,
}

pub async fn serve(config: Config, db: PgPool) -> anyhow::Result<()> {
    let meter = opentelemetry::global::meter("auth1");

    let issued_tokens = meter
        .u64_counter("auth1.issued_tokens")
        .with_description("Total number of successful token requests")
        .init();

    let app = app().with_state(AppState {
        db,
        email: Arc::new(config.email_client()?),
        ca: config.ca()?,
        oidc: Arc::new(config.oidc()?),
        issued_tokens,
    });

    axum::Server::bind(&SocketAddr::from(([0, 0, 0, 0], 8000)))
        .serve(app.into_make_service())
        .await
        .context("serve failed")
}

pub fn app() -> Router<AppState> {
    Router::<_>::new()
        .nest("/account", account::routes())
        .nest("/keys", keys::routes())
        .nest("/users", users::routes())
        .nest("/token", token::routes())
        .nest("/login", login::routes())
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
