use anyhow::Context;
use axum::{response::IntoResponse, routing::get, Extension, Json, Router};

use serde::Serialize;
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};

use crate::{email, x509, Config};

mod error;
mod extract;
mod keys;
mod token;
mod users;
mod verify;

pub use error::Error;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Clone)]
struct ApiContext {
    db: PgPool,
    email: Arc<email::Client>,
    ca: Arc<x509::Authority>,
}

pub async fn serve(config: Config, db: PgPool) -> anyhow::Result<()> {
    let client = config.email_client()?;
    let ca = x509::Authority::self_signed().context("error generating self-signed certificate")?;

    let app = app(db, client, ca);

    axum::Server::bind(&SocketAddr::from(([0, 0, 0, 0], 8000)))
        .serve(app.into_make_service())
        .await
        .context("serve failed")
}

pub fn app(db: PgPool, email: email::Client, ca: x509::Authority) -> Router {
    Router::new()
        .route("/health", get(health))
        .nest("/users", users::routes())
        .nest("/keys", keys::routes())
        .nest("/token", token::routes())
        .nest("/verify", verify::routes())
        .layer(Extension(ApiContext {
            db,
            email: Arc::new(email),
            ca: Arc::new(ca),
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
