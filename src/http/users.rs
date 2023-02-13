use axum::{extract::Path, response::IntoResponse, routing::get, Extension, Json, Router};
use serde::Serialize;
use sqlx::FromRow;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{ApiContext, Error, Result};

#[derive(Debug, Serialize, FromRow)]
struct Profile {
    id: Uuid,
    full_name: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

async fn profile(ctx: Extension<ApiContext>, Path(id): Path<Uuid>) -> Result<impl IntoResponse> {
    let profile = sqlx::query_as!(
        Profile,
        "SELECT id, full_name, created_at FROM users WHERE id = $1",
        id,
    )
    .fetch_optional(&ctx.db)
    .await?
    .ok_or(Error::AccountNotFound)?;

    Ok(([("cache-control", "no-cache")], Json(profile)))
}

pub fn routes() -> Router {
    Router::new().route("/:id/profile", get(profile))
}
