use axum::{
    extract::Path,
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::http::extract::Identity;

use super::{ApiContext, Error, Result};

#[derive(Debug, Serialize)]
struct Profile {
    id: Uuid,
    full_name: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
}

async fn get_profile(
    ctx: Extension<ApiContext>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse> {
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

#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
struct UpdateProfile {
    full_name: Option<String>,
}

impl UpdateProfile {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

async fn update_profile(
    ctx: Extension<ApiContext>,
    identity: Identity,
    Path(id): Path<Uuid>,
    Json(data): Json<UpdateProfile>,
) -> Result<Response> {
    if identity.claims.sub != id {
        return Err(Error::Forbidden);
    }

    if data.is_empty() {
        return Ok(get_profile(ctx, Path(id)).await?.into_response());
    }

    let profile = sqlx::query_as!(
        Profile,
        "UPDATE users SET full_name = COALESCE($1, full_name) WHERE id = $2 RETURNING id, full_name, created_at",
        data.full_name,
        id,
    ).fetch_one(&ctx.db).await?;

    Ok(([("cache-control", "no-cache")], Json(profile)).into_response())
}

pub fn routes() -> Router {
    Router::new().route("/:id/profile", get(get_profile).patch(update_profile))
}
