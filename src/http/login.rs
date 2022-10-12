use axum::{response::IntoResponse, routing::post, Extension, Json, Router, http::StatusCode};
use serde::Deserialize;
use uuid::Uuid;

use crate::jwt::oob;

use super::{ApiContext, Error, Result};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    email: String,
}

async fn login(
    Json(req): Json<LoginRequest>,
    ctx: Extension<ApiContext>,
) -> Result<impl IntoResponse> {
    let mut tx = ctx.db.begin().await?;

    let (user, secret) = sqlx::query_as::<_, (Uuid, Option<Vec<u8>>)>(
        "SELECT id, oob_secret FROM users WHERE email = $1",
    )
    .bind(&req.email)
    .fetch_optional(&mut tx)
    .await?
    .ok_or(Error::WrongEmailPassword)?;

    let secret = if let Some(secret) = secret {
        secret
    } else {
        oob::update_secret(user, &mut tx).await?.to_vec() // suboptimal heap allocation
    };

    let token = oob::sign(user, oob::Band::Email, &req.email, &secret)?;

    todo!();

    tx.commit().await?;

    Ok(StatusCode::ACCEPTED)
}

pub fn routes() -> Router {
    Router::new().route("/", post(login))
}
