use axum::{http::StatusCode, response::IntoResponse, routing::post, Extension, Json, Router};
use lettre::message::Mailbox;
use serde::Deserialize;
use tracing::error;
use uuid::Uuid;

use crate::{email::send_login_email, jwt::oob};

use super::{ApiContext, Error, Result};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    email: String,
}

async fn login(
    Json(LoginRequest { email }): Json<LoginRequest>,
    ctx: Extension<ApiContext>,
) -> Result<impl IntoResponse> {
    let mut tx = ctx.db.begin().await?;

    let (full_name, user, secret) = sqlx::query_as::<_, (String, Uuid, Option<Vec<u8>>)>(
        "SELECT full_name, id, oob_secret FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&mut tx)
    .await?
    .ok_or(Error::WrongEmailPassword)?;

    let mailbox = Mailbox::new(
        Some(full_name),
        email.parse().map_err(|_| {
            error!(%user, email, "failed to parse email of existing user");
            Error::Internal
        })?,
    );

    let secret = if let Some(secret) = secret {
        secret
    } else {
        oob::update_secret(user, &mut tx).await?.to_vec() // suboptimal heap allocation
    };

    let token = oob::sign(user, oob::Band::Email, &email, &secret)?;

    send_login_email(&ctx.email, mailbox, &token, false).await?;

    tx.commit().await?;

    Ok(StatusCode::ACCEPTED)
}

pub fn routes() -> Router {
    Router::new().route("/", post(login))
}
