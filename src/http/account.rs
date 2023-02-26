use axum::{response::IntoResponse, routing::get, Extension, Json, Router};
use lettre::{message::Mailbox, Address};
use serde::{Deserialize, Serialize};

use time::OffsetDateTime;
use tracing::instrument;
use uuid::Uuid;

use super::{extract::Identity, login::LoginResponse, ApiContext, Result};
use crate::{
    email::send_login_email,
    oob,
    util::{create_user, CreatedUser},
};

#[derive(Debug, Deserialize)]
struct NewUser {
    email: Address,
    full_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: Uuid,
    email: String,
    full_name: String,
    verified: bool,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    last_login: Option<OffsetDateTime>,
}

#[instrument(skip_all)]
async fn register(
    ctx: Extension<ApiContext>,
    Json(req): Json<NewUser>,
) -> Result<impl IntoResponse> {
    let mut tx = ctx.db.begin().await?;

    let email = req.email.to_string();

    let CreatedUser {
        id,
        jwt_secret: _,
        oob_secret,
    } = create_user(&email, Some(&req.full_name), &mut tx).await?;

    let (token, otp) = oob::sign(id, oob::Band::Email, email.as_bytes(), &oob_secret);

    send_login_email(
        &ctx.email,
        Mailbox::new(Some(req.full_name), req.email),
        otp,
    )
    .await?;

    tx.commit().await?;

    Ok(LoginResponse { token })
}

#[instrument(skip_all)]
async fn get_current_user(ctx: Extension<ApiContext>, identity: Identity) -> Result<Json<User>> {
    let user = sqlx::query_as!(
        User,
        "SELECT id, email, verified, full_name, created_at, last_login FROM users WHERE id = $1",
        identity.claims.sub
    )
    .fetch_one(&ctx.db)
    .await?;

    Ok(Json(user))
}

pub fn routes() -> Router {
    Router::new().route("/", get(get_current_user).post(register))
}
