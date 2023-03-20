use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
use lettre::{message::Mailbox, Address};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use time::OffsetDateTime;
use tracing::instrument;
use uuid::Uuid;

use super::{extract::Identity, login::LoginResponse, AppState, Result};
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
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    last_login: Option<OffsetDateTime>,
}

#[instrument(skip_all)]
async fn register(state: State<AppState>, Json(req): Json<NewUser>) -> Result<impl IntoResponse> {
    let mut tx = state.db.begin().await?;

    let email = req.email.to_string();

    let CreatedUser {
        id,
        jwt_secret: _,
        oob_secret,
    } = create_user(&email, Some(&req.full_name), &mut tx).await?;

    let (token, otp) = oob::sign(id, oob::Band::Email, email.as_bytes(), &oob_secret);

    send_login_email(
        &state.email,
        Mailbox::new(Some(req.full_name), req.email),
        otp,
    )
    .await?;

    tx.commit().await?;

    Ok(LoginResponse { token })
}

#[instrument(skip_all)]
async fn get_current_user(State(db): State<PgPool>, identity: Identity) -> Result<Json<User>> {
    let user = sqlx::query_as!(
        User,
        "SELECT id, email, full_name, created_at, last_login FROM users WHERE id = $1",
        identity.claims.sub
    )
    .fetch_one(&db)
    .await?;

    Ok(Json(user))
}

pub fn routes() -> Router<AppState> {
    Router::<_>::new().route("/", get(get_current_user).post(register))
}
