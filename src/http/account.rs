use axum::{response::IntoResponse, routing::get, Extension, Json, Router};
use lettre::{message::Mailbox, Address};
use serde::{Deserialize, Serialize};

use tracing::instrument;
use uuid::Uuid;

use super::{extract::Identity, login::LoginResponse, ApiContext, Error, Result};
use crate::{email::send_login_email, jwt::refresh_token, oob};

#[derive(Debug, Deserialize)]
struct NewUser {
    email: Address,
    full_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserJson {
    id: Uuid,
    email: String,
    full_name: String,
    verified: bool,
}

#[instrument(skip_all)]
async fn register(
    ctx: Extension<ApiContext>,
    Json(req): Json<NewUser>,
) -> Result<impl IntoResponse> {
    let uid = Uuid::new_v4();
    let jwt_secret = refresh_token::gen_secret();

    let mut tx = ctx.db.begin().await?;

    let email = req.email.to_string();
    let oob_secret = oob::gen_secret();

    sqlx::query!(
        r#"INSERT INTO users (id, email, full_name, jwt_secret, oob_secret) VALUES ($1, $2, $3, $4, $5)"#,
        uid,
        &email,
        req.full_name,
        &jwt_secret,
        &oob_secret,
    )
    .execute(&mut tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(dbe) if dbe.constraint() == Some("users_email_key") => {
            Error::email_in_use()
        }
        e => e.into(),
    })?;

    let (token, otp) = oob::sign(uid, oob::Band::Email, email.as_bytes(), &oob_secret);

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
async fn get_current_user(
    ctx: Extension<ApiContext>,
    identity: Identity,
) -> Result<Json<UserJson>> {
    let user = sqlx::query_as!(
        UserJson,
        "SELECT id, email, verified, full_name FROM users WHERE id = $1",
        identity.claims.sub
    )
    .fetch_one(&ctx.db)
    .await?;

    Ok(Json(user))
}

pub fn routes() -> Router {
    Router::new().route("/", get(get_current_user).post(register))
}
