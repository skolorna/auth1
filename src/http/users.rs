use argon2::{password_hash::SaltString, Argon2, PasswordHash};
use axum::{
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use lettre::{message::Mailbox, Address};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{error::SqlxResultExt, extract::Identity, ApiContext, Error, Result};
use crate::{
    email::send_confirmation_email,
    jwt::{self, verification_token},
};

#[derive(Debug, Deserialize)]
struct NewUser {
    email: Address,
    password: String,
    full_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserJson {
    id: Uuid,
    email: String,
    full_name: String,
    verified: bool,
}

async fn register(
    ctx: Extension<ApiContext>,
    Json(req): Json<NewUser>,
) -> Result<impl IntoResponse> {
    let password_hash = hash_password(req.password).await?;
    let uid = Uuid::new_v4();
    let jwt_secret = jwt::refresh_token::gen_secret();
    let refresh_token = jwt::refresh_token::sign(uid, &jwt_secret)?;

    let mut tx = ctx.db.begin().await?;

    let access_token = jwt::access_token::sign(uid, &ctx.ca, &mut tx).await?;

    sqlx::query!(
        r#"INSERT INTO users (id, email, full_name, hash, jwt_secret) VALUES ($1, $2, $3, $4, $5)"#,
        uid,
        req.email.to_string(),
        req.full_name,
        password_hash,
        &jwt_secret,
    )
    .execute(&mut tx)
    .await
    .on_constraint("users_email_key", |_| Error::EmailInUse)?;

    let verification_token = verification_token::sign(req.email.to_string(), &password_hash)?;

    send_confirmation_email(
        &ctx.email,
        Mailbox::new(Some(req.full_name), req.email),
        &verification_token,
    )
    .await?;

    tx.commit().await?;

    Ok(access_token)
}

async fn current_user(ctx: Extension<ApiContext>, identity: Identity) -> Result<impl IntoResponse> {
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
    Router::new()
        .route("/", post(register))
        .route("/@me", get(current_user))
}

async fn hash_password(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || -> Result<String> {
        let salt = SaltString::generate(rand::thread_rng());
        Ok(
            PasswordHash::generate(Argon2::default(), password, salt.as_str())
                .map_err(|_| Error::internal())?
                .to_string(),
        )
    })
    .await
    .map_err(|_| Error::internal())?
}
