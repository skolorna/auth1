use argon2::{password_hash::SaltString, Argon2, PasswordHash};
use axum::{response::IntoResponse, routing::post, Extension, Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use super::{ApiContext, Error, Result};
use crate::jwt;

#[derive(Debug, Deserialize)]
struct NewUser {
    email: String,
    password: String,
    full_name: String,
}

async fn register(
    ctx: Extension<ApiContext>,
    Json(req): Json<NewUser>,
) -> Result<impl IntoResponse> {
    let password_hash = hash_password(req.password).await?;
    let uid = Uuid::new_v4();
    let jwt_secret = jwt::gen_secret();
    let refresh_token = jwt::refresh_token::sign(uid, &jwt_secret)?;

    let mut tx = ctx.db.begin().await?;

    sqlx::query!(
        r#"INSERT INTO users (id, email, full_name, hash, jwt_secret) values ($1, $2, $3, $4, $5)"#,
        uid,
        req.email,
        req.full_name,
        password_hash,
        &jwt_secret,
    )
    .execute(&mut tx)
    .await?;

    tx.commit().await?;

    Ok(refresh_token)
}

pub fn routes() -> Router {
    Router::new().route("/", post(register))
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