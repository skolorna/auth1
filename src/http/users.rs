use argon2::{password_hash::SaltString, Argon2, PasswordHash};
use axum::{
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use lettre::{message::Mailbox, Address};
use serde::{Deserialize, Serialize};

use uuid::Uuid;

use super::{
    error::SqlxResultExt,
    extract::Identity,
    token::{verify_password, TokenResponse, TokenType},
    ApiContext, Error, Result,
};
use crate::{
    email::send_confirmation_email,
    jwt::{access_token, refresh_token, verification_token},
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
    let jwt_secret = refresh_token::gen_secret();
    let refresh_token = refresh_token::sign(uid, &jwt_secret)?;

    let mut tx = ctx.db.begin().await?;

    let access_token = access_token::sign(uid, &ctx.ca, &mut tx).await?;

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

    let verification_token = verification_token::sign(uid, req.email.to_string(), &password_hash)?;

    send_confirmation_email(
        &ctx.email,
        Mailbox::new(Some(req.full_name), req.email),
        &verification_token,
        true,
    )
    .await?;

    tx.commit().await?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: TokenType::Bearer,
        expires_in: access_token::TTL.whole_seconds(),
        refresh_token: Some(refresh_token),
    }))
}

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

#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
struct UpdateUser {
    email: Option<Address>,
    full_name: Option<String>,
    password: Option<String>,
    new_password: Option<String>,
}

impl UpdateUser {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

async fn update_user(
    ctx: Extension<ApiContext>,
    identity: Identity,
    Json(req): Json<UpdateUser>,
) -> Result<Json<UserJson>> {
    if req.is_empty() {
        return get_current_user(ctx, identity).await;
    }

    let mut tx = ctx.db.begin().await?;

    let email = req.email.as_ref().map(ToString::to_string);

    let updated_email = if let Some(ref new) = email {
        let current =
            sqlx::query_scalar!("SELECT email FROM users WHERE id = $1", identity.claims.sub)
                .fetch_one(&mut tx)
                .await?;
        current != *new
    } else {
        false
    };

    if updated_email || req.new_password.is_some() {
        // updating these fields requires password authentication

        let password = req.password.ok_or(Error::PasswordRequired)?;

        let current_hash =
            sqlx::query_scalar!("SELECT hash FROM users WHERE id = $1", identity.claims.sub)
                .fetch_one(&mut tx)
                .await?;

        verify_password(password, current_hash).await?;
    }

    let (hash, jwt_secret) = if let Some(new_password) = req.new_password {
        (
            Some(hash_password(new_password).await?),
            Some(refresh_token::gen_secret()),
        )
    } else {
        (None, None)
    };

    let jwt_secret = jwt_secret.as_ref().map(|a| &a[..]);

    let record = sqlx::query!(
        r#"
            UPDATE users
            SET email = COALESCE($1, users.email),
                verified = COALESCE($2, users.verified),
                full_name = COALESCE($3, users.full_name),
                hash = COALESCE($4, users.hash),
                jwt_secret = COALESCE($5, users.jwt_secret)
            WHERE id = $6
            RETURNING id, email, verified, full_name, hash
        "#,
        email,
        updated_email.then_some(false),
        req.full_name,
        hash,
        jwt_secret,
        identity.claims.sub
    )
    .fetch_one(&mut tx)
    .await
    .on_constraint("user_email_key", |_| Error::EmailInUse)?;

    if updated_email {
        send_confirmation_email(
            &ctx.email,
            Mailbox::new(Some(record.full_name.clone()), req.email.unwrap()),
            &verification_token::sign(identity.claims.sub, record.email.clone(), &record.hash)?,
            false,
        )
        .await?;
    }

    tx.commit().await?;

    Ok(Json(UserJson {
        id: record.id,
        email: record.email,
        full_name: record.full_name,
        verified: record.verified,
    }))
}

pub fn routes() -> Router {
    Router::new()
        .route("/", post(register))
        .route("/@me", get(get_current_user).patch(update_user))
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
