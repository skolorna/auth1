use argon2::{password_hash::SaltString, Argon2, PasswordHash};
use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, put},
    Extension, Json, Router,
};
use lettre::{message::Mailbox, Address};
use serde::{Deserialize, Serialize};

use tracing::instrument;
use uuid::Uuid;

use super::{
    extract::Identity,
    token::{verify_password, TokenResponse, TokenType},
    ApiContext, Error, Result,
};
use crate::{
    email::{send_confirmation_email, send_password_reset_email},
    jwt::{access_token, email_token, refresh_token, reset_token},
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

#[instrument(skip_all)]
async fn register(
    ctx: Extension<ApiContext>,
    Json(req): Json<NewUser>,
) -> Result<impl IntoResponse> {
    let password_hash = hash_password(req.password).await?;
    let uid = Uuid::new_v4();
    let jwt_secret = refresh_token::gen_secret();

    let mut tx = ctx.db.begin().await?;

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
    .map_err(|e| match e {
        sqlx::Error::Database(dbe) if dbe.constraint() == Some("users_email_key") => {
            Error::email_in_use()
        }
        e => e.into(),
    })?;

    let refresh_token = refresh_token::sign(uid, &jwt_secret)?;
    let access_token = access_token::sign(uid, &ctx.ca, &mut tx).await?;
    let email_token = email_token::sign(uid, req.email.to_string(), &password_hash)?;

    send_confirmation_email(
        &ctx.email,
        Mailbox::new(Some(req.full_name), req.email),
        &email_token,
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

#[instrument(skip_all)]
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
    .map_err(|e| match e {
        sqlx::Error::Database(dbe) if dbe.constraint() == Some("users_email_key") => {
            Error::email_in_use()
        }
        e => e.into(),
    })?;

    if updated_email || !record.verified {
        send_confirmation_email(
            &ctx.email,
            Mailbox::new(Some(record.full_name.clone()), req.email.unwrap()),
            &email_token::sign(identity.claims.sub, record.email.clone(), &record.hash)?,
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

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ResetPassword {
    RequestToken { email: Address },
    Finalize { token: String, password: String },
}

async fn reset_password(
    Json(req): Json<ResetPassword>,
    ctx: Extension<ApiContext>,
) -> Result<impl IntoResponse> {
    match req {
        ResetPassword::RequestToken { email } => {
            let record = sqlx::query!(
                "SELECT full_name, id, hash FROM users WHERE email = $1",
                &email.to_string()
            )
            .fetch_optional(&ctx.db)
            .await?;

            if let Some(record) = record {
                let token = reset_token::sign(record.id, email.as_ref(), &record.hash)?;
                let to = Mailbox::new(Some(record.full_name), email);

                send_password_reset_email(&ctx.email, to, &token).await?;
            }

            Ok(StatusCode::ACCEPTED)
        }
        ResetPassword::Finalize { token, password } => {
            let mut tx = ctx.db.begin().await?;

            let claims = reset_token::verify(&token, &mut tx).await?;

            let password_hash = hash_password(password).await?;
            let jwt_secret = refresh_token::gen_secret();

            sqlx::query!(
                "UPDATE users SET hash = $1, jwt_secret = $2 WHERE id = $3",
                password_hash,
                &jwt_secret,
                claims.sub
            )
            .execute(&mut tx)
            .await?;

            tx.commit().await?;

            Ok(StatusCode::NO_CONTENT)
        }
    }
}

pub fn routes() -> Router {
    Router::new()
        .route("/", get(get_current_user).patch(update_user).post(register))
        .route("/password", put(reset_password))
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
