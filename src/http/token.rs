use argon2::{Argon2, PasswordHash};
use axum::{response::IntoResponse, routing::post, Extension, Form, Json, Router};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use crate::jwt::{access_token, oob, refresh_token};

use super::{ApiContext, Error, Result};

#[derive(Debug, Deserialize)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
enum TokenRequest {
    Password {
        /// Actually an email, but "username" conforms to OpenID spec
        username: String,
        password: String,
    },
    Oob {
        token: String,
    },
    RefreshToken {
        refresh_token: String,
    },
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: TokenType,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub enum TokenType {
    Bearer,
}

#[instrument(skip_all)]
async fn request_token(
    ctx: Extension<ApiContext>,
    Form(req): Form<TokenRequest>,
) -> Result<impl IntoResponse> {
    let mut conn = ctx.db.acquire().await?;

    let res = match req {
        TokenRequest::Password { username, password } => {
            let (uid, password_hash, jwt_secret) = sqlx::query_as::<_, (Uuid, String, Vec<u8>)>(
                "SELECT id, hash, jwt_secret FROM users WHERE email = $1",
            )
            .bind(username)
            .fetch_optional(&mut conn)
            .await?
            .ok_or_else(Error::email_not_in_use)?;

            verify_password(password, password_hash).await?;

            TokenResponse {
                access_token: access_token::sign(uid, &ctx.ca, &mut conn).await?,
                token_type: TokenType::Bearer,
                expires_in: access_token::TTL.whole_seconds(),
                refresh_token: Some(refresh_token::sign(uid, &jwt_secret)?),
            }
        }
        TokenRequest::Oob { token } => {
            let claims = oob::verify(&token, &mut conn).await?;

            let (jwt_secret,) =
                sqlx::query_as::<_, (Vec<u8>,)>("SELECT jwt_secret FROM users WHERE id = $1")
                    .bind(claims.sub)
                    .fetch_one(&mut conn)
                    .await?;

            oob::update_secret(claims.sub, &mut conn).await?;

            TokenResponse {
                access_token: access_token::sign(claims.sub, &ctx.ca, &mut conn).await?,
                token_type: TokenType::Bearer,
                expires_in: access_token::TTL.whole_seconds(),
                refresh_token: Some(refresh_token::sign(claims.sub, &jwt_secret)?),
            }
        }
        TokenRequest::RefreshToken { refresh_token } => {
            let claims = refresh_token::verify(&refresh_token, &mut conn).await?;

            TokenResponse {
                access_token: access_token::sign(claims.sub, &ctx.ca, &mut conn).await?,
                token_type: TokenType::Bearer,
                expires_in: access_token::TTL.whole_seconds(),
                refresh_token: None,
            }
        }
    };

    Ok(Json(res))
}

pub fn routes() -> Router {
    Router::new().route("/", post(request_token))
}

pub async fn verify_password(password: String, password_hash: String) -> Result<()> {
    tokio::task::spawn_blocking(move || -> Result<()> {
        let hash = PasswordHash::new(&password_hash).map_err(|_| Error::internal())?;

        hash.verify_password(&[&Argon2::default()], password)
            .map_err(|e| match e {
                argon2::password_hash::Error::Password => Error::WrongEmailPassword,
                _ => Error::internal(),
            })
    })
    .await
    .map_err(|_| Error::internal())?
}
