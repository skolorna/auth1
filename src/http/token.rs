use axum::{
    response::{IntoResponse, Response},
    routing::post,
    Extension, Form, Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::{
    jwt::{access_token, refresh_token},
    oob::{self, Otp},
};

use super::{ApiContext, Result};

#[derive(Debug, Deserialize)]
#[serde(tag = "grant_type", rename_all = "snake_case")]
enum TokenRequest {
    Otp { token: String, otp: Otp },
    RefreshToken { refresh_token: String },
}

#[derive(Debug, Serialize)]
pub struct TokenResponseJson {
    pub access_token: String,
    pub token_type: TokenType,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

#[derive(Debug)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

impl IntoResponse for TokenResponse {
    fn into_response(self) -> Response {
        Json(TokenResponseJson {
            access_token: self.access_token,
            token_type: TokenType::Bearer,
            expires_in: access_token::TTL.whole_seconds(),
            refresh_token: self.refresh_token,
        })
        .into_response()
    }
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
    let mut tx = ctx.db.begin().await?;

    let res = match req {
        TokenRequest::Otp { token, otp } => {
            let claims = oob::verify(&token, otp, &mut tx).await?;

            let (jwt_secret,) =
                sqlx::query_as::<_, (Vec<u8>,)>("SELECT jwt_secret FROM users WHERE id = $1")
                    .bind(claims.sub)
                    .fetch_one(&mut tx)
                    .await?;

            if matches!(claims.band, oob::Band::Email) {
                sqlx::query!("UPDATE users SET verified = true WHERE id = $1", claims.sub)
                    .execute(&mut tx)
                    .await?;
            }

            oob::update_secret(claims.sub, &mut tx).await?;

            TokenResponse {
                access_token: access_token::sign(claims.sub, &ctx.ca, &mut tx).await?,
                refresh_token: Some(refresh_token::sign(claims.sub, &jwt_secret)?),
            }
        }
        TokenRequest::RefreshToken { refresh_token } => {
            let claims = refresh_token::verify(&refresh_token, &mut tx).await?;

            TokenResponse {
                access_token: access_token::sign(claims.sub, &ctx.ca, &mut tx).await?,
                refresh_token: None,
            }
        }
    };

    tx.commit().await?;

    Ok(res)
}

pub fn routes() -> Router {
    Router::new().route("/", post(request_token))
}
