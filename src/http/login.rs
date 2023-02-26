use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Extension, Json, Router,
};
use lettre::message::Mailbox;
use serde::{Deserialize, Serialize};
use tracing::error;
use uuid::Uuid;

use crate::{email::send_login_email, oob};

use super::{ApiContext, Error, Result};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    email: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
}

impl IntoResponse for LoginResponse {
    fn into_response(self) -> Response {
        (StatusCode::ACCEPTED, Json(self)).into_response()
    }
}

async fn login(
    ctx: Extension<ApiContext>,
    Json(LoginRequest { email }): Json<LoginRequest>,
) -> Result<LoginResponse> {
    let mut tx = ctx.db.begin().await?;

    let (full_name, user, secret) = sqlx::query_as::<_, (String, Uuid, Option<Vec<u8>>)>(
        "SELECT full_name, id, oob_secret FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&mut tx)
    .await?
    .ok_or(Error::AccountNotFound)?;

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
        oob::update_secret(user, &mut tx).await?.to_vec() // suboptimal heap allocation?
    };

    let (token, otp) = oob::sign(user, oob::Band::Email, &email, &secret);

    send_login_email(&ctx.email, mailbox, otp).await?;

    tx.commit().await?;

    Ok(LoginResponse { token })
}

// async fn oauth_login(
//     ctx: Extension<ApiContext>,
//     cookie_jar: CookieJar,
// ) -> Result<impl IntoResponse> {
//     let client = &ctx.oidc.google;

//     let (url, csrf_token, _nonce) = client.authorize_url(
//             AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
//             CsrfToken::new_random,
//             Nonce::new_random,
//         )
//         .add_scope(Scope::new("email".to_owned()))
//         .add_scope(Scope::new("profile".to_owned()))
//         .url();

//     let csrf_cookie = Cookie::new("CSRF_TOKEN", csrf_token.secret().clone());

//     Ok((
//         StatusCode::SEE_OTHER,
//         [(LOCATION, HeaderValue::try_from(url.as_str()).unwrap())],
//         cookie_jar.add(csrf_cookie),
//     ))
// }

// #[derive(Debug, Deserialize)]
// struct CallbackParameters {
//     code: AuthorizationCode,
//     state: CsrfToken,
// }

// async fn oauth_callback(
//     ctx: Extension<ApiContext>,
//     Query(query): Query<CallbackParameters>,
//     cookie_jar: CookieJar,
// ) -> Result<impl IntoResponse> {
//     if cookie_jar.get("CSRF_TOKEN").ok_or(Error::OIDC)?.value() != query.state.secret() {
//         error!("csrf token mismatch");
//         return Err(Error::OIDC);
//     }

//     let client = &ctx.oidc.google;

//     let res = client
//         .exchange_code(query.code)
//         .request_async(async_http_client)
//         .await?;

//     let claims: CoreUserInfoClaims = client
//         .user_info(res.access_token().clone(), None)
//         .unwrap()
//         .request_async(async_http_client)
//         .await?;

//     // create_or_login_oidc_user(claims, &ctx.ca, ctx.db).await?;

//     Ok(())
// }

pub fn routes() -> Router {
    Router::new().route("/", post(login))
    // .route("/google", get(oauth_login))
    // .route("/google/code", get(oauth_callback))
}
