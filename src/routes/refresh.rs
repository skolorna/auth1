use actix_web::{post, web, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::{
    db::postgres::PgPool,
    errors::AppResult,
    token::{refresh_token::RefreshToken, AccessToken},
};

#[derive(Debug, Deserialize)]
struct RefreshAccessTokenRequest {
    token: RefreshToken,
}

#[derive(Debug, Serialize)]
struct RefreshAccessTokenResponse {
    access_token: AccessToken,
}

#[post("")]
async fn refresh_access_token(
    pool: web::Data<PgPool>,
    web::Json(RefreshAccessTokenRequest { token }): web::Json<RefreshAccessTokenRequest>,
) -> AppResult<HttpResponse> {
    let conn = pool.get()?;
    let access_token = token.sign_access_token_simple(&conn)?;

    Ok(HttpResponse::Ok().json(RefreshAccessTokenResponse { access_token }))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(refresh_access_token);
}
