use actix_web::{post, web, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::{
    result::Result,
    token::{AccessToken, RefreshToken},
    DbPool,
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
    pool: web::Data<DbPool>,
    web::Json(RefreshAccessTokenRequest { token }): web::Json<RefreshAccessTokenRequest>,
) -> Result<HttpResponse> {
    let conn = pool.get()?;
    let access_token = token.sign_access_token_simple(&conn)?;

    Ok(HttpResponse::Ok().json(RefreshAccessTokenResponse { access_token }))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(refresh_access_token);
}
