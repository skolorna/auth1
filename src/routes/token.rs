use actix_web::{post, web, HttpResponse};
use serde::{Deserialize, Serialize};

use crate::{
    db::postgres::PgPool,
    errors::AppResult,
    token::{refresh_token::RefreshToken, AccessToken, TokenResponse},
};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ManageTokenRequest {
    RefreshAccessToken { refresh_token: RefreshToken },
}

#[derive(Debug, Serialize)]
struct RefreshAccessTokenResponse {
    access_token: AccessToken,
}

#[post("")]
async fn manage_token(
    pool: web::Data<PgPool>,
    web::Json(req): web::Json<ManageTokenRequest>,
) -> AppResult<HttpResponse> {
    let conn = pool.get()?;

    let res: TokenResponse = match req {
        ManageTokenRequest::RefreshAccessToken { refresh_token } => {
            let access_token = refresh_token.sign_access_token_simple(&conn)?;

            TokenResponse {
                access_token,
                refresh_token: None,
            }
        }
    };

    Ok(HttpResponse::Ok().json(res))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(manage_token);
}
