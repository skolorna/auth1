use actix_web::{web, HttpResponse};
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

async fn manage_token(
    pool: web::Data<PgPool>,
    web::Json(req): web::Json<ManageTokenRequest>,
) -> AppResult<HttpResponse> {
    let conn = pool.get()?;

    let res: TokenResponse = match req {
        ManageTokenRequest::RefreshAccessToken { refresh_token } => {
            let access_token = refresh_token.access_token_ez(&conn)?;

            TokenResponse {
                access_token,
                refresh_token: None,
            }
        }
    };

    Ok(HttpResponse::Ok().json(res))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("").route(web::post().to(manage_token)));
}
