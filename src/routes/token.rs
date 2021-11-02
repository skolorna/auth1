use actix_web::{web, HttpResponse};
use serde::Deserialize;

use crate::{
    db::postgres::PgPool,
    errors::AppResult,
    models::Certificate,
    token::{access_token, refresh_token, TokenResponse},
    x509::CertificateAuthority,
};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ManageTokenRequest {
    RefreshAccessToken { refresh_token: String },
}

async fn manage_token(
    pool: web::Data<PgPool>,
    ca: web::Data<CertificateAuthority>,
    web::Json(req): web::Json<ManageTokenRequest>,
) -> AppResult<HttpResponse> {
    let pg = pool.get()?;

    let res: TokenResponse = match req {
        ManageTokenRequest::RefreshAccessToken {
            refresh_token: data,
        } => {
            let claims = refresh_token::decode(&pg, &data)?;
            let cert = Certificate::for_signing(&pg, &ca)?;

            TokenResponse {
                access_token: access_token::sign(&cert, claims.sub)?,
                refresh_token: None,
            }
        }
    };

    Ok(HttpResponse::Ok().json(res))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("").route(web::post().to(manage_token)));
}
