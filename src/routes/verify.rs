use actix_web::http::header::{CacheControl, CacheDirective};
use actix_web::{get, web, HttpResponse};
use serde::Deserialize;

use crate::result::Result;
use crate::token::VerificationToken;
use crate::DbPool;

#[derive(Deserialize)]
pub struct VerificationQuery {
    token: VerificationToken,
}

#[get("")]
async fn verify_email(
    pool: web::Data<DbPool>,
    web::Query(info): web::Query<VerificationQuery>,
) -> Result<HttpResponse> {
    let conn = pool.get()?;
    info.token.verify(&conn)?;

    Ok(HttpResponse::NoContent()
        .set(CacheControl(vec![CacheDirective::NoCache]))
        .body(""))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(verify_email);
}
