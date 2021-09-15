use actix_web::{post, web, HttpResponse};
use serde::Deserialize;

use crate::db::postgres::PgPool;
use crate::result::Result;
use crate::token::VerificationToken;

#[derive(Deserialize)]
pub struct VerificationQuery {
    token: VerificationToken,
}

#[post("")]
async fn verify_email(
    pool: web::Data<PgPool>,
    info: web::Json<VerificationQuery>,
) -> Result<HttpResponse> {
    let conn = pool.get()?;
    info.token.verify(&conn)?;

    Ok(HttpResponse::Ok().body("success"))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(verify_email);
}
