use actix_web::{post, web, HttpResponse};
use serde::Deserialize;

use crate::result::Result;
use crate::token::VerificationToken;
use crate::DbPool;

#[derive(Deserialize)]
pub struct VerificationQuery {
    token: VerificationToken,
}

#[post("")]
async fn verify_email(
    pool: web::Data<DbPool>,
    info: web::Json<VerificationQuery>,
) -> Result<HttpResponse> {
    let conn = pool.get()?;
    info.token.verify(&conn)?;

    Ok(HttpResponse::Ok().body("success"))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(verify_email);
}
