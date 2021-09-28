use actix_web::{post, web, HttpResponse};
use serde::Deserialize;

use crate::client_info::ClientInfo;
use crate::db::postgres::PgPool;
use crate::db::redis::RedisPool;
use crate::email::{EmailBackend};
use crate::errors::{AppResult, Error};
use crate::identity::Identity;

use crate::token::VerificationToken;

#[derive(Deserialize)]
pub struct VerificationQuery {
    token: VerificationToken,
}

#[post("")]
async fn verify_email(
    pool: web::Data<PgPool>,
    info: web::Json<VerificationQuery>,
) -> AppResult<HttpResponse> {
    let conn = pool.get()?;
    info.token.verify(&conn)?;

    Ok(HttpResponse::Ok().body("success"))
}

#[post("/resend")]
async fn resend_verification(
    _redis: web::Data<RedisPool>,
    _email: web::Data<EmailBackend>,
    _client_info: ClientInfo,
    ident: Identity,
) -> AppResult<HttpResponse> {
    if ident.user.verified {
        return Err(Error::AlreadyVerified);
    }

    todo!();

    // web::block(move || {
    //     EMAIL_RATE_LIMIT.remaining_requests(&client_info.addr, &mut redis.get()?)?;
    //     send_verification_email(&email, &ident.user)
    // })
    // .await?;

    Ok(HttpResponse::NoContent().body(""))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(verify_email).service(resend_verification);
}
