use actix_web::{post, web, HttpResponse};
use serde::Deserialize;

use crate::client_info::ClientInfo;
use crate::db::postgres::PgPool;
use crate::db::redis::RedisPool;
use crate::email::{send_verification_email, SmtpConnection, EMAIL_RATE_LIMIT};
use crate::identity::Identity;
use crate::rate_limit::RateLimit;
use crate::result::{Error, Result};
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

#[post("/resend")]
async fn resend_verification(
    redis: web::Data<RedisPool>,
    smtp: web::Data<SmtpConnection>,
    client_info: ClientInfo,
    ident: Identity,
) -> Result<HttpResponse> {
    if ident.user.verified {
        return Err(Error::AlreadyVerified);
    }

    web::block(move || {
        EMAIL_RATE_LIMIT.remaining_requests(&client_info.addr, &mut redis.get()?)?;
        send_verification_email(&smtp, &ident.user)
    })
    .await?;

    Ok(HttpResponse::NoContent().body(""))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(verify_email).service(resend_verification);
}
