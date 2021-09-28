use actix_web::{post, web, HttpResponse};
use serde::Deserialize;

use crate::client_info::ClientInfo;
use crate::db::postgres::PgPool;
use crate::db::redis::RedisPool;
use crate::email::{Emails, EMAIL_RATE_LIMIT};
use crate::errors::{AppResult, Error};
use crate::identity::Identity;

use crate::rate_limit::RateLimit;
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
    redis: web::Data<RedisPool>,
    emails: web::Data<Emails>,
    client_info: ClientInfo,
    ident: Identity,
) -> AppResult<HttpResponse> {
    if ident.user.verified {
        return Err(Error::AlreadyVerified);
    }

    web::block(move || {
        EMAIL_RATE_LIMIT.remaining_requests(&client_info.addr, &mut redis.get()?)?;
        let token = VerificationToken::generate(&ident.user)?;
        emails.send_user_confirmation(&ident.user, token)
    })
    .await?;

    Ok(HttpResponse::NoContent().body(""))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(verify_email).service(resend_verification);
}
