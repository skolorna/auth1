pub mod sessions;

use actix_web::{
    get,
    http::header::{CacheControl, CacheDirective},
    post, web, HttpResponse,
};

use crate::{
    db::{postgres::PgPool, redis::RedisPool},
    email::{send_welcome_email, SmtpConnSpec},
    identity::Identity,
    models::{user::CreateUser, User},
    rate_limit::{RateLimited, SimpleRateLimit},
    remote_ip::RemoteIp,
    result::{Error, Result},
};

#[post("")]
async fn create_user(
    pg: web::Data<PgPool>,
    redis: web::Data<RedisPool>,
    smtp: web::Data<SmtpConnSpec>,
    data: web::Json<CreateUser>,
    remote_ip: RemoteIp,
) -> Result<HttpResponse> {
    const RATE_LIMIT: SimpleRateLimit = SimpleRateLimit::new("create_user", 60, 10);

    let remaining_requests = RATE_LIMIT.remaining_requests(&remote_ip.into(), &mut redis.get()?)?;

    dbg!(remaining_requests);

    let pg = pg.get()?;
    let created_user = web::block::<_, _, Error>(move || {
        let created_user = User::create(&pg, data.0)?;
        send_welcome_email(&pg, smtp.as_ref(), created_user.email.clone())?;
        Ok(created_user)
    })
    .await?;

    Ok(HttpResponse::Created().json(created_user))
}

#[get("/@me")]
async fn get_me(ident: Identity) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok()
        .set(CacheControl(vec![CacheDirective::Private]))
        .json(ident.user))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(create_user)
        .service(get_me)
        .service(web::scope("/@me/sessions").configure(sessions::configure));
}
