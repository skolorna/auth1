pub mod sessions;

use actix_web::{
    get,
    http::header::{CacheControl, CacheDirective},
    patch, post, web, HttpResponse,
};

use crate::{
    client_info::ClientInfo,
    db::{postgres::PgPool, redis::RedisPool},
    email::{send_verification_email, SmtpConnection},
    identity::Identity,
    models::{
        user::{CreateUser, UpdateUser},
        User,
    },
    rate_limit::{RateLimit, SlidingWindow},
    result::{Error, Result},
};

#[post("")]
async fn create_user(
    pg: web::Data<PgPool>,
    redis: web::Data<RedisPool>,
    smtp: web::Data<SmtpConnection>,
    web::Json(data): web::Json<CreateUser>,
    client_info: ClientInfo,
) -> Result<HttpResponse> {
    const RATE_LIMIT: SlidingWindow = SlidingWindow::new("create_user", 3600, 100);

    web::block(move || RATE_LIMIT.remaining_requests(&client_info.to_string(), &mut redis.get()?))
        .await?;

    let pg = pg.get()?;
    let created_user = web::block::<_, _, Error>(move || {
        let created_user = User::create(&pg, &data)?;
        send_verification_email(smtp.as_ref(), &created_user)?;
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

#[patch("/@me")]
async fn patch_me(
    ident: Identity,
    web::Json(info): web::Json<UpdateUser>,
    pool: web::Data<PgPool>,
    smtp: web::Data<SmtpConnection>,
) -> Result<HttpResponse> {
    let result = web::block(move || ident.user.update(&smtp, &pool.get()?, info)).await?;

    Ok(HttpResponse::Ok().json(result))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(create_user)
        .service(get_me)
        .service(patch_me)
        .service(web::scope("/@me/sessions").configure(sessions::configure));
}
