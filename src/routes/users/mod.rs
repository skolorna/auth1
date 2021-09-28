pub mod sessions;

use actix_web::{
    get,
    http::header::{CacheControl, CacheDirective},
    patch, web, HttpResponse,
};

use crate::{
    db::postgres::PgPool, email::SmtpConnection, identity::Identity, models::user::UpdateUser,
    result::Result,
};

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
    cfg.service(get_me)
        .service(patch_me)
        .service(web::scope("/@me/sessions").configure(sessions::configure));
}
