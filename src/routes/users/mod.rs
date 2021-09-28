pub mod sessions;

use actix_web::{
    get,
    http::header::{CacheControl, CacheDirective},
    patch, web, HttpResponse,
};

use crate::{
    db::postgres::PgPool, email::Emails, errors::AppResult, identity::Identity,
    models::user::UpdateUser,
};

#[get("/@me")]
async fn get_me(ident: Identity) -> AppResult<HttpResponse> {
    Ok(HttpResponse::Ok()
        .set(CacheControl(vec![CacheDirective::Private]))
        .json(ident.user))
}

#[patch("/@me")]
async fn patch_me(
    ident: Identity,
    web::Json(info): web::Json<UpdateUser>,
    pool: web::Data<PgPool>,
    emails: web::Data<Emails>,
) -> AppResult<HttpResponse> {
    let result = web::block(move || ident.user.update(emails.as_ref(), &pool.get()?, info)).await?;

    Ok(HttpResponse::Ok().json(result))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(get_me)
        .service(patch_me)
        .service(web::scope("/@me/sessions").configure(sessions::configure));
}
