use actix_web::{
    http::header::{CacheControl, CacheDirective},
    web, HttpResponse,
};

use crate::{
    db::postgres::PgPool, email::Emails, errors::AppResult, identity::Identity,
    models::user::UpdateUser,
};

async fn get_me(ident: Identity) -> AppResult<HttpResponse> {
    Ok(HttpResponse::Ok()
        .set(CacheControl(vec![CacheDirective::Private]))
        .json(ident.user))
}

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
    cfg.service(
        web::resource("/@me")
            .route(web::get().to(get_me))
            .route(web::patch().to(patch_me)),
    );
}
