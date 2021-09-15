pub mod sessions;

use actix_web::{
    get,
    http::header::{CacheControl, CacheDirective},
    post, web, HttpResponse,
};

use crate::{
    db::postgres::PgPool,
    email::{send_welcome_email, SmtpConnSpec},
    identity::Identity,
    models::{user::CreateUser, User},
    result::{Error, Result},
};

#[post("")]
async fn create_user(
    pool: web::Data<PgPool>,
    smtp: web::Data<SmtpConnSpec>,
    data: web::Json<CreateUser>,
) -> Result<HttpResponse> {
    let conn = pool.get()?;
    let created_user = web::block::<_, _, Error>(move || {
        let created_user = User::create(&conn, data.0)?;
        send_welcome_email(&conn, smtp.as_ref(), created_user.email.clone())?;
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
