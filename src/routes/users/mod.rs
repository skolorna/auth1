pub mod sessions;

use actix_web::{
    get,
    http::header::{CacheControl, CacheDirective},
    post, web, HttpResponse,
};
use diesel::prelude::*;

use crate::{
    email::{send_welcome_email, SmtpConnSpec},
    identity::Identity,
    models::User,
    result::{Error, Result},
    CreateUser, DbPool,
};

#[deprecated(note = "do not deploy")]
#[get("")]
async fn list_users(pool: web::Data<DbPool>) -> Result<HttpResponse> {
    use crate::schema::users::dsl::*;

    let conn = pool.get()?;
    let res = web::block(move || users.load::<User>(&conn)).await?;

    Ok(HttpResponse::Ok().json(res))
}

#[post("")]
async fn create_user(
    pool: web::Data<DbPool>,
    smtp: web::Data<SmtpConnSpec>,
    data: web::Json<CreateUser>,
) -> Result<HttpResponse> {
    let conn = pool.get()?;
    let created_user = web::block::<_, _, Error>(move || {
        let created_user = crate::create_user(&conn, data.0)?;
        send_welcome_email(&conn, smtp.as_ref(), created_user.email.clone())?;
        Ok(created_user)
    })
    .await?;

    Ok(HttpResponse::Created()
        .set(CacheControl(vec![CacheDirective::NoCache]))
        .json(created_user))
}

#[get("/@me")]
async fn get_me(ident: Identity) -> HttpResponse {
    HttpResponse::Ok().json(ident.user)
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(list_users)
        .service(create_user)
        .service(get_me)
        // TODO: Add some fancy extractor that can automatically infer @me
        // as the user currently logged in.
        .service(web::scope("/@me/sessions").configure(sessions::configure));
}
