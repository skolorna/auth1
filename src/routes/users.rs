use actix_web::{get, post, web, HttpResponse};
use diesel::RunQueryDsl;

use crate::{
    email::{send_email_confirmation, SmtpConnSpec},
    identity::Identity,
    models::User,
    result::Result,
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
    let created_user = web::block(move || crate::create_user(&conn, data.0)).await?;

    send_email_confirmation(smtp.as_ref(), created_user.email.clone())?;

    Ok(HttpResponse::Created().json(created_user))
}

#[get("/@me")]
async fn get_me(ident: Identity) -> HttpResponse {
    HttpResponse::Ok().json(ident.user)
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(list_users).service(create_user).service(get_me);
}
