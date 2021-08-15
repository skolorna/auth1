use actix_web::{get, post, web, HttpResponse};
use diesel::RunQueryDsl;
use serde::Deserialize;
use validator::Validate;

use crate::{CreateUser, DbPool, Identity, email::{send_email_confirmation, SmtpConnSpec}, models::User, result::Result, sign_in_with_password};

#[get("/users")]
async fn list_users(pool: web::Data<DbPool>) -> Result<HttpResponse> {
    use crate::schema::users::dsl::*;

    let conn = pool.get()?;
    let res = web::block(move || users.load::<User>(&conn)).await?;

    Ok(HttpResponse::Ok().json(res))
}

#[post("/users")]
async fn create_user(
    pool: web::Data<DbPool>,
    smtp: web::Data<SmtpConnSpec>,
    data: web::Json<CreateUser>,
) -> Result<HttpResponse> {
    let conn = pool.get()?;
    let created_user = web::block(move || crate::create_user(&conn, data.0)).await?;

    send_email_confirmation(smtp.as_ref(), created_user.email.clone());

    Ok(HttpResponse::Ok().body(format!("{:?}", created_user)))
}

#[get("/users/@me")]
async fn get_me(
    identity: Identity,
) -> HttpResponse {
    HttpResponse::Ok().json(identity.user)
}

#[derive(Debug, Validate, Deserialize)]
struct PasswordAuthCredentials {
    #[validate(email)]
    pub email: String,

    pub password: String,
}

#[post("/session")]
async fn create_session(
    pool: web::Data<DbPool>,
    credentials: web::Json<PasswordAuthCredentials>,
) -> Result<HttpResponse> {
    let conn = pool.get()?;
    let user =
        web::block(move || sign_in_with_password(&conn, &credentials.email, &credentials.password))
            .await?;

    Ok(HttpResponse::Ok().json(user))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(create_session)
        .service(list_users)
        .service(create_user).service(get_me);
}
