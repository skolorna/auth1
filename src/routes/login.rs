use actix_web::{post, web, HttpResponse};
use serde::Deserialize;

use crate::models::Session;
use crate::result::Result;
use crate::{login_with_password, DbPool};

#[derive(Debug, Deserialize)]
struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[post("")]
async fn handle_login(
    pool: web::Data<DbPool>,
    credentials: web::Json<LoginRequest>,
) -> Result<HttpResponse> {
    let conn = pool.get()?;
    let res = web::block(move || {
        let user = login_with_password(&conn, &credentials.email, &credentials.password)?;
        Session::create(&conn, user.id)
    })
    .await?;

    Ok(HttpResponse::Ok().json(res))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(handle_login);
}
