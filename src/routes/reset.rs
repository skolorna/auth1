use actix_web::{web, HttpResponse};

use crate::errors::AppResult;

async fn handle_password_reset() -> AppResult<HttpResponse> {
    Ok(HttpResponse::Ok().body("Password reset"))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
  cfg.service(web::resource("").route(web::post()).to(handle_password_reset));
}
