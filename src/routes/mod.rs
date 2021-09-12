pub mod keys;
pub mod login;
pub mod refresh;
pub mod users;
pub mod verify;

use actix_web::{
    get,
    http::header::{CacheControl, CacheDirective},
    web, HttpResponse,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

// TODO: Check if the database if healthy, too.
#[get("/health")]
async fn get_health() -> HttpResponse {
    return HttpResponse::Ok()
        .set(CacheControl(vec![CacheDirective::NoStore]))
        .json(HealthResponse {
            status: "ok".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        });
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(get_health)
        .service(web::scope("/users").configure(users::configure))
        .service(web::scope("/login").configure(login::configure))
        .service(web::scope("/keys").configure(keys::configure))
        .service(web::scope("/verify").configure(verify::configure))
        .service(web::scope("/refresh").configure(refresh::configure));
}
