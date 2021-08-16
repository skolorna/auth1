mod keys;
mod users;

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

// TODO: Check if the database if healthy
#[get("/health")]
async fn get_health() -> HttpResponse {
    HttpResponse::Ok()
        .set(CacheControl(vec![CacheDirective::NoCache]))
        .json(HealthResponse {
            status: "ok".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        })
}

// TODO: MAKE SURE CACHE-CONTROL IS PROPERLY SET FOR ALL ROUTES
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(get_health)
        .service(web::scope("/users").configure(users::configure))
        .service(web::scope("/keys").configure(keys::configure));
}
