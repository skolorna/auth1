pub mod keys;
pub mod login;
pub mod register;
pub mod token;
pub mod users;
pub mod verify;

use actix_web::{
    http::header::{CacheControl, CacheDirective},
    web, HttpResponse,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

async fn get_health() -> HttpResponse {
    return HttpResponse::Ok()
        .set(CacheControl(vec![CacheDirective::NoStore]))
        .json(HealthResponse {
            status: "ok".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        });
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/health").route(web::get().to(get_health)))
        .service(web::scope("/users").configure(users::configure))
        .service(web::scope("/login").configure(login::configure))
        .service(web::scope("/jwks.json").configure(keys::configure))
        .service(web::scope("/verify").configure(verify::configure))
        .service(web::scope("/register").configure(register::configure))
        .service(web::scope("/token").configure(token::configure));
}

#[cfg(test)]
mod tests {
    use actix_web::http::StatusCode;

    use super::*;

    #[actix_rt::test]
    async fn health() {
        let res = get_health().await;
        assert_eq!(res.status(), StatusCode::OK);
    }
}
