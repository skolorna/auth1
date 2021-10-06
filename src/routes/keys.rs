use actix_web::http::header::{self, CacheControl, CacheDirective};
use actix_web::{web, HttpResponse};

use crate::db::postgres::PgPool;
use crate::errors::{AppError, AppResult};
use crate::models::session::SessionId;
use crate::models::Session;
use crate::util::http_date_fmt;

async fn get_pubkey(
    pool: web::Data<PgPool>,
    web::Path(id): web::Path<SessionId>,
) -> AppResult<HttpResponse> {
    let conn = pool.get()?;
    let data = Session::get_pubkey(&conn, id)?.ok_or(AppError::SessionNotFound)?;
    let pem = String::from_utf8(data.pubkey).expect("invalid utf8 in pubkey");

    // Is it really PEM? 🤔
    debug_assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));

    Ok(HttpResponse::Ok()
        .set(CacheControl(vec![
            CacheDirective::Public,
            CacheDirective::MustRevalidate,
            CacheDirective::NoTransform,
        ]))
        .set_header(header::EXPIRES, http_date_fmt(data.exp))
        .set_header(header::CONTENT_TYPE, "application/x-pem-file")
        .body(pem))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/{id}").route(web::get().to(get_pubkey)));
}
