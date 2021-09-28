use actix_web::http::header::{self, CacheControl, CacheDirective};
use actix_web::{get, web, HttpResponse};

use crate::db::postgres::PgPool;
use crate::errors::AppResult;
use crate::models::session::SessionId;
use crate::models::Session;
use crate::util::http_date_fmt;

#[get("/{id}")]
async fn get_pubkey(
    pool: web::Data<PgPool>,
    web::Path(id): web::Path<SessionId>,
) -> AppResult<HttpResponse> {
    let conn = pool.get()?;
    let (pem, _sub, exp) = Session::get_pubkey(&conn, id)?;
    let pem = String::from_utf8(pem).expect("invalid utf8 in pubkey");

    // Is it really PEM? 🤔
    debug_assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));

    Ok(HttpResponse::Ok()
        .set(CacheControl(vec![
            CacheDirective::Public,
            CacheDirective::MustRevalidate,
            CacheDirective::NoTransform,
        ]))
        .set_header(header::EXPIRES, http_date_fmt(exp))
        .set_header(header::CONTENT_TYPE, "application/x-pem-file")
        .body(pem))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(get_pubkey);
}
