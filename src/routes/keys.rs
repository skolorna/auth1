use actix_web::http::header::{self, CacheControl, CacheDirective};
use actix_web::{get, web, HttpResponse};

use crate::models::session::SessionId;
use crate::models::Session;
use crate::result::Result;
use crate::DbPool;

#[get("/{id}.pub")]
async fn get_pubkey(
    pool: web::Data<DbPool>,
    web::Path(id): web::Path<SessionId>,
) -> Result<HttpResponse> {
    let conn = pool.get()?;
    let (pem, _) = Session::get_pubkey(&conn, id)?;
    let pem = String::from_utf8(pem).expect("invalid utf8 in pubkey");

    // Is it really PEM? 🤔
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));

    Ok(HttpResponse::Ok()
        .set(CacheControl(vec![CacheDirective::MaxAge(30 * 86400)]))
        .set_header(header::CONTENT_TYPE, "application/x-pem-file")
        .body(pem))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(get_pubkey);
}
