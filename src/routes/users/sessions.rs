use actix_web::{
    delete, get,
    http::header::{CacheControl, CacheDirective},
    web, HttpResponse,
};
use diesel::prelude::*;

use crate::{
    db::postgres::PgPool,
    identity::Identity,
    models::{
        session::{SessionId, SessionInfo},
        Session,
    },
    result::{Error, Result},
};

#[get("")]
async fn list_sessions(pool: web::Data<PgPool>, ident: Identity) -> Result<HttpResponse> {
    use crate::schema::sessions::columns;
    let conn = pool.get()?;
    let res = web::block(move || {
        Session::belonging_to(&ident.user)
            .select((columns::id, columns::sub, columns::started, columns::exp))
            .filter(Session::not_expired())
            .load::<SessionInfo>(&conn)
    })
    .await?;

    Ok(HttpResponse::Ok()
        .set(CacheControl(vec![CacheDirective::Private]))
        .json(res))
}

#[delete("")]
async fn clear_sessions(pool: web::Data<PgPool>, ident: Identity) -> Result<HttpResponse> {
    let conn = pool.get()?;
    let num_deleted =
        web::block(move || diesel::delete(Session::belonging_to(&ident.user)).execute(&conn))
            .await?;

    Ok(HttpResponse::Ok().body(format!("deleted {} keys", num_deleted)))
}

#[delete("/{id}")]
async fn delete_session(
    pool: web::Data<PgPool>,
    ident: Identity,
    web::Path(id): web::Path<SessionId>,
) -> Result<HttpResponse> {
    let conn = pool.get()?;
    let num_deleted = web::block(move || {
        diesel::delete(Session::belonging_to(&ident.user).filter(Session::with_id(id)))
            .execute(&conn)
    })
    .await?;

    if num_deleted < 1 {
        Err(Error::KeyNotFound)
    } else {
        Ok(HttpResponse::NoContent().body(""))
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(list_sessions)
        .service(clear_sessions)
        .service(delete_session);
}
