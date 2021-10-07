use actix_web::{
    http::header::{CacheControl, CacheDirective},
    web, HttpResponse,
};
use diesel::prelude::*;

use crate::{
    db::postgres::PgPool,
    errors::{AppError, AppResult},
    identity::Identity,
    models::{
        session::{SessionId, SessionInfo},
        Session,
    },
};

async fn list_sessions(pool: web::Data<PgPool>, ident: Identity) -> AppResult<HttpResponse> {
    use crate::schema::sessions::columns;
    let conn = pool.get()?;

    let res: Vec<SessionInfo> = web::block(move || {
        Session::belonging_to(&ident.user)
            .select((columns::id, columns::sub, columns::started, columns::exp))
            .filter(Session::not_expired())
            .load(&conn)
    })
    .await?;

    Ok(HttpResponse::Ok()
        .set(CacheControl(vec![CacheDirective::Private]))
        .json(res))
}

async fn clear_sessions(pool: web::Data<PgPool>, ident: Identity) -> AppResult<HttpResponse> {
    let conn = pool.get()?;

    let num_deleted =
        web::block(move || diesel::delete(Session::belonging_to(&ident.user)).execute(&conn))
            .await?;

    Ok(HttpResponse::Ok().body(format!("deleted {} sessions", num_deleted)))
}

async fn delete_session(
    pool: web::Data<PgPool>,
    ident: Identity,
    web::Path(id): web::Path<SessionId>,
) -> AppResult<HttpResponse> {
    let conn = pool.get()?;

    let num_deleted = web::block(move || {
        diesel::delete(Session::belonging_to(&ident.user).filter(Session::with_id(id)))
            .execute(&conn)
    })
    .await?;

    if num_deleted < 1 {
        Err(AppError::SessionNotFound)
    } else {
        Ok(HttpResponse::NoContent().body(""))
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("")
            .route(web::get().to(list_sessions))
            .route(web::delete().to(clear_sessions)),
    )
    .service(web::resource("/{id}").route(web::delete().to(delete_session)));
}
