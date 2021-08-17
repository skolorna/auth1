use actix_web::{delete, get, web, HttpResponse};

use diesel::prelude::*;

use crate::{
    identity::Identity,
    models::{
        session::{SessionId, SessionInfo},
        Session,
    },
    result::{Error, Result},
    DbPool,
};

#[get("")]
async fn list_sessions(pool: web::Data<DbPool>, ident: Identity) -> Result<HttpResponse> {
    use crate::schema::sessions::columns;
    let conn = pool.get()?;
    let res = web::block(move || {
        Session::belonging_to(&ident.user)
            .select((columns::id, columns::sub, columns::started, columns::exp))
            .load::<SessionInfo>(&conn)
    })
    .await?;
    // let keys: Vec<Key> = web::block(move || crate::schema::keys::table.load(&conn)).await?;
    // let res: Vec<String> = keys.into_iter().map(|k| String::from_utf8_lossy(&k.private_key).to_string()).collect();

    Ok(HttpResponse::Ok().json(res))
}

#[delete("")]
async fn clear_sessions(pool: web::Data<DbPool>, ident: Identity) -> Result<HttpResponse> {
    let conn = pool.get()?;
    let num_deleted =
        web::block(move || diesel::delete(Session::belonging_to(&ident.user)).execute(&conn))
            .await?;

    Ok(HttpResponse::Ok().body(format!("deleted {} keys", num_deleted)))
}

#[delete("/{id}")]
async fn delete_session(
    pool: web::Data<DbPool>,
    ident: Identity,
    web::Path(id): web::Path<SessionId>,
) -> Result<HttpResponse> {
    use crate::schema::sessions::columns;
    let conn = pool.get()?;
    let num_deleted = web::block(move || {
        diesel::delete(Session::belonging_to(&ident.user).filter(columns::id.eq(id))).execute(&conn)
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
