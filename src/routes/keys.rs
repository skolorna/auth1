use actix_web::{
    delete, get,
    http::header::{self, CacheControl, CacheDirective},
    post, web, HttpResponse,
};

use diesel::{BelongingToDsl, ExpressionMethods, QueryDsl, RunQueryDsl};

use crate::{
    identity::Identity,
    login_with_password,
    models::{
        key::{KeyId, KeyInfo},
        Key,
    },
    result::{Error, Result},
    DbPool,
};
use serde::Deserialize;

#[get("")]
async fn list_keys(pool: web::Data<DbPool>, ident: Identity) -> Result<HttpResponse> {
    use crate::schema::keys::columns;
    let conn = pool.get()?;
    let res = web::block(move || {
        Key::belonging_to(&ident.user)
            .select((columns::id, columns::sub, columns::iat))
            .load::<KeyInfo>(&conn)
    })
    .await?;
    // let keys: Vec<Key> = web::block(move || crate::schema::keys::table.load(&conn)).await?;
    // let res: Vec<String> = keys.into_iter().map(|k| String::from_utf8_lossy(&k.private_key).to_string()).collect();

    Ok(HttpResponse::Ok().json(res))
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[post("")]
async fn create_key(
    pool: web::Data<DbPool>,
    credentials: web::Json<LoginRequest>,
) -> Result<HttpResponse> {
    let conn = pool.get()?;
    let res = web::block(move || {
        let user = login_with_password(&conn, &credentials.email, &credentials.password)?;
        Key::create(&conn, user.id)
    })
    .await?;

    Ok(HttpResponse::Created()
        .set(CacheControl(vec![CacheDirective::NoCache]))
        .json(res))
}

#[delete("")]
async fn delete_all_keys(pool: web::Data<DbPool>, ident: Identity) -> Result<HttpResponse> {
    let conn = pool.get()?;
    let num_deleted =
        web::block(move || diesel::delete(Key::belonging_to(&ident.user)).execute(&conn)).await?;

    Ok(HttpResponse::Ok().body(format!("deleted {} keys", num_deleted)))
}

#[delete("/{id}")]
async fn delete_key(
    pool: web::Data<DbPool>,
    ident: Identity,
    web::Path(id): web::Path<KeyId>,
) -> Result<HttpResponse> {
    use crate::schema::keys::columns;
    let conn = pool.get()?;
    let num_deleted = web::block(move || {
        diesel::delete(Key::belonging_to(&ident.user).filter(columns::id.eq(id))).execute(&conn)
    })
    .await?;

    if num_deleted < 1 {
        Err(Error::KeyNotFound)
    } else {
        Ok(HttpResponse::NoContent().body(""))
    }
}

#[get("/{id}.pub")]
async fn get_public_key(
    pool: web::Data<DbPool>,
    web::Path(id): web::Path<KeyId>,
) -> Result<HttpResponse> {
    let conn = pool.get()?;
    let pem = Key::get_public(&conn, id)?;
    let pem = String::from_utf8(pem).expect("invalid utf8 in pubkey");

    // Is it really PEM? 🤔
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));

    Ok(HttpResponse::Ok()
        .set(CacheControl(vec![CacheDirective::MaxAge(30 * 86400)]))
        .set_header(header::CONTENT_TYPE, "application/x-pem-file")
        .body(pem))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(list_keys)
        .service(create_key)
        .service(delete_all_keys)
        .service(delete_key)
        .service(get_public_key);
}
