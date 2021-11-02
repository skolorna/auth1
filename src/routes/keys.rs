use actix_web::http::header::{CacheControl, CacheDirective};
use actix_web::{web, HttpResponse};
use diesel::prelude::*;

use serde::Serialize;

use crate::db::postgres::PgPool;
use crate::errors::{AppError, AppResult};
use crate::models::certificate::CertificateId;
use crate::models::Certificate;
use crate::schema::certificates::{columns, table};
use crate::types::jwk::{Algorithm, JsonWebKey, KeyUse};
use crate::types::DbX509;

async fn list_keys(pg: web::Data<PgPool>) -> AppResult<HttpResponse> {
    let pg = pg.get()?;

    let data: Vec<(CertificateId, DbX509)> = table
        .select((columns::id, columns::x509))
        .filter(Certificate::valid_for_verifying())
        .load(&pg)?;

    let res: Result<Vec<JsonWebKey>, openssl::error::ErrorStack> = data
        .into_iter()
        .map(|(id, x509)| {
            let jwk = JsonWebKey {
                algorithm: Some(Algorithm::RS256),
                key: x509.jwk_key()?,
                key_use: Some(KeyUse::Signing),
                key_id: Some(id.to_string()),
                x5: x509.jwk_x5()?,
            };

            Ok(jwk)
        })
        .collect();

    let jwks = res.map_err(|e| AppError::InternalError { cause: e.into() })?;

    #[derive(Debug, Serialize)]
    struct JsonWebKeySet {
        keys: Vec<JsonWebKey>,
    }

    let res = JsonWebKeySet { keys: jwks };

    Ok(HttpResponse::Ok()
        .set(CacheControl(vec![
            CacheDirective::Public,
            CacheDirective::MaxAge(15),
            CacheDirective::MustRevalidate,
        ]))
        .json(res))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("").route(web::get().to(list_keys)));
}
