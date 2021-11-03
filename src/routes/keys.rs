use std::iter;

use actix_web::http::header::{CacheControl, CacheDirective};
use actix_web::{web, HttpResponse};
use diesel::prelude::*;

use serde::Serialize;

use crate::db::postgres::PgPool;
use crate::errors::{AppError, AppResult};
use crate::models::certificate::CertificateId;
use crate::models::Certificate;
use crate::schema::certificates::{columns, table};
use crate::types::jwk::x5::{JwkX5, X509Params};
use crate::types::jwk::{Algorithm, JsonWebKey, KeyUse};
use crate::types::DbX509;
use crate::x509::chain::X509Chain;

async fn list_keys(pg: web::Data<PgPool>) -> AppResult<HttpResponse> {
    let pg = pg.get()?;

    let data: Vec<(CertificateId, DbX509, X509Chain)> = table
        .select((columns::id, columns::x509, columns::chain))
        .filter(Certificate::valid_for_verifying())
        .load(&pg)?;

    let res: Result<Vec<JsonWebKey>, openssl::error::ErrorStack> = data
        .into_iter()
        .map(|(id, x509, rest)| {
            let key = x509.0.public_key()?.rsa()?.as_ref().into();
            let sha1_thumbprint = x509.0.sha1_thumbprint()?.into();
            let sha256_thumbprint = x509.0.sha256_thumbprint()?.into();

            let mut chain = Vec::with_capacity(1 + rest.len());

            for c in iter::once(x509.into()).chain(rest.certs) {
                let der = c.to_der()?;
                chain.push(der.into());
            }

            let jwk = JsonWebKey {
                algorithm: Some(Algorithm::RS256),
                key,
                key_use: Some(KeyUse::Signing),
                key_id: Some(id.to_string()),
                x5: X509Params {
                    url: None,
                    cert_chain: Some(chain),
                    thumbprint: Some(sha1_thumbprint),
                    thumbprint_sha256: Some(sha256_thumbprint),
                },
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
