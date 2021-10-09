use actix_web::http::header::{CacheControl, CacheDirective};
use actix_web::{web, HttpResponse};
use diesel::prelude::*;
use jsonwebkey::{JsonWebKey, Key, KeyUse, PublicExponent, RsaPublic};
use openssl::rsa::Rsa;
use serde::Serialize;

use crate::db::postgres::PgPool;
use crate::errors::{AppError, AppResult};
use crate::models::keypair::KeypairId;
use crate::models::Keypair;
use crate::schema::keypairs::{columns, table};

async fn list_keys(pg: web::Data<PgPool>) -> AppResult<HttpResponse> {
    let pg = pg.get()?;

    let data: Vec<(KeypairId, Vec<u8>)> = table
        .select((columns::id, columns::public))
        .filter(Keypair::valid_for_verifying())
        .load(&pg)?;

    let res: Result<Vec<JsonWebKey>, openssl::error::ErrorStack> = data
        .into_iter()
        .map(|(id, der)| {
            let rsa = Rsa::public_key_from_der(&der)?;

            let mut jwk = JsonWebKey::new(Key::RSA {
                public: RsaPublic {
                    e: PublicExponent,
                    n: rsa.n().to_vec().into(),
                },
                private: None,
            });

            jwk.key_id = Some(id.to_string());
            jwk.key_use = Some(KeyUse::Signing);

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
        ]))
        .json(res))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("").route(web::get().to(list_keys)));
}
