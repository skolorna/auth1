use crate::{db::postgres::PgConn, diesel::QueryDsl, errors::AppError, models::Keypair};
use chrono::Utc;
use diesel::prelude::*;
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::{
    errors::AppResult,
    models::{keypair::KeypairId, user::UserId},
};

pub const JWT_ALG: Algorithm = Algorithm::RS256;
pub const TTL_SECS: i64 = 600;

fn map_jwt_err(err: jsonwebtoken::errors::Error) -> AppError {
    jwt_err_opaque!(err, AppError::InvalidAccessToken)
}

pub fn decode(pg: &PgConn, token: &str) -> AppResult<AccessTokenClaims> {
    use crate::schema::keypairs::{columns, table};

    let header = jsonwebtoken::decode_header(token).map_err(map_jwt_err)?;

    let kid: KeypairId = header
        .kid
        .ok_or(AppError::InvalidAccessToken)?
        .parse()
        .map_err(|_| AppError::InvalidAccessToken)?;

    dbg!(kid);

    let key: Vec<u8> = table
        .select(columns::public)
        .filter(Keypair::valid_for_verifying())
        .find(kid)
        .first(pg)?;

    // The proper encoding can be obtained by RsaKey::public_key_to_der_pkcs1.
    let key = DecodingKey::from_rsa_der(&key);

    let validation = Validation::new(JWT_ALG);
    let decoded =
        jsonwebtoken::decode::<AccessTokenClaims>(token, &key, &validation).map_err(map_jwt_err)?;

    dbg!("decoded");

    Ok(decoded.claims)
}

pub fn sign(keypair: &Keypair, sub: UserId) -> AppResult<String> {
    let header = Header {
        typ: Some("JWT".into()),
        alg: JWT_ALG,
        cty: None,
        jku: None,
        kid: Some(keypair.id.to_string()),
        x5u: None,
        x5t: None,
    };

    let claims = AccessTokenClaims {
        sub,
        exp: Utc::now().timestamp() + TTL_SECS,
    };

    let token = jsonwebtoken::encode(&header, &claims, &keypair.jwt_enc())
        .map_err(|e| AppError::InternalError { cause: e.into() })?;

    Ok(token)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject of the token (the user id).
    pub sub: UserId,

    /// Expiration timestamp of the token (UNIX timestamp).
    pub exp: i64,
}
