use crate::{
    db::postgres::PgConn,
    errors::{AppError, AppResult},
    models::user::UserId,
};

use chrono::Utc;
use diesel::prelude::*;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

pub const JWT_ALG: Algorithm = Algorithm::HS256;
pub const TTL_SECS: i64 = 90 * 86400;
pub const SECRET_SIZE: usize = 64;

fn map_jwt_err(err: jsonwebtoken::errors::Error) -> AppError {
    jwt_err_opaque!(err, AppError::InvalidRefreshToken)
}

pub fn decode(pg: &PgConn, token: &str) -> AppResult<RefreshTokenClaims> {
    use crate::schema::users::{columns, table};

    let validation = Validation::new(JWT_ALG);

    let RefreshTokenClaims { sub, .. } =
        jsonwebtoken::dangerous_insecure_decode_with_validation(token, &validation)
            .map_err(map_jwt_err)?
            .claims;

    let secret = table
        .select(columns::jwt_secret)
        .find(sub)
        .first::<Vec<u8>>(pg)?;

    let key = DecodingKey::from_secret(&secret);

    let claims = jsonwebtoken::decode::<RefreshTokenClaims>(token, &key, &validation)
        .map_err(map_jwt_err)?
        .claims;

    Ok(claims)
}

pub fn sign(sub: UserId, secret: &[u8]) -> AppResult<String> {
    let key = EncodingKey::from_secret(secret);

    let header = Header::new(JWT_ALG);

    let claims = RefreshTokenClaims {
        sub,
        exp: Utc::now().timestamp() + TTL_SECS,
    };

    jsonwebtoken::encode(&header, &claims, &key).map_err(map_jwt_err)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: UserId,
    pub exp: i64,
}
