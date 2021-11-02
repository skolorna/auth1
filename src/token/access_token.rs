use crate::{
    db::postgres::PgConn, diesel::QueryDsl, errors::AppError, models::Certificate, types::DbX509,
};
use chrono::Utc;
use diesel::prelude::*;
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::{
    errors::AppResult,
    models::{certificate::CertificateId, user::UserId},
};

pub const JWT_ALG: Algorithm = Algorithm::RS256;
pub const TTL_SECS: i64 = 600;

fn map_jwt_err(err: jsonwebtoken::errors::Error) -> AppError {
    jwt_err_opaque!(err, AppError::InvalidAccessToken)
}

pub fn decode(pg: &PgConn, token: &str) -> AppResult<Claims> {
    use crate::schema::certificates::{columns, table};

    let header = jsonwebtoken::decode_header(token).map_err(map_jwt_err)?;

    let kid: CertificateId = header
        .kid
        .ok_or(AppError::InvalidAccessToken)?
        .parse()
        .map_err(|_| AppError::InvalidAccessToken)?;

    let x509: DbX509 = table
        .select(columns::x509)
        .filter(Certificate::valid_for_verifying())
        .find(kid)
        .first(pg)?;
    let der = x509.0.public_key()?.rsa()?.public_key_to_der_pkcs1()?;
    let key = DecodingKey::from_rsa_der(&der);

    let validation = Validation::new(JWT_ALG);
    let decoded = jsonwebtoken::decode::<Claims>(token, &key, &validation).map_err(map_jwt_err)?;

    Ok(decoded.claims)
}

pub fn sign(cert: &Certificate, sub: UserId) -> AppResult<String> {
    let header = Header {
        typ: Some("JWT".into()),
        alg: JWT_ALG,
        cty: None,
        jku: None,
        kid: Some(cert.id.to_string()),
        x5u: None,
        x5t: None,
    };

    let claims = Claims {
        sub,
        exp: Utc::now().timestamp() + TTL_SECS,
    };

    let token = jsonwebtoken::encode(&header, &claims, &cert.jwt_enc())
        .map_err(|e| AppError::InternalError { cause: e.into() })?;

    Ok(token)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject of the token (the user id).
    pub sub: UserId,

    /// Expiration timestamp of the token (UNIX timestamp).
    pub exp: i64,
}
