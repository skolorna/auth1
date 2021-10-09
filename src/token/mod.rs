use std::fmt::Display;

use crate::{
    db::postgres::PgConn,
    diesel::QueryDsl,
    errors::AppError,
    models::{Keypair, User},
    types::EmailAddress,
};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::{
    errors::AppResult,
    models::{keypair::KeypairId, user::UserId},
};

macro_rules! jwt_err_opaque {
    ($err:expr, $out:expr) => {{
        use ::jsonwebtoken::errors::ErrorKind::*;
        use ::tracing::warn;

        warn!("{}", $err);

        match $err.kind() {
            InvalidToken | InvalidSignature | ExpiredSignature | InvalidIssuer
            | InvalidAudience | InvalidSubject | ImmatureSignature | InvalidAlgorithm
            | Base64(_) | Json(_) | Utf8(_) => $out,
            InvalidEcdsaKey | InvalidRsaKey | InvalidAlgorithmName | InvalidKeyFormat
            | Crypto(_) | __Nonexhaustive => AppError::InternalError { cause: $err.into() },
        }
    }};
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessToken(String);

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject of the token (the user id).
    pub sub: UserId,

    /// Expiration timestamp of the token (UNIX timestamp).
    pub exp: i64,
}

impl AccessToken {
    pub const JWT_ALG: Algorithm = Algorithm::RS256;

    pub fn ttl() -> Duration {
        Duration::days(30)
    }

    pub fn new<S: ToString>(s: S) -> Self {
        Self(s.to_string())
    }

    /// Verify and decode a JWT.
    pub fn verify_and_decode(&self, conn: &PgConn) -> AppResult<AccessTokenClaims> {
        use crate::schema::keypairs::{columns, table};

        let header = jsonwebtoken::decode_header(&self.0).map_err(Self::jwt_error_opaque)?;

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
            .first(conn)?;
        let key = DecodingKey::from_rsa_der(&key);

        dbg!(&key);

        let validation = Validation::new(Self::JWT_ALG);
        let decoded = jsonwebtoken::decode::<AccessTokenClaims>(&self.0, &key, &validation)
            .map_err(Self::jwt_error_opaque)?;

        dbg!("decoded");

        Ok(decoded.claims)
    }

    pub fn sign(pg: &PgConn, sub: UserId) -> AppResult<Self> {
        let keypair = Keypair::for_signing(pg)?;

        let now = Utc::now();
        let exp = now + Self::ttl();

        let header = Header {
            typ: Some("JWT".into()),
            alg: Self::JWT_ALG,
            cty: None,
            jku: None,
            kid: Some(keypair.id.to_string()),
            x5u: None,
            x5t: None,
        };

        let claims = AccessTokenClaims {
            sub,
            exp: exp.timestamp(),
        };

        let token = jsonwebtoken::encode(&header, &claims, &keypair.jwt_enc())
            .map_err(|e| AppError::InternalError { cause: e.into() })?;

        Ok(Self::new(token))
    }

    fn jwt_error_opaque(err: jsonwebtoken::errors::Error) -> AppError {
        jwt_err_opaque!(err, AppError::InvalidAccessToken)
    }
}

/// Token used for verifying (only email addresses for now).
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationToken(String);

impl VerificationToken {
    const JWT_ALG: Algorithm = Algorithm::HS256;

    pub fn new(s: impl ToString) -> Self {
        Self(s.to_string())
    }

    pub fn generate(user: &User) -> AppResult<Self> {
        let key = EncodingKey::from_secret(user.hash.as_bytes());
        let exp = Utc::now() + Duration::hours(24);
        let header = Header::new(Self::JWT_ALG);
        let claims = VerificationTokenClaims {
            email: user.email.clone(),
            exp: exp.timestamp(),
        };

        let token = jsonwebtoken::encode(&header, &claims, &key).map_err(Self::jwt_error_opaque)?;

        Ok(Self::new(token))
    }

    pub fn verify(&self, conn: &PgConn) -> AppResult<()> {
        use crate::schema::users::{columns, table};

        let data = jsonwebtoken::dangerous_insecure_decode::<VerificationTokenClaims>(&self.0)
            .map_err(Self::jwt_error_opaque)?;

        let (hash, already_verified): (String, bool) = table
            .select((columns::hash, columns::verified))
            .filter(columns::email.eq(data.claims.email))
            .first(conn)?;

        if already_verified {
            return Err(AppError::InvalidVerificationToken);
        }

        let key = DecodingKey::from_secret(hash.as_bytes());
        let data = jsonwebtoken::decode::<VerificationTokenClaims>(
            &self.0,
            &key,
            &Validation::new(Self::JWT_ALG),
        )
        .map_err(Self::jwt_error_opaque)?;

        diesel::update(table.filter(columns::email.eq(data.claims.email)))
            .set(columns::verified.eq(true))
            .execute(conn)?;

        Ok(())
    }

    fn jwt_error_opaque(err: jsonwebtoken::errors::Error) -> AppError {
        jwt_err_opaque!(err, AppError::InvalidVerificationToken)
    }
}

impl Display for VerificationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "{}", self.0);
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationTokenClaims {
    pub exp: i64,
    pub email: EmailAddress,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: AccessToken,
}
