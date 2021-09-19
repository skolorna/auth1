//! Everything tokens: access tokens, refresh tokens and even verification tokens!
pub mod refresh_token;

use std::fmt::Display;

use crate::{db::postgres::PgConn, diesel::QueryDsl, models::User, types::EmailAddress};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::{
    models::{session::SessionId, user::UserId, Session},
    result::{Error, Result},
};

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

    pub fn new<S: ToString>(s: S) -> Self {
        Self(s.to_string())
    }

    /// Verify and decode a JWT with relatively descriptive errors. **The errors should be made more opaque before
    /// arriving at the user.**
    pub fn verify_and_decode(&self, conn: &PgConn) -> Result<AccessTokenClaims> {
        let header = jsonwebtoken::decode_header(&self.0)?;
        let kid: SessionId = header
            .kid
            .ok_or(Error::InvalidCredentials)?
            .parse()
            .map_err(|_| Error::InvalidCredentials)?;
        let (key, key_owner, _exp) = Session::get_pubkey(conn, kid)?;
        let key = DecodingKey::from_rsa_pem(&key)?;
        let validation = Validation::new(Self::JWT_ALG);
        let decoded = jsonwebtoken::decode::<AccessTokenClaims>(&self.0, &key, &validation)?;

        if key_owner != decoded.claims.sub {
            // Something fishy is going on.
            return Err(Error::InvalidCredentials);
        }

        Ok(decoded.claims)
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

    pub fn generate(user: &User) -> Result<Self> {
        let key = EncodingKey::from_secret(user.hash.as_bytes());
        let exp = Utc::now() + Duration::hours(24);
        let header = Header::new(Self::JWT_ALG);
        let claims = VerificationTokenClaims {
            email: user.email.to_owned(),
            exp: exp.timestamp(),
        };
        let token = jsonwebtoken::encode(&header, &claims, &key)?;

        Ok(Self::new(token))
    }

    pub fn verify(&self, conn: &PgConn) -> Result<()> {
        use crate::schema::users::{columns, table};

        let data = jsonwebtoken::dangerous_insecure_decode::<VerificationTokenClaims>(&self.0)?;
        let (hash, already_verified): (String, bool) = table
            .select((columns::hash, columns::verified))
            .filter(columns::email.eq(data.claims.email))
            .first(conn)?;

        if already_verified {
            return Err(Error::InvalidCredentials);
        }

        let key = DecodingKey::from_secret(hash.as_bytes());
        let data = jsonwebtoken::decode::<VerificationTokenClaims>(
            &self.0,
            &key,
            &Validation::new(Self::JWT_ALG),
        )?;

        diesel::update(table.filter(columns::email.eq(data.claims.email)))
            .set(columns::verified.eq(true))
            .execute(conn)?;

        Ok(())
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
