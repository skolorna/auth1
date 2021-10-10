pub mod access_token;
pub mod refresh_token;

use std::fmt::Display;

use crate::{
    db::postgres::PgConn, diesel::QueryDsl, errors::AppError, models::User, types::EmailAddress,
};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::errors::AppResult;

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
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}
