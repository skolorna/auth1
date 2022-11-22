use std::{convert::TryFrom, fmt::Display};

use jsonwebtoken::{DecodingKey, TokenData, Validation};
use serde::de::DeserializeOwned;
use tracing::error;

use crate::http::{Error, Result};

pub(crate) trait JwtResultExt<T> {
    fn map_token_err(self, map_err: impl FnOnce(InvalidTokenReason) -> Error) -> Result<T>;
}

#[derive(Debug, Clone, Copy)]
pub enum InvalidTokenReason {
    Malformed,
    Expired,
    Immature,
    Bad,
}

impl InvalidTokenReason {
    pub const fn key_not_found() -> Self {
        Self::Bad
    }
}

impl Display for InvalidTokenReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvalidTokenReason::Malformed => write!(f, "malformed"),
            InvalidTokenReason::Expired => write!(f, "expired signature"),
            InvalidTokenReason::Immature => write!(f, "immature signature"),
            InvalidTokenReason::Bad => write!(f, "bad signature"),
        }
    }
}

impl TryFrom<&jsonwebtoken::errors::Error> for InvalidTokenReason {
    type Error = ();

    fn try_from(e: &jsonwebtoken::errors::Error) -> Result<Self, Self::Error> {
        use jsonwebtoken::errors::ErrorKind;

        match e.kind() {
            ErrorKind::InvalidToken
            | ErrorKind::MissingRequiredClaim(_)
            | ErrorKind::Base64(_)
            | ErrorKind::Json(_)
            | ErrorKind::Utf8(_) => Ok(Self::Malformed),
            ErrorKind::ImmatureSignature => Ok(Self::Immature),
            ErrorKind::ExpiredSignature => Ok(Self::Expired),
            ErrorKind::InvalidAlgorithmName
            | ErrorKind::InvalidIssuer
            | ErrorKind::InvalidAudience
            | ErrorKind::InvalidAlgorithm
            | ErrorKind::InvalidSubject
            | ErrorKind::InvalidSignature => Ok(Self::Bad),
            _ => Err(()),
        }
    }
}

impl<T> JwtResultExt<T> for jsonwebtoken::errors::Result<T> {
    fn map_token_err(self, map_err: impl FnOnce(InvalidTokenReason) -> Error) -> Result<T> {
        self.map_err(|e| match InvalidTokenReason::try_from(&e) {
            Ok(r) => map_err(r),
            Err(()) => {
                error!("jwt error: {e}");
                Error::Internal
            }
        })
    }
}

pub mod refresh_token {
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
    use rand::{thread_rng, Rng};
    use serde::{Deserialize, Serialize};
    use sqlx::PgExecutor;
    use time::{Duration, OffsetDateTime};
    use tracing::instrument;
    use uuid::Uuid;

    use crate::http::{Error, Result};

    use super::{decode_insecure, JwtResultExt};

    pub const TTL: Duration = Duration::days(90);
    pub const SECRET_LEN: usize = 64;
    pub const ALG: Algorithm = Algorithm::HS256;

    pub fn gen_secret() -> [u8; SECRET_LEN] {
        let mut buf = [0; SECRET_LEN];
        thread_rng().fill(&mut buf);
        buf
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Claims {
        pub sub: Uuid,
        pub iat: i64,
        pub exp: i64,
    }

    #[instrument(skip(secret))]
    pub fn sign(sub: Uuid, secret: &[u8]) -> Result<String> {
        let header = Header {
            typ: Some("JWT".into()),
            alg: ALG,
            ..Header::default()
        };

        let key = EncodingKey::from_secret(secret);
        let iat = OffsetDateTime::now_utc();
        let exp = iat + TTL;
        let claims = Claims {
            sub,
            iat: iat.unix_timestamp(),
            exp: exp.unix_timestamp(),
        };

        jsonwebtoken::encode(&header, &claims, &key).map_token_err(|_| unreachable!())
    }

    #[instrument(skip(db))]
    pub async fn verify(token: &str, db: impl PgExecutor<'_>) -> Result<Claims> {
        let claims = decode_insecure::<Claims>(token)
            .map_token_err(Error::InvalidRefreshToken)?
            .claims;

        let (secret,) =
            sqlx::query_as::<_, (Vec<u8>,)>("SELECT jwt_secret FROM users WHERE id = $1")
                .bind(claims.sub)
                .fetch_optional(db)
                .await?
                .ok_or_else(Error::email_not_in_use)?;

        let key = DecodingKey::from_secret(&secret);
        let data = jsonwebtoken::decode(token, &key, &Validation::new(ALG))
            .map_token_err(Error::InvalidRefreshToken)?;

        Ok(data.claims)
    }
}

pub mod access_token {
    use std::sync::Arc;

    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
    use openssl::x509::X509;
    use sqlx::{PgConnection, PgExecutor};
    use time::{Duration, OffsetDateTime};
    use tokio::sync::RwLock;
    use tracing::instrument;
    use uuid::Uuid;

    use crate::{
        http::{Error, Result},
        x509,
    };

    use super::{InvalidTokenReason, JwtResultExt};

    pub const ALG: Algorithm = Algorithm::ES256;
    pub const TTL: Duration = Duration::minutes(10);

    pub type Claims = auth1_sdk::AccessTokenClaims;

    #[instrument(skip(ca, db))]
    pub async fn sign(
        sub: Uuid,
        ca: &Arc<RwLock<x509::Authority>>,
        db: &mut PgConnection,
    ) -> Result<String> {
        let (kid, key) = ca.read().await.get_sig_key(db).await?;
        let key = EncodingKey::from_ec_pem(&key).map_token_err(|_| unreachable!())?;

        let header = Header {
            typ: Some("JWT".into()),
            alg: ALG,
            kid: Some(kid.to_string()),
            ..Header::default()
        };

        let iat = OffsetDateTime::now_utc().unix_timestamp();
        let claims = Claims {
            sub,
            iat,
            exp: iat + TTL.whole_seconds(),
        };

        jsonwebtoken::encode(&header, &claims, &key).map_token_err(|_| unreachable!())
    }

    #[instrument(skip(db))]
    pub async fn verify(token: &str, db: impl PgExecutor<'_>) -> Result<Claims> {
        let header = jsonwebtoken::decode_header(token).map_token_err(Error::InvalidAccessToken)?;
        let kid: Uuid = header
            .kid
            .ok_or(Error::InvalidAccessToken(InvalidTokenReason::Malformed))?
            .parse()
            .map_err(|_| Error::InvalidAccessToken(InvalidTokenReason::Malformed))?;

        let record = sqlx::query!("SELECT x509 FROM certificates WHERE id = $1", kid)
            .fetch_optional(db)
            .await?
            .ok_or(Error::InvalidAccessToken(
                InvalidTokenReason::key_not_found(),
            ))?;
        let x509 = X509::from_der(&record.x509)?;
        let key = x509.public_key()?.public_key_to_pem()?;
        let key = DecodingKey::from_ec_pem(&key).map_token_err(|_| unreachable!())?;

        let data = jsonwebtoken::decode::<Claims>(token, &key, &Validation::new(ALG))
            .map_token_err(Error::InvalidAccessToken)?;

        Ok(data.claims)
    }
}

pub(crate) fn decode_insecure<T: DeserializeOwned>(
    token: &str,
) -> jsonwebtoken::errors::Result<TokenData<T>> {
    let mut validation = Validation::default();
    validation.insecure_disable_signature_validation();
    jsonwebtoken::decode(token, &DecodingKey::from_secret(&[]), &validation)
}
