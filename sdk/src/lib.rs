use std::{sync::Arc, time::Duration};

use cache_control::CacheControl;
use jsonwebtoken::Validation;
use jwk::Jwk;
use reqwest::{IntoUrl, Url};
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, time::Instant};
use uuid::Uuid;

pub const JWKS_URL: &str = "https://api-staging.skolorna.com/v0/auth/keys";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("jwk error: {0}")]
    Jwk(#[from] jwk::Error),

    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("key not found")]
    KeyNotFound,

    #[error("malformed token")]
    MalformedToken,

    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: Uuid,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Clone)]
pub struct KeyStore {
    jwks_url: Url,
    cache: Arc<RwLock<Option<(Instant, jwk::Set)>>>,
}

impl KeyStore {
    pub fn new(jwks_url: impl IntoUrl) -> Result<Self, Error> {
        Ok(Self {
            jwks_url: jwks_url.into_url()?,
            cache: Arc::new(RwLock::new(None)),
        })
    }

    pub async fn jwks(&self) -> Result<jwk::Set> {
        let reader = self.cache.read().await;

        if let Some((exp, cached)) = reader.as_ref() {
            if exp.elapsed().is_zero() {
                return Ok(cached.clone());
            }
        }

        drop(reader);

        let mut writer = self.cache.write().await;

        let res = reqwest::get(self.jwks_url.clone()).await?;

        let headers = res.headers();

        let cc = headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let cc = CacheControl::from_value(cc);
        let max_age = cc.and_then(|cc| cc.max_age).unwrap_or_default();

        let age = headers
            .get("age")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or_default();
        let age = Duration::from_secs(age);

        let exp = Instant::now() + max_age - age;

        let jwks: jwk::Set = res.json().await?;

        *writer = Some((exp, jwks.clone()));

        Ok(jwks)
    }

    pub async fn get_key(&self, kid: &str) -> Result<Jwk> {
        let jwk::Set { keys } = self.jwks().await?;

        keys.iter()
            .find(|k| k.key_id.as_deref() == Some(kid))
            .map(Clone::clone)
            .ok_or(Error::KeyNotFound)
    }

    pub async fn verify(&self, token: &str) -> Result<AccessTokenClaims> {
        let header = jsonwebtoken::decode_header(token)?;
        let kid = header.kid.ok_or(Error::MalformedToken)?;

        let jwk = self.get_key(&kid).await?;
        let alg = jwk.algorithm.ok_or(Error::MalformedToken)?;
        let key = jwk.key.to_jwt_key()?;

        let data =
            jsonwebtoken::decode::<AccessTokenClaims>(token, &key, &Validation::new(alg.into()))?;

        Ok(data.claims)
    }
}
