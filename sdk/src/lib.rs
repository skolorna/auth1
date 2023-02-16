use std::{str::FromStr, sync::Arc, time::Duration};

use cache_control::CacheControl;
use jsonwebtoken::Validation;
use jwk::Jwk;
use opentelemetry::propagation::Injector;
use reqwest::{
    header::{HeaderMap, HeaderName},
    Client, IntoUrl, Url,
};
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, time::Instant};
#[cfg(feature = "tracing")]
use tracing::debug;
use uuid::Uuid;

#[cfg(feature = "actix")]
pub mod actix;

#[cfg(feature = "axum")]
pub mod axum;

mod error;

pub use error::*;

pub const JWKS_URL: &str = "https://api.skolorna.com/v0/auth/keys";
pub const TIMEOUT: Duration = Duration::from_secs(5);

type Result<T, E = Error> = core::result::Result<T, E>;

pub struct Identity {
    pub claims: AccessTokenClaims,
}

impl Identity {
    pub fn id(&self) -> Uuid {
        self.claims.sub
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: Uuid,
    pub iat: i64,
    pub exp: i64,
}

struct CacheEntry {
    expires: Instant,
    inner: jwk::Set,
}

impl CacheEntry {
    const fn new(expires: Instant, value: jwk::Set) -> Self {
        Self {
            expires,
            inner: value,
        }
    }

    fn is_fresh(&self) -> bool {
        self.expires.elapsed().is_zero()
    }
}

/// A caching JWT key store.
#[derive(Clone)]
pub struct KeyStore {
    jwks_url: Url,
    cache: Arc<RwLock<Option<CacheEntry>>>,
    client: Client,
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new(JWKS_URL).unwrap()
    }
}

impl KeyStore {
    pub fn new(jwks_url: impl IntoUrl) -> Result<Self, Error> {
        Ok(Self {
            jwks_url: jwks_url.into_url()?,
            cache: Arc::new(RwLock::new(None)),
            client: Client::builder().timeout(TIMEOUT).build()?,
        })
    }

    pub async fn jwks(&self) -> Result<jwk::Set> {
        let reader = self.cache.read().await;

        if let Some(entry) = reader.as_ref() {
            if entry.is_fresh() {
                return Ok(entry.inner.clone());
            }
        }

        drop(reader);

        let mut writer = self.cache.write().await;

        let res = self
            .client
            .get(self.jwks_url.clone())
            .headers(inject_context())
            .send()
            .await?;

        let headers = res.headers();

        let cc = headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let cc = CacheControl::from_value(cc);
        let max_age = cc.and_then(|cc| cc.max_age).unwrap_or_default();

        let age = Duration::from_secs(
            headers
                .get("age")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok())
                .unwrap_or_default(),
        );

        let exp = Instant::now() + max_age - age;

        let jwks: jwk::Set = res.json().await?;

        *writer = Some(CacheEntry::new(exp, jwks.clone()));

        Ok(jwks)
    }

    pub async fn get_key(&self, kid: &str) -> Result<Option<Jwk>> {
        let jwk::Set { keys } = self.jwks().await?;

        Ok(keys
            .iter()
            .find(|k| k.key_id.as_deref() == Some(kid))
            .map(Clone::clone))
    }

    pub async fn verify(&self, token: &str) -> Result<AccessTokenClaims> {
        let header = jsonwebtoken::decode_header(token)?;
        let kid = header.kid.ok_or(Error::InvalidToken)?;

        let jwk = self.get_key(&kid).await?.ok_or(Error::InvalidToken)?;
        let alg = jwk.algorithm.ok_or(Error::InvalidToken)?;
        let key = jwk.key.to_jwt_key();

        let claims =
            jsonwebtoken::decode::<AccessTokenClaims>(token, &key, &Validation::new(alg.into()))?
                .claims;

        #[cfg(feature = "tracing")]
        debug!(uid=%claims.sub, "verified token");

        Ok(claims)
    }
}

fn inject_context() -> HeaderMap {
    struct HeaderInjector<'a>(&'a mut HeaderMap);

    impl Injector for HeaderInjector<'_> {
        fn set(&mut self, key: &str, value: String) {
            if let Ok(key) = HeaderName::from_str(key) {
                if let Ok(value) = value.parse() {
                    self.0.insert(key, value);
                }
            }
        }
    }

    let mut headers = HeaderMap::new();

    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject(&mut HeaderInjector(&mut headers));
    });

    headers
}

#[cfg(test)]
mod tests {
    use crate::KeyStore;

    #[tokio::test]
    async fn jwks() {
        let ks = KeyStore::default();
        let set = ks.jwks().await.unwrap();

        assert!(!set.keys.is_empty());
    }
}
