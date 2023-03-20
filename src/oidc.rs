use std::sync::Arc;

use http_cache_reqwest::{Cache, CacheMode, HttpCache, MokaManager};
use once_cell::sync::OnceCell;
use openidconnect::{
    core::{CoreClient, CoreIdTokenClaims, CoreProviderMetadata},
    ClientId, ClientSecret, HttpRequest, HttpResponse, IssuerUrl, RedirectUrl,
};
use reqwest_middleware::ClientWithMiddleware;
use serde::{Deserialize, Serialize};
use sqlx::{Connection, PgConnection};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::error;

use crate::{
    http::{self, Result},
    jwt::{access_token, refresh_token},
    util::{create_user, CreatedUser},
    x509::Authority,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Google,
}

pub struct ProviderInfo {
    pub issuer_url: IssuerUrl,
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
    pub redirect_url: RedirectUrl,
}

pub type RequestError = reqwest_middleware::Error;

pub type DiscoveryError = openidconnect::DiscoveryError<RequestError>;

pub type RequestTokenError = openidconnect::core::CoreRequestTokenError<RequestError>;

pub type UserInfoError = openidconnect::UserInfoError<RequestError>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("discovery failed: {0}")]
    Discovery(#[from] DiscoveryError),
    #[error("failed to request token: {0}")]
    RequestToken(#[from] RequestTokenError),
    #[error("user info failure: {0}")]
    UserInfo(#[from] UserInfoError),
    #[error("claims verification error: {0}")]
    ClaimsVerification(#[from] openidconnect::ClaimsVerificationError),
}

pub struct Oidc {
    pub google: ProviderInfo,
}

static CLIENT: OnceCell<ClientWithMiddleware> = OnceCell::new();

pub async fn http_client(req: HttpRequest) -> core::result::Result<HttpResponse, RequestError> {
    let client = CLIENT.get_or_init(|| {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        reqwest_middleware::ClientBuilder::new(client)
            .with(Cache(HttpCache {
                mode: CacheMode::Default,
                manager: MokaManager::default(),
                options: None,
            }))
            .build()
    });

    let HttpRequest {
        url,
        method,
        headers,
        body,
    } = req;

    let res = client
        .clone()
        .request(method, url)
        .body(body)
        .headers(headers)
        .send()
        .await?;

    Ok(openidconnect::HttpResponse {
        status_code: res.status(),
        headers: res.headers().to_owned(),
        body: res.bytes().await?.to_vec(),
    })
}

impl Oidc {
    fn info(&self, provider: &Provider) -> &ProviderInfo {
        match provider {
            Provider::Google => &self.google,
        }
    }

    async fn metadata(&self, provider: &Provider) -> Result<CoreProviderMetadata> {
        let issuer_url = self.info(provider).issuer_url.clone();

        Ok(CoreProviderMetadata::discover_async(issuer_url, http_client).await?)
    }

    pub async fn get_client(&self, provider: &Provider) -> Result<CoreClient> {
        let metadata = self.metadata(provider).await?;
        let info = self.info(provider);

        Ok(CoreClient::from_provider_metadata(
            metadata,
            info.client_id.clone(),
            Some(info.client_secret.clone()),
        )
        .set_redirect_uri(info.redirect_url.clone()))
    }
}

pub async fn create_or_login_oidc_user(
    claims: CoreIdTokenClaims,
    ca: &Arc<RwLock<Authority>>,
    db: &mut PgConnection,
) -> Result<http::TokenResponse> {
    let mut tx = db.begin().await?;

    if claims.email_verified() != Some(true) {
        error!("oidc user email not verified");
        return Err(http::Error::OidcInvalidEmail);
    }

    let email = claims
        .email()
        .ok_or(http::Error::OidcInvalidEmail)?
        .as_str();

    let (id, jwt_secret) = if let Some(record) =
        sqlx::query!("SELECT id, jwt_secret FROM users WHERE email = $1", email)
            .fetch_optional(&mut tx)
            .await?
    {
        (record.id, record.jwt_secret)
    } else {
        let name = claims.name().and_then(|n| n.get(None)).map(|n| n.as_str());
        let CreatedUser { id, jwt_secret, .. } = create_user(email, name, &mut tx).await?;
        (id, jwt_secret.to_vec())
    };

    let access_token = access_token::sign(id, ca, &mut tx).await?;

    sqlx::query!("UPDATE users SET last_login = NOW() WHERE id = $1", id)
        .execute(&mut tx)
        .await?;

    tx.commit().await?;

    Ok(http::TokenResponse {
        access_token,
        refresh_token: Some(refresh_token::sign(id, &jwt_secret)?),
    })
}
