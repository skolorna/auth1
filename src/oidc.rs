use std::sync::Arc;

use openidconnect::core::{CoreClient, CoreIdTokenClaims};
use serde::{Deserialize, Serialize};
use sqlx::{Connection, PgConnection};
use tokio::sync::RwLock;
use tracing::error;

use crate::{
    http::{self, Error, Result},
    jwt::{access_token, refresh_token},
    util::{create_user, CreatedUser},
    x509::Authority,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Google,
}

pub struct OIDC {
    pub google: CoreClient,
}

impl OIDC {
    pub fn get_client(&self, provider: &Provider) -> &CoreClient {
        match provider {
            Provider::Google => &self.google,
        }
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
        return Err(Error::OIDC);
    }

    let email = claims.email().ok_or(Error::OIDC)?.as_str();

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
