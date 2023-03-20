use std::iter;

use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
use futures::TryStreamExt;
use jwk::{Jwk, X509Ext};
use openssl::x509::X509;
use time::Duration;
use uuid::Uuid;

use crate::x509;

use super::{AppState, Error, Result};

const JWKS_CACHE_TTL: Duration = Duration::seconds(15);

async fn list(state: State<AppState>) -> Result<impl IntoResponse> {
    let mut conn = state.db.acquire().await?;

    state
        .ca
        .read()
        .await
        .sig_key_foresight(&mut conn, JWKS_CACHE_TTL * 2)
        .await?;

    let keys = sqlx::query_as::<_, (Uuid, Vec<u8>, x509::Chain)>(
        "SELECT id, x509, chain FROM certificates WHERE naf > NOW()",
    )
    .fetch(&mut conn)
    .map_err(Error::from)
    .and_then(|(id, der, chain)| async move {
        let mut jwk = X509::from_der(&der)?.to_jwk()?;
        jwk.key_id = Some(id.to_string());
        jwk.x5.cert_chain = Some(
            iter::once(Ok(der))
                .chain(chain.iter().map(|c| c.to_der()))
                .collect::<Result<Vec<_>, _>>()?,
        );
        Ok::<Jwk, Error>(jwk)
    })
    .try_collect::<Vec<_>>()
    .await?;

    Ok((
        [(
            "cache-control",
            format!(
                "max-age={}, must-revalidate",
                JWKS_CACHE_TTL.whole_seconds()
            ),
        )],
        Json(jwk::Set { keys }),
    ))
}

pub fn routes() -> Router<AppState> {
    Router::<_>::new().route("/", get(list))
}
