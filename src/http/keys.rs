use std::iter;

use axum::{response::IntoResponse, routing::get, Extension, Json, Router};
use futures::{StreamExt, TryStreamExt};
use openssl::x509::X509;
use serde::Serialize;

use uuid::Uuid;

use crate::{
    jwk::{Jwk, X509Ext},
    x509,
};

use super::{ApiContext, Error, Result};

#[derive(Debug, Serialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

async fn list(ctx: Extension<ApiContext>) -> Result<impl IntoResponse> {
    let keys = sqlx::query_as::<_, (Uuid, Vec<u8>, x509::Chain)>(
        "SELECT id, x509, chain FROM certificates WHERE naf > NOW()",
    )
    .fetch(&ctx.db)
    .map_err(Error::from)
    .map(|res| {
        res.and_then(|(id, der, chain)| {
            let mut jwk = X509::from_der(&der)?.to_jwk()?;
            jwk.key_id = Some(id.to_string());
            jwk.x5.cert_chain = Some(
                iter::once(Ok(der))
                    .chain(chain.iter().map(|c| c.to_der()))
                    .collect::<Result<Vec<_>, _>>()?,
            );
            Ok::<Jwk, Error>(jwk)
        })
    })
    .try_collect::<Vec<_>>()
    .await?;

    Ok((
        [("cache-control", "max-age=15, must-revalidate")],
        Json(JwkSet { keys }),
    ))
}

pub fn routes() -> Router {
    Router::new().route("/", get(list))
}
