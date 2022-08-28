use axum::{response::IntoResponse, Extension, Json};
use futures::{StreamExt, TryStreamExt};
use openssl::x509::X509;
use serde::Serialize;
use sqlx::{postgres::PgRow, FromRow, Row};
use uuid::Uuid;

use crate::jwk::{Jwk, X509Ext};

use super::{ApiContext, Error, Result};

#[derive(Debug, Serialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

pub(super) async fn get(ctx: Extension<ApiContext>) -> Result<impl IntoResponse> {
    let keys =
        sqlx::query_as::<_, (Uuid, Vec<u8>)>("SELECT id, x509 FROM certificates WHERE naf > NOW()")
            .fetch(&ctx.db)
            .map_err(Error::from)
            .map(|res| {
                res.and_then(|(id, x509)| {
                    let mut jwk = X509::from_der(&x509)?.to_jwk()?;
                    jwk.key_id = Some(id.to_string());
                    Ok::<Jwk, Error>(jwk)
                })
            })
            .try_collect::<Vec<_>>()
            .await?;

    Ok(Json(JwkSet { keys }))
}
