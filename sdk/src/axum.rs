use axum::{
    async_trait,
    extract::{rejection::TypedHeaderRejection, FromRequestParts},
    headers::{authorization::Bearer, Authorization},
    response::{IntoResponse, Response},
    Extension, TypedHeader,
};
use http::request::Parts;

use crate::{Identity, KeyStore};

#[derive(Debug, thiserror::Error)]
pub enum IdentityRejection {
    #[error("{0}")]
    InvalidHeader(TypedHeaderRejection),
    #[error("{0}")]
    Auth1(crate::Error),
}

impl IntoResponse for IdentityRejection {
    fn into_response(self) -> Response {
        match self {
            IdentityRejection::InvalidHeader(e) => e.into_response(),
            IdentityRejection::Auth1(e) => (e.status_code(), e.to_string()).into_response(),
        }
    }
}

impl From<crate::Error> for IdentityRejection {
    fn from(e: crate::Error) -> Self {
        IdentityRejection::Auth1(e)
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for Identity
where
    S: Send + Sync,
{
    type Rejection = IdentityRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(authorization) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(IdentityRejection::InvalidHeader)?;

        let Extension(store) = Extension::<KeyStore>::from_request_parts(parts, state)
            .await
            .expect("missing KeyStore extension in request");

        let claims = store.verify(authorization.token()).await?;

        Ok(Identity { claims })
    }
}
