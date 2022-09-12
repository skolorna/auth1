use axum::{
    async_trait,
    extract::{rejection::TypedHeaderRejection, FromRequest, RequestParts},
    headers::{authorization::Bearer, Authorization},
    response::{IntoResponse, Response},
    Extension, TypedHeader,
};

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
impl<B> FromRequest<B> for Identity
where
    B: Send,
{
    type Rejection = IdentityRejection;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let TypedHeader(authorization) = TypedHeader::<Authorization<Bearer>>::from_request(req)
            .await
            .map_err(IdentityRejection::InvalidHeader)?;

        let Extension(store) = Extension::<KeyStore>::from_request(req)
            .await
            .expect("missing KeyStore extension in request");

        let claims = store.verify(authorization.token()).await?;

        Ok(Identity { claims })
    }
}
