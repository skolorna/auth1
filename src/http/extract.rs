use axum::{
    async_trait,
    extract::FromRequestParts,
    headers::{authorization::Bearer, Authorization},
    http::request::Parts,
    response::{IntoResponse, Response},
    Extension, TypedHeader,
};
use tracing::debug;

use crate::{http::ApiContext, jwt::access_token};

pub struct Identity {
    pub claims: access_token::Claims,
}

#[async_trait]
impl<S> FromRequestParts<S> for Identity
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let TypedHeader(authorization) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(IntoResponse::into_response)?;

        let Extension(ctx): Extension<ApiContext> = Extension::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;

        let claims = access_token::verify(authorization.token(), &ctx.db)
            .await
            .map_err(IntoResponse::into_response)?;

        debug!(uid=%claims.sub, "authenticated user by access token");

        Ok(Identity { claims })
    }
}
