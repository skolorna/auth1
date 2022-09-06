use axum::{
    async_trait,
    extract::{FromRequest, RequestParts},
    headers::{authorization::Bearer, Authorization},
    response::{IntoResponse, Response},
    Extension, TypedHeader,
};
use sentry::configure_scope;
use tracing::debug;

use crate::{http::ApiContext, jwt::access_token};

pub struct Identity {
    pub claims: access_token::Claims,
}

#[async_trait]
impl<B> FromRequest<B> for Identity
where
    B: Send,
{
    type Rejection = Response;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let TypedHeader(authorization) = TypedHeader::<Authorization<Bearer>>::from_request(req)
            .await
            .map_err(IntoResponse::into_response)?;

        let Extension(ctx): Extension<ApiContext> = Extension::from_request(req)
            .await
            .map_err(IntoResponse::into_response)?;

        let claims = access_token::verify(authorization.token(), &ctx.db)
            .await
            .map_err(IntoResponse::into_response)?;

        debug!(uid=%claims.sub, "authenticated user by access token");

        configure_scope(|scope| {
            scope.set_user(Some(sentry::User {
                id: Some(claims.sub.to_string()),
                ..Default::default()
            }));
        });

        Ok(Identity { claims })
    }
}
