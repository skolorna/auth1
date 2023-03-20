use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    headers::{authorization::Bearer, Authorization},
    http::request::Parts,
    response::{IntoResponse, Response},
    TypedHeader,
};
use sqlx::PgPool;
use tracing::debug;

use crate::{http::AppState, jwt::access_token};

pub struct Identity {
    pub claims: access_token::Claims,
}

#[async_trait]
impl FromRequestParts<AppState> for Identity {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let TypedHeader(authorization) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(IntoResponse::into_response)?;

        let State(db) = State::<PgPool>::from_request_parts(parts, state)
            .await
            .unwrap();

        let claims = access_token::verify(authorization.token(), &db)
            .await
            .map_err(IntoResponse::into_response)?;

        debug!(uid=%claims.sub, "authenticated user by access token");

        Ok(Identity { claims })
    }
}
