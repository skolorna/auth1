use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;
use tracing::error;

use crate::jwt::InvalidTokenReason;

#[derive(Debug, Error)]
pub enum Error {
    #[error("an internal error occurred")]
    Internal,
    #[error("database error")]
    Sqlx(sqlx::Error),
    #[error("email error")]
    Lettre(lettre::error::Error),
    #[error("email error")]
    Smtp(lettre::transport::smtp::Error),
    #[error("email already in use")]
    EmailInUse,
    #[error("invalid refresh token: {0}")]
    InvalidRefreshToken(InvalidTokenReason),
    #[error("invalid access token: {0}")]
    InvalidAccessToken(InvalidTokenReason),
    #[error("invalid oob token: {0}")]
    InvalidOobToken(InvalidTokenReason),
    #[error("account not found")]
    AccountNotFound,
    #[error("forbidden")]
    Forbidden,
    #[error("oidc error")]
    OIDC,
}

impl Error {
    pub const fn status_code(&self) -> StatusCode {
        match self {
            Self::Internal | Self::Sqlx(_) | Self::Lettre(_) | Self::Smtp(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::EmailInUse => StatusCode::CONFLICT,
            Self::InvalidRefreshToken(_) => StatusCode::UNAUTHORIZED,
            Self::InvalidAccessToken(_) => StatusCode::UNAUTHORIZED,
            Self::InvalidOobToken(_) => StatusCode::BAD_REQUEST,
            Self::AccountNotFound => StatusCode::BAD_REQUEST,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::OIDC => StatusCode::BAD_REQUEST,
        }
    }

    pub const fn internal() -> Self {
        Self::Internal
    }

    pub const fn email_not_in_use() -> Self {
        Self::AccountNotFound
    }

    pub const fn email_in_use() -> Self {
        Self::EmailInUse
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.status_code(), self.to_string()).into_response()
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        error!("openssl error: {e}");
        Self::Internal
    }
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        error!("sqlx error: {e}");
        Error::Sqlx(e)
    }
}

impl From<lettre::error::Error> for Error {
    fn from(e: lettre::error::Error) -> Self {
        error!("lettre error: {e}");
        Error::Lettre(e)
    }
}

impl From<lettre::transport::smtp::Error> for Error {
    fn from(e: lettre::transport::smtp::Error) -> Self {
        error!("smtp error: {e}");
        Error::Smtp(e)
    }
}

impl From<lettre::transport::file::Error> for Error {
    fn from(e: lettre::transport::file::Error) -> Self {
        error!("file email transport error: {e}");
        Error::Internal
    }
}

impl From<handlebars::RenderError> for Error {
    fn from(e: handlebars::RenderError) -> Self {
        error!("handlebars render error: {e}");
        Error::Internal
    }
}

type OIDCTokenError =
    openidconnect::core::CoreRequestTokenError<openidconnect::reqwest::AsyncHttpClientError>;

impl From<OIDCTokenError> for Error {
    fn from(value: OIDCTokenError) -> Self {
        error!("oidc token error: {value}");
        Self::OIDC
    }
}

type OIDCUserInfoError = openidconnect::UserInfoError<openidconnect::reqwest::AsyncHttpClientError>;

impl From<OIDCUserInfoError> for Error {
    fn from(value: OIDCUserInfoError) -> Self {
        error!("oidc user info error: {value}");
        Self::OIDC
    }
}
