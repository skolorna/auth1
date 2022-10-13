use std::fmt::Display;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tracing::error;

use crate::jwt::InvalidTokenReason;

#[derive(Debug)]
pub enum Error {
    Internal,
    Sqlx(sqlx::Error),
    Lettre(lettre::error::Error),
    Smtp(lettre::transport::smtp::Error),
    EmailInUse,
    PasswordRequired,
    InvalidRefreshToken(InvalidTokenReason),
    InvalidAccessToken(InvalidTokenReason),
    InvalidEmailToken(InvalidTokenReason),
    InvalidResetToken(InvalidTokenReason),
    InvalidOobToken(InvalidTokenReason),
    WrongEmailPassword,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal | Self::Sqlx(_) | Self::Lettre(_) | Self::Smtp(_) => {
                f.write_str("an internal error occurred")
            }
            Self::EmailInUse => f.write_str("email already in use"),
            Self::PasswordRequired => f.write_str("password required"),
            Self::InvalidRefreshToken(r) => write!(f, "invalid refresh token: {r}"),
            Self::InvalidAccessToken(r) => write!(f, "invalid access token: {r}"),
            Self::InvalidEmailToken(r) => write!(f, "invalid email token: {r}"),
            Self::InvalidResetToken(r) => write!(f, "invalid reset token: {r}"),
            Self::InvalidOobToken(r) => write!(f, "invalid oob token: {r}"),
            Self::WrongEmailPassword => f.write_str("wrong email or password"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    pub const fn status_code(&self) -> StatusCode {
        match self {
            Self::Internal | Self::Sqlx(_) | Self::Lettre(_) | Self::Smtp(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::EmailInUse => StatusCode::CONFLICT,
            Self::PasswordRequired => StatusCode::BAD_REQUEST,
            Self::InvalidRefreshToken(_) => StatusCode::UNAUTHORIZED,
            Self::InvalidAccessToken(_) => StatusCode::UNAUTHORIZED,
            Self::InvalidEmailToken(_) => StatusCode::BAD_REQUEST,
            Self::InvalidResetToken(_) => StatusCode::BAD_REQUEST,
            Self::InvalidOobToken(_) => StatusCode::BAD_REQUEST,
            Self::WrongEmailPassword => StatusCode::UNAUTHORIZED,
        }
    }

    pub const fn internal() -> Self {
        Self::Internal
    }

    pub const fn email_not_in_use() -> Self {
        Self::WrongEmailPassword
    }

    pub const fn email_in_use() -> Self {
        Self::EmailInUse
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

impl From<handlebars::RenderError> for Error {
    fn from(e: handlebars::RenderError) -> Self {
        error!("handlebars render error: {e}");
        Error::Internal
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.status_code(), self.to_string()).into_response()
    }
}
