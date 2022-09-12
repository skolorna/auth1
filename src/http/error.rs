use std::fmt::Display;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tracing::error;

#[derive(Debug)]
pub enum Error {
    Internal,
    Sqlx(sqlx::Error),
    Lettre(lettre::error::Error),
    Smtp(lettre::transport::smtp::Error),
    EmailInUse,
    Unauthorized,
    PasswordRequired,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Error::Internal | Error::Sqlx(_) | Error::Lettre(_) | Error::Smtp(_) => {
                "an internal error occurred"
            }
            Error::EmailInUse => "email already in use",
            Error::Unauthorized => "unauthorized",
            Error::PasswordRequired => "password required",
        };

        f.write_str(msg)
    }
}

impl std::error::Error for Error {}

impl Error {
    pub const fn status_code(&self) -> StatusCode {
        match self {
            Self::Internal | Self::Sqlx(_) | Self::Lettre(_) | Self::Smtp(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::EmailInUse | Self::PasswordRequired => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
        }
    }

    pub const fn internal() -> Self {
        Self::Internal
    }

    pub const fn user_not_found() -> Self {
        Self::Unauthorized
    }

    pub const fn email_in_use() -> Self {
        Self::EmailInUse
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;

        match e.kind() {
            ErrorKind::InvalidToken
            | ErrorKind::InvalidAlgorithmName
            | ErrorKind::MissingRequiredClaim(_)
            | ErrorKind::InvalidIssuer
            | ErrorKind::InvalidAudience
            | ErrorKind::ExpiredSignature
            | ErrorKind::InvalidAlgorithm
            | ErrorKind::ImmatureSignature
            | ErrorKind::InvalidSubject
            | ErrorKind::Base64(_)
            | ErrorKind::Json(_)
            | ErrorKind::Utf8(_)
            | ErrorKind::InvalidSignature => Self::Unauthorized,
            _ => {
                error!("jwt error: {e}");
                Self::Internal
            }
        }
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

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.status_code(), self.to_string()).into_response()
    }
}
