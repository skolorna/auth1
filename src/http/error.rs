use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use sqlx::error::DatabaseError;
use tracing::error;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("an internal error occurred")]
    Internal,

    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("email error")]
    Lettre(#[from] lettre::error::Error),

    #[error("smtp error")]
    Smtp(#[from] lettre::transport::smtp::Error),

    #[error("email is already in use")]
    EmailInUse,

    #[error("unauthorized")]
    Unauthorized,
}

impl Error {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Internal | Self::Sqlx(..) | Self::Smtp(..) | Self::Lettre(..) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::EmailInUse => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
        }
    }

    pub const fn internal() -> Self {
        Self::Internal
    }

    pub const fn user_not_found() -> Self {
        Self::Unauthorized
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
            _ => Self::Internal,
        }
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        error!("openssl error: {e}");
        Self::Internal
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.status_code(), self.to_string()).into_response()
    }
}

pub trait SqlxResultExt<T> {
    fn on_constraint(
        self,
        name: &str,
        f: impl FnOnce(Box<dyn DatabaseError>) -> Error,
    ) -> Result<T, Error>;
}

impl<T, E> SqlxResultExt<T> for Result<T, E>
where
    E: Into<Error>,
{
    fn on_constraint(
        self,
        name: &str,
        map_err: impl FnOnce(Box<dyn DatabaseError>) -> Error,
    ) -> Result<T, Error> {
        self.map_err(|e| match e.into() {
            Error::Sqlx(sqlx::Error::Database(dbe)) if dbe.constraint() == Some(name) => {
                map_err(dbe)
            }
            e => e,
        })
    }
}
