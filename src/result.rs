use actix_web::{http::StatusCode, ResponseError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("internal server error")]
    InternalError,

    #[error("something else has the same unique value")]
    UniqueViolation,

    #[error("database error")]
    DieselError(#[from] diesel::result::Error),

    #[error("email already in use")]
    EmailInUse,

    #[error("user not found")]
    UserNotFound,

    #[error("missing or invalid token")]
    MissingOrInvalidToken,

    #[error("malformed token")]
    MalformedToken,
}

impl ResponseError for Error {
    fn status_code(&self) -> actix_web::http::StatusCode {
        use Error::*;

        match self {
            InvalidCredentials => StatusCode::FORBIDDEN,
            UniqueViolation => StatusCode::CONFLICT,
            InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            DieselError(ref err) => {
                use diesel::result::{DatabaseErrorKind, Error::*};

                match err {
                    DatabaseError(DatabaseErrorKind::UniqueViolation, _) => StatusCode::CONFLICT,
                    NotFound => StatusCode::NOT_FOUND,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                }
            }
            EmailInUse => StatusCode::CONFLICT,
            UserNotFound => StatusCode::NOT_FOUND,
            MissingOrInvalidToken => StatusCode::BAD_REQUEST,
            MalformedToken => StatusCode::BAD_REQUEST,
        }
    }
}

impl From<pbkdf2::password_hash::Error> for Error {
    fn from(_: pbkdf2::password_hash::Error) -> Self {
        Self::InvalidCredentials
    }
}

impl From<r2d2::Error> for Error {
    fn from(_: r2d2::Error) -> Self {
        Self::InternalError
    }
}

impl<E: std::fmt::Debug + Into<Error>> From<actix_web::error::BlockingError<E>> for Error {
    fn from(err: actix_web::error::BlockingError<E>) -> Self {
        use actix_web::error::BlockingError::*;

        match err {
            Error(e) => e.into(),
            Canceled => Self::InternalError,
        }
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        use self::Error::*;
        use jsonwebtoken::errors::ErrorKind::*;

        match err.kind() {
            InvalidToken => MalformedToken,
            InvalidSignature | InvalidEcdsaKey | InvalidRsaKey | ExpiredSignature => {
                InvalidCredentials
            }
            _ => InternalError,
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
