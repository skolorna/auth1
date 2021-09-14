use actix_web::{http::StatusCode, ResponseError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("database error: {0}")]
    DieselError(#[from] diesel::result::Error),

    #[error("failed to compose email")]
    EmailFailed(#[from] lettre_email::error::Error),

    #[error("email already in use")]
    EmailInUse,

    #[error("internal server error")]
    InternalError,

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("invalid email")]
    InvalidEmail,

    #[error("key not found")]
    KeyNotFound,

    #[error("the token is missing or cannot be parsed")]
    MissingToken,

    #[error("email delivery failed")]
    SmtpError(#[from] lettre::smtp::error::Error),

    #[error("user not found")]
    UserNotFound,
}

impl ResponseError for Error {
    fn status_code(&self) -> actix_web::http::StatusCode {
        use Error::{
            DieselError, EmailFailed, EmailInUse, InternalError, InvalidCredentials, InvalidEmail,
            KeyNotFound, MissingToken, SmtpError, UserNotFound,
        };

        match self {
            InvalidCredentials => StatusCode::FORBIDDEN,
            InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            DieselError(ref err) => {
                use diesel::result::{
                    DatabaseErrorKind,
                    Error::{DatabaseError, NotFound},
                };

                match err {
                    DatabaseError(DatabaseErrorKind::UniqueViolation, _) => StatusCode::CONFLICT,
                    NotFound => StatusCode::NOT_FOUND,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                }
            }
            EmailInUse => StatusCode::CONFLICT,
            UserNotFound => StatusCode::NOT_FOUND,
            MissingToken => StatusCode::UNAUTHORIZED,
            EmailFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            SmtpError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            InvalidEmail => StatusCode::BAD_REQUEST,
            KeyNotFound => StatusCode::NOT_FOUND,
        }
    }
}

impl From<pbkdf2::password_hash::Error> for Error {
    fn from(_: pbkdf2::password_hash::Error) -> Self {
        Self::InvalidCredentials
    }
}

impl From<aes_gcm::Error> for Error {
    fn from(_: aes_gcm::Error) -> Self {
        Self::InvalidCredentials // I wish the error was more transparent
    }
}

impl From<r2d2::Error> for Error {
    fn from(_: r2d2::Error) -> Self {
        Self::InternalError
    }
}

impl<E: std::fmt::Debug + Into<Self>> From<actix_web::error::BlockingError<E>> for Error {
    fn from(err: actix_web::error::BlockingError<E>) -> Self {
        use actix_web::error::BlockingError::{Canceled, Error};

        match err {
            Error(e) => e.into(),
            Canceled => Self::InternalError,
        }
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        use self::Error::{InternalError, InvalidCredentials};
        use jsonwebtoken::errors::ErrorKind::*;

        match err.kind() {
            InvalidToken | InvalidSignature | InvalidAlgorithmName | InvalidAlgorithm
            | ExpiredSignature | InvalidIssuer | InvalidAudience | InvalidSubject
            | ImmatureSignature | Json(_) | Utf8(_) | Base64(_) => InvalidCredentials,
            InvalidKeyFormat | Crypto(_) | InvalidEcdsaKey | InvalidRsaKey | __Nonexhaustive => {
                InternalError
            }
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;
