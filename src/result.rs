use std::convert::TryInto;

use actix_web::{
    dev::HttpResponseBuilder,
    http::{header, StatusCode},
    HttpResponse, ResponseError,
};
use chrono::Duration;
use r2d2_redis::redis::RedisError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("database error: {0}")]
    DieselError(#[from] diesel::result::Error),

    #[error("redis error")]
    RedisError(#[from] RedisError),

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

    #[error("rate limit exceeded")]
    RateLimitExceeded { retry_after: Option<Duration> },

    #[error("user not found")]
    UserNotFound,
}

impl ResponseError for Error {
    fn status_code(&self) -> actix_web::http::StatusCode {
        use Error::{
            DieselError, EmailFailed, EmailInUse, InternalError, InvalidCredentials, InvalidEmail,
            KeyNotFound, MissingToken, RateLimitExceeded, RedisError, SmtpError, UserNotFound,
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
            RedisError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            RateLimitExceeded { .. } => StatusCode::TOO_MANY_REQUESTS,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let mut res = HttpResponseBuilder::new(self.status_code());

        res.header(header::CONTENT_TYPE, "text/plain; charset=utf-8");

        match self {
            Error::RateLimitExceeded {
                retry_after: Some(retry_after),
            } => {
                let secs: u64 = retry_after.num_seconds().try_into().unwrap_or(0);

                res.header(header::RETRY_AFTER, secs.to_string());
            }
            _ => {}
        }

        res.body(self.to_string())
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
