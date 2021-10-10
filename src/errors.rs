use std::fmt::Display;

use actix_web::{
    dev::HttpResponseBuilder, error::JsonPayloadError, http::StatusCode, HttpResponse,
    ResponseError,
};
use chrono::{DateTime, Utc};
use r2d2_redis::redis::RedisError;
use serde::Serialize;
use tracing::log::warn;
use zxcvbn::ZxcvbnError;

use crate::crypto::PasswordFeedback;

#[derive(Debug)]
pub enum AppError {
    InternalError {
        cause: Box<dyn std::error::Error + Send + Sync>,
    },
    EmailInUse,
    InvalidEmailPassword,
    TooManyRequests {
        retry_after: Option<DateTime<Utc>>,
    },
    SessionNotFound,
    InvalidAccessToken,
    BadRequest(Option<String>),
    MissingAccessToken,
    InvalidVerificationToken,
    JsonError(serde_json::Error),
    PayloadTooLarge,
    WeakPassword {
        feedback: Option<PasswordFeedback>,
    },
    InvalidRefreshToken,
}

impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::InternalError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::EmailInUse => StatusCode::CONFLICT,
            AppError::InvalidEmailPassword => StatusCode::BAD_REQUEST,
            AppError::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
            AppError::SessionNotFound => StatusCode::NOT_FOUND,
            AppError::InvalidAccessToken => StatusCode::FORBIDDEN,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::MissingAccessToken => StatusCode::UNAUTHORIZED,
            AppError::InvalidVerificationToken => StatusCode::BAD_REQUEST,
            AppError::JsonError(_) => StatusCode::BAD_REQUEST,
            AppError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::WeakPassword { .. } => StatusCode::BAD_REQUEST,
            AppError::InvalidRefreshToken => StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let mut res = HttpResponseBuilder::new(self.status_code());

        if let AppError::InternalError { cause } = self {
            // For debugging purpouses, it can be quite helpful to log internal errors.
            warn!("{}", cause);
        }

        res.json(ErrorJson::from(self))
    }
}

impl AppError {
    pub fn code(&self) -> &'static str {
        match self {
            AppError::InternalError { .. } => "internal_error",
            AppError::EmailInUse => "email_in_use",
            AppError::InvalidEmailPassword => "invalid_email_password",
            AppError::TooManyRequests { .. } => "too_many_requests",
            AppError::SessionNotFound => "session_not_found",
            AppError::InvalidAccessToken => "invalid_access_token",
            AppError::BadRequest(_) => "bad_request",
            AppError::MissingAccessToken => "missing_access_token",
            AppError::InvalidVerificationToken => "invalid_verification_token",
            AppError::JsonError(_) => "invalid_body",
            AppError::PayloadTooLarge => "too_large",
            AppError::WeakPassword { .. } => "weak_password",
            AppError::InvalidRefreshToken => "invalid_refresh_token",
        }
    }
}

impl Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::InternalError { .. } => write!(f, "An unknown error occurred."),
            AppError::EmailInUse => write!(f, "The email address is in use by another account."),
            AppError::InvalidEmailPassword => write!(f, "The email and/or password is incorrect."),
            AppError::TooManyRequests { .. } => write!(f, "Too many requests."),
            AppError::SessionNotFound => write!(f, "Session not found."),
            AppError::InvalidAccessToken => write!(f, "Invalid access token."),
            AppError::BadRequest(m) => match m {
                Some(m) => write!(f, "{}", m),
                None => write!(f, "Bad request."),
            },
            AppError::MissingAccessToken => write!(f, "Access token is missing."),
            AppError::InvalidVerificationToken => write!(f, "The verification token is invalid."),
            AppError::JsonError(e) => e.fmt(f),
            AppError::PayloadTooLarge => write!(f, "Payload too large"),
            AppError::WeakPassword { feedback } => match feedback {
                Some(feedback) => write!(f, "{}", feedback),
                _ => write!(f, "Password is too weak."),
            },
            AppError::InvalidRefreshToken => write!(f, "Invalid refresh token."),
        }
    }
}

impl From<diesel::result::Error> for AppError {
    fn from(err: diesel::result::Error) -> Self {
        Self::InternalError { cause: err.into() }
    }
}

impl From<lettre::error::Error> for AppError {
    fn from(err: lettre::error::Error) -> Self {
        Self::InternalError { cause: err.into() }
    }
}

impl From<lettre::transport::smtp::Error> for AppError {
    fn from(err: lettre::transport::smtp::Error) -> Self {
        Self::InternalError { cause: err.into() }
    }
}

impl From<RedisError> for AppError {
    fn from(err: RedisError) -> Self {
        Self::InternalError { cause: err.into() }
    }
}

impl From<pbkdf2::password_hash::Error> for AppError {
    fn from(err: pbkdf2::password_hash::Error) -> Self {
        match err {
            pbkdf2::password_hash::Error::Password => Self::InvalidEmailPassword,
            _ => Self::InternalError {
                cause: err.to_string().into(),
            },
        }
    }
}

impl<E: std::fmt::Debug + Into<Self>> From<actix_web::error::BlockingError<E>> for AppError {
    fn from(err: actix_web::error::BlockingError<E>) -> Self {
        use actix_web::error::BlockingError::{Canceled, Error};

        match err {
            Error(e) => e.into(),
            Canceled => Self::InternalError {
                cause: "Blocking task canceled".into(),
            },
        }
    }
}

impl From<r2d2::Error> for AppError {
    fn from(err: r2d2::Error) -> Self {
        Self::InternalError { cause: err.into() }
    }
}

impl From<JsonPayloadError> for AppError {
    fn from(err: JsonPayloadError) -> Self {
        match err {
            JsonPayloadError::Overflow => Self::PayloadTooLarge,
            JsonPayloadError::ContentType => Self::BadRequest(Some("Wrong content type.".into())),
            JsonPayloadError::Deserialize(e) => Self::JsonError(e),
            JsonPayloadError::Payload(_) => Self::BadRequest(None),
        }
    }
}

impl From<ZxcvbnError> for AppError {
    fn from(err: ZxcvbnError) -> Self {
        match err {
            ZxcvbnError::BlankPassword => Self::WeakPassword { feedback: None },
            ZxcvbnError::DurationOutOfRange => Self::InternalError { cause: err.into() },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorJson {
    pub code: String,
    pub message: String,
}

impl From<&AppError> for ErrorJson {
    fn from(err: &AppError) -> Self {
        Self {
            code: err.code().to_string(),
            message: err.to_string(),
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;

/// Make all server-related JWT errors opaque to the client.
macro_rules! jwt_err_opaque {
    ($err:expr, $out:expr) => {{
        use ::jsonwebtoken::errors::ErrorKind::*;
        use ::tracing::warn;

        warn!("{}", $err);

        match $err.kind() {
            InvalidToken | InvalidSignature | ExpiredSignature | InvalidIssuer
            | InvalidAudience | InvalidSubject | ImmatureSignature | InvalidAlgorithm
            | Base64(_) | Json(_) | Utf8(_) => $out,
            InvalidEcdsaKey | InvalidRsaKey | InvalidAlgorithmName | InvalidKeyFormat
            | Crypto(_) | __Nonexhaustive => AppError::InternalError { cause: $err.into() },
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_serialization() {
        assert_eq!(
            AppError::InternalError {
                cause: "Secret error".into()
            }
            .code(),
            "internal_error"
        )
    }
}
