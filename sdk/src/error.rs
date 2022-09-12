#[cfg(feature = "tracing")]
use tracing::error;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http error")]
    Http,

    #[error("unknown error")]
    Unknown,

    #[error("invalid token")]
    InvalidToken,
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;

        match *e.kind() {
            ErrorKind::InvalidEcdsaKey
            | ErrorKind::InvalidRsaKey(_)
            | ErrorKind::RsaFailedSigning
            | ErrorKind::InvalidKeyFormat
            | ErrorKind::MissingAlgorithm
            | ErrorKind::Crypto(_) => {
                #[cfg(feature = "tracing")]
                error!("unknown jwt error: {e}");
                Self::Unknown
            }
            _ => Self::InvalidToken,
        }
    }
}

impl From<reqwest::Error> for Error {
    #[allow(unused_variables)] // e isn't used unless the tracing feature is enabled
    fn from(e: reqwest::Error) -> Self {
        #[cfg(feature = "tracing")]
        error!("reqwest error: {e}");
        Self::Http
    }
}

impl Error {
    #[cfg(feature = "http")]
    pub const fn status_code(&self) -> http::StatusCode {
        use http::StatusCode;

        match self {
            Error::Http | Error::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
            Error::InvalidToken => StatusCode::UNAUTHORIZED,
        }
    }
}
