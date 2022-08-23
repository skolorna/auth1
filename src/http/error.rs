use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("an internal error occurred")]
    Internal,

    #[error("database error")]
    Sqlx(#[from] sqlx::Error),
}

impl Error {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Internal | Self::Sqlx(..) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn internal() -> Self {
        Self::Internal
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(_: jsonwebtoken::errors::Error) -> Self {
        Self::Internal
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.status_code(), self.to_string()).into_response()
    }
}
