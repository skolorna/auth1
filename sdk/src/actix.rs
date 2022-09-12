use actix_web::{
    body::BoxBody, dev::Payload, http::header, FromRequest, HttpRequest, HttpResponse,
    ResponseError,
};
use actix_web_httpauth::{
    extractors::{bearer::BearerAuth, AuthenticationError},
    headers::www_authenticate::bearer,
};
use futures_core::future::LocalBoxFuture;
use futures_util::{future, FutureExt};
use http::HeaderValue;

use crate::{Identity, KeyStore};

#[derive(Debug, thiserror::Error)]
pub enum FromRequestError {
    #[error("{0}")]
    InvalidHeader(#[from] AuthenticationError<bearer::Bearer>),
    #[error("{0}")]
    Auth1(#[from] crate::Error),
}

impl ResponseError for FromRequestError {
    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        match self {
            FromRequestError::InvalidHeader(e) => e.error_response(),
            FromRequestError::Auth1(e) => {
                let mut res = HttpResponse::new(e.status_code());
                res.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                res.set_body(BoxBody::new(e.to_string()))
            }
        }
    }
}

impl FromRequest for Identity {
    type Error = FromRequestError;

    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let token = match BearerAuth::from_request(req, payload).into_inner() {
            Ok(auth) => auth.token().to_owned(),
            Err(e) => return future::err(FromRequestError::InvalidHeader(e)).boxed_local(),
        };

        let store = req
            .app_data::<KeyStore>()
            .expect("no KeyStore in app_data")
            .clone();

        async move {
            let claims = store.verify(&token).await?;
            Ok(Identity { claims })
        }
        .boxed_local()
    }
}
