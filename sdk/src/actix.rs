use actix_web::{dev::Payload, FromRequest, HttpRequest, ResponseError};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use futures_core::future::LocalBoxFuture;
use futures_util::{future, FutureExt};

use crate::{Error, Identity, KeyStore};

impl ResponseError for Error {}

impl FromRequest for Identity {
    type Error = Error;

    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let token = match BearerAuth::from_request(req, payload).into_inner() {
            Ok(auth) => auth.token().to_owned(),
            Err(_) => return future::err(Error::MalformedToken).boxed_local(),
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
