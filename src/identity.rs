use std::pin::Pin;

use crate::{
    models::User,
    result::Error,
    token::{AccessToken, AccessTokenClaims},
    DbPool,
};

use actix_web::{http::header::Header, web, FromRequest};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use diesel::prelude::*;
use futures_util::Future;

/// An extractor for Actix Web that ensures that the user is properly authenticated.
/// Make sure to include `{user}` in the path in order for this extractor to correctly
/// extract `target`.
#[derive(Debug)]
pub struct Identity {
    pub user: User,
    pub claims: AccessTokenClaims,
}

impl FromRequest for Identity {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = core::result::Result<Self, Error>>>>;
    type Config = ();

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let access_token = match Authorization::<Bearer>::parse(req) {
            Ok(authorization) => {
                let bearer = authorization.into_scheme();
                AccessToken::new(bearer.token())
            }
            Err(_) => return Box::pin(async { Err(Error::MissingToken) }),
        };

        let pool = req.app_data::<web::Data<DbPool>>().unwrap().clone();

        Box::pin(async move {
            use crate::schema::users;

            let conn = pool.get()?;
            let claims = access_token.verify_and_decode(&conn)?;
            let user_id = claims.sub;
            let user: User = web::block(move || users::table.find(user_id).first(&conn)).await?;

            Ok(Self { user, claims })
        })
    }
}
