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

        let pool = req
            .app_data::<web::Data<DbPool>>()
            .expect("db pool not set in app_data")
            .clone();

        Box::pin(async move {
            use crate::schema::users;

            let conn = pool.get()?;
            let claims = access_token
                .verify_and_decode(&conn)
                // Don't give away details about token formatting specifications.
                .map_err(|_| Error::InvalidCredentials)?;
            let user_id = claims.sub;
            let user: User = web::block(move || users::table.find(user_id).first(&conn)).await?;

            Ok(Self { user, claims })
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::get_test_pool;

    use super::*;
    use actix_web::http::{header, StatusCode};
    use actix_web::ResponseError;
    use actix_web::{dev::Payload, test::TestRequest};

    #[actix_rt::test]
    async fn errors() {
        let expected: Vec<(TestRequest, StatusCode)> = vec![
            (TestRequest::get(), StatusCode::UNAUTHORIZED),
            (
                TestRequest::with_header(header::AUTHORIZATION, "Bear"),
                StatusCode::UNAUTHORIZED,
            ),
            (
                TestRequest::with_header(header::AUTHORIZATION, "Bearer invalidjsonwebtoken"),
                StatusCode::FORBIDDEN,
            ),
            (
                // Correctly formatted JWT, but without the "kid" claim.
                TestRequest::with_header(header::AUTHORIZATION, "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
                StatusCode::FORBIDDEN,
            ),
        ];

        let pool = get_test_pool();

        for (req, status) in expected {
            let req = req.data(pool.clone());
            let res = Identity::from_request(&req.to_http_request(), &mut Payload::None).await;
            assert_eq!(res.unwrap_err().status_code(), status);
        }
    }
}
