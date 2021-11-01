use std::pin::Pin;

use crate::{
    db::postgres::PgPool,
    errors::AppError,
    models::User,
    token::access_token::{self, Claims},
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
    pub claims: Claims,
}

impl FromRequest for Identity {
    type Error = AppError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, AppError>>>>;
    type Config = ();

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let token = match Authorization::<Bearer>::parse(req) {
            Ok(authorization) => {
                let bearer = authorization.into_scheme();
                bearer.token().to_string()
            }
            Err(_) => return Box::pin(async { Err(AppError::MissingAccessToken) }),
        };

        let pool = req
            .app_data::<web::Data<PgPool>>()
            .expect("db pool not set in app_data")
            .clone();

        Box::pin(async move {
            use crate::schema::users;

            let pg = pool.get()?;
            let claims = access_token::decode(&pg, &token)?;
            let user_id = claims.sub;
            let user: User = web::block(move || users::table.find(user_id).first(&pg)).await?;

            Ok(Self { user, claims })
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::db::postgres::pg_test_pool;

    use super::*;
    use actix_web::http::{header, StatusCode};
    use actix_web::ResponseError;
    use actix_web::{dev::Payload, test::TestRequest};

    #[actix_rt::test]
    async fn errors() {
        let expected: Vec<(TestRequest, StatusCode)> = vec![
            (TestRequest::get(), StatusCode::FORBIDDEN),
            (
                TestRequest::with_header(header::AUTHORIZATION, "Bear"),
                StatusCode::FORBIDDEN,
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

        let pool = pg_test_pool();

        for (req, status) in expected {
            let req = req.data(pool.clone());
            let res = Identity::from_request(&req.to_http_request(), &mut Payload::None).await;
            assert_eq!(res.unwrap_err().status_code(), status);
        }
    }
}
