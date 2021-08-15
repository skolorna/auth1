pub mod email;
pub mod models;
pub mod result;
pub mod routes;
pub mod schema;

#[macro_use]
extern crate diesel;

use std::pin::Pin;

use actix_web::{http::header::Header, web, FromRequest};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use diesel::{
    r2d2::{self, ConnectionManager},
    ExpressionMethods, OptionalExtension, PgConnection, QueryDsl, RunQueryDsl,
};
use futures_util::Future;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use models::User;
use pbkdf2::password_hash::{PasswordHash, PasswordVerifier};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::result::Result;
use crate::{models::NewUser, result::Error};

pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type DbConn = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

pub fn create_pool(database_url: &str) -> DbPool {
    eprintln!("Connecting to Postgres ...");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("failed to create pool");

    eprintln!("Connected!");

    pool
}

#[derive(Debug, Validate, Deserialize)]
pub struct CreateUser {
    #[validate(email)]
    pub email: String,

    pub password: String,
}

pub fn create_user(conn: &DbConn, query: CreateUser) -> Result<User> {
    if query.validate().is_err() {
        panic!("invalid query");
    }

    use crate::schema::users;

    let hash = hash_password(query.password.as_bytes());

    let new_user = NewUser {
        email: &query.email,
        hash: &hash,
    };

    let inserted_row = diesel::insert_into(users::table)
        .values(&new_user)
        .get_result(conn)
        .map_err(|err| match err {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) => Error::EmailInUse,
            _ => err.into(),
        })?;

    Ok(inserted_row)
}

pub fn hash_password(password: &[u8]) -> String {
    use pbkdf2::{
        password_hash::{PasswordHasher, SaltString},
        Pbkdf2,
    };
    use rand_core::OsRng;

    let salt = SaltString::generate(&mut OsRng);

    Pbkdf2
        .hash_password_simple(password, &salt)
        .unwrap()
        .to_string()
}

/// Verify a password.
/// ```
/// use pbkdf2::password_hash::PasswordHash;
/// use auth1::{hash_password, verify_password};
///
/// let password = b"d0ntpwnme";
/// let hash = hash_password(password);
/// let parsed_hash = PasswordHash::new(&hash).unwrap();
///
/// assert!(verify_password(password, &parsed_hash).is_ok());
/// assert!(verify_password(b"dontpwnme", &parsed_hash).is_err());
/// ```
pub fn verify_password(
    password: &[u8],
    hash: &pbkdf2::password_hash::PasswordHash,
) -> core::result::Result<(), pbkdf2::password_hash::Error> {
    pbkdf2::Pbkdf2.verify_password(password, hash)
}

pub fn get_user_by_email(conn: &DbConn, email: &str) -> Result<User> {
    use crate::schema::users::{columns, dsl::users};
    users
        .filter(columns::email.eq(email))
        .first(conn)
        .optional()?
        .ok_or(Error::UserNotFound)
}

pub fn sign_in_with_password(conn: &DbConn, email: &str, password: &str) -> Result<User> {
    let user: User = get_user_by_email(conn, email)?;
    let hash = PasswordHash::new(&user.hash).expect("failed to parse hash");

    verify_password(password.as_bytes(), &hash)?;

    Ok(user)
}

#[derive(Debug)]
pub struct Identity {
    user: User,
}

impl Identity {
    pub fn new(user: User) -> Self {
        Self {
            user,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject of the token (the user id).
    sub: i32,

    /// Expiration timestamp of the token (UNIX timestamp).
    exp: i64,
}

impl FromRequest for Identity {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = core::result::Result<Identity, Error>>>>;
    type Config = ();

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let token = match Authorization::<Bearer>::parse(req) {
            Ok(authorization) => {
                let bearer = authorization.into_scheme();
                bearer.token().to_string()
            }
            Err(_) => return Box::pin(async { Err(Error::MissingOrInvalidToken) }),
        };

        let pool = req.app_data::<web::Data<DbPool>>().unwrap().clone();

        Box::pin(async move {
            // let header = jsonwebtoken::decode_header(&token).unwrap();
            use schema::users;

            let conn = pool.get()?;

            const SECRET: &[u8] = b"secret";
            let decoded = jsonwebtoken::decode::<AccessTokenClaims>(
                &token,
                &DecodingKey::from_secret(SECRET),
                &Validation::new(Algorithm::HS256),
            ).unwrap();

            let user: User = users::table.find(decoded.claims.sub).first(&conn)?;

            Ok(Identity::new(user))
        })
    }
}
