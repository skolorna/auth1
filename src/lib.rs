pub mod email;
pub mod identity;
pub mod models;
pub mod result;
pub mod routes;
pub mod schema;
pub mod token;

#[macro_use]
extern crate diesel;

use std::str::FromStr;

use diesel::{
    r2d2::{self, ConnectionManager},
    ExpressionMethods, OptionalExtension, PgConnection, QueryDsl, RunQueryDsl,
};
use lettre::EmailAddress;
use models::User;
use pbkdf2::password_hash::{PasswordHash, PasswordVerifier};
use serde::Deserialize;

use crate::result::Error;
use crate::{models::user::NewUser, result::Result};

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

#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub password: String,
}

pub fn create_user(conn: &DbConn, query: CreateUser) -> Result<User> {
    use crate::schema::users;

    let email = EmailAddress::from_str(&query.email).map_err(|_| Error::InvalidEmail)?;
    let hash = hash_password(query.password.as_bytes());

    let new_user = NewUser {
        email: &email.to_string(),
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

/// Hash and salt a password.
/// ```
/// use auth1::hash_password;
///
/// let p = b"gru";
/// assert_ne!(hash_password(p), hash_password(p));
/// ```
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

pub fn login_with_password(conn: &DbConn, email: &str, password: &str) -> Result<User> {
    let user: User = get_user_by_email(conn, email)?;
    let hash = PasswordHash::new(&user.hash).expect("failed to parse hash");

    verify_password(password.as_bytes(), &hash)?;

    Ok(user)
}
