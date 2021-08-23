pub mod email;
pub mod identity;
pub mod models;
pub mod result;
pub mod routes;
pub mod schema;
pub mod token;

#[macro_use]
extern crate diesel;

use diesel::{
    r2d2::{self, ConnectionManager},
    PgConnection, RunQueryDsl,
};
use email::SmtpConnSpec;
use lettre::EmailAddress;
use models::User;
use pbkdf2::password_hash::{PasswordHash, PasswordVerifier};
use serde::Deserialize;
use std::env;
use std::str::FromStr;
use uuid::Uuid;

use crate::result::Error;
use crate::{models::user::NewUser, result::Result};

pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type DbConn = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

#[macro_use]
extern crate diesel_migrations;

/// Create a database pool and run the necessary migrations.
#[must_use]
pub fn initialize_pool(database_url: &str) -> DbPool {
    embed_migrations!();

    eprintln!("Connecting to Postgres");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("failed to create pool");

    eprintln!("Running migrations");
    let conn = pool.get().expect("failed to get connection");
    embedded_migrations::run_with_output(&conn, &mut std::io::stderr()).expect("migrations failed");
    println!("Database initialized!");

    pool
}

#[non_exhaustive]
#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub password: String,
}

pub fn create_user(conn: &DbConn, query: CreateUser) -> Result<User> {
    use crate::schema::users;

    let email = EmailAddress::from_str(&query.email).map_err(|_| Error::InvalidEmail)?;
    let hash = hash_password(query.password.as_bytes())?;

    let new_user = NewUser {
        id: Uuid::new_v4(),
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
/// assert_ne!(hash_password(p).unwrap(), hash_password(p).unwrap());
/// ```
///
/// # Errors
/// The function throws an error if the hashing fails.
pub fn hash_password(password: &[u8]) -> Result<String> {
    use pbkdf2::{
        password_hash::{PasswordHasher, SaltString},
        Pbkdf2,
    };
    use rand_core::OsRng;

    let salt = SaltString::generate(&mut OsRng);

    Pbkdf2
        .hash_password_simple(password, &salt)
        .map(|h| h.to_string())
        .map_err(|_| Error::InternalError)
}

/// Compare a password against a hashed value.
/// ```
/// use pbkdf2::password_hash::PasswordHash;
/// use auth1::{hash_password, verify_password};
///
/// let password = b"d0ntpwnme";
/// let hash = hash_password(password).unwrap();
/// let parsed_hash = PasswordHash::new(&hash).unwrap();
///
/// assert!(verify_password(password, &parsed_hash).is_ok());
/// assert!(verify_password(b"dontpwnme", &parsed_hash).is_err());
/// ```
///
/// # Errors
/// Throws an error if the password is wrong.
pub fn verify_password(
    password: &[u8],
    hash: &pbkdf2::password_hash::PasswordHash,
) -> core::result::Result<(), pbkdf2::password_hash::Error> {
    pbkdf2::Pbkdf2.verify_password(password, hash)
}

/// Login using email and password.
pub fn login_with_password(conn: &DbConn, email: &str, password: &str) -> Result<User> {
    let user = User::find_by_email(conn, email)?;
    let hash = PasswordHash::new(&user.hash).expect("failed to parse hash");

    verify_password(password.as_bytes(), &hash)?;

    Ok(user)
}

#[derive(Clone)]
pub struct Data {
    pub pool: DbPool,
    pub smtp: SmtpConnSpec,
}

impl Data {
    pub fn from_env() -> Self {
        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set");

        let smtp_host = env::var("SMTP_HOST").expect("SMTP_HOST is not set");
        let smtp_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME is not set");
        let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD is not set");
        let smtp_spec = SmtpConnSpec::new(smtp_host, smtp_username, smtp_password);

        Self {
            smtp: smtp_spec,
            pool: initialize_pool(&database_url),
        }
    }
}

#[macro_export]
macro_rules! create_app {
    ($data:expr) => {{
        use actix_web::middleware::{normalize, Logger};
        use actix_web::{web, App};

        let auth1::Data { pool, smtp } = $data;

        App::new()
            .data(pool)
            .data(smtp)
            .app_data(
                web::JsonConfig::default()
                    .error_handler(|err, _req| actix_web::error::ErrorBadRequest(err)),
            )
            .wrap(normalize::NormalizePath::new(
                normalize::TrailingSlash::Trim,
            ))
            .configure(auth1::routes::configure)
            .wrap(Logger::default())
    }};
}
