pub mod email;
pub mod identity;
pub mod models;
pub mod result;
pub mod routes;
pub mod schema;
pub mod token;
pub mod util;

#[macro_use]
extern crate diesel;

use crate::result::Error;
use crate::result::Result;
use diesel::{
    r2d2::{self, ConnectionManager},
    PgConnection,
};
use email::SmtpConnSpec;
use models::User;
use once_cell::sync::Lazy;
use pbkdf2::password_hash::{PasswordHash, PasswordVerifier};
use std::env;
use std::sync::Mutex;

pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type DbConn = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

#[macro_use]
extern crate diesel_migrations;

static MIGRATION_MUTEX: Lazy<Mutex<()>> = Lazy::new(Mutex::default);

/// Create a database pool and run the necessary migrations.
#[must_use]
pub fn initialize_pool(database_url: &str) -> DbPool {
    let _shared = MIGRATION_MUTEX.lock().expect("failed to acquire lock");

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

pub fn get_pool_from_env() -> DbPool {
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set");

    initialize_pool(&db_url)
}

pub fn get_test_conn() -> DbConn {
    dotenv::dotenv().ok();
    let pool = get_pool_from_env();
    pool.get().unwrap()
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
        Self {
            smtp: SmtpConnSpec::from_env(),
            pool: get_pool_from_env(),
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
