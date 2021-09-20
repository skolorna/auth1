pub mod client_info;
pub mod crypto;
pub mod db;
pub mod email;
pub mod identity;
pub mod models;
pub mod rate_limit;
pub mod result;
pub mod routes;
pub mod schema;
pub mod token;
pub mod types;
pub mod util;

// Hopefully this makes Diesel work in Docker
extern crate openssl;

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate diesel_migrations;

use crate::result::Result;
use client_info::ClientInfoConfig;
use crypto::verify_password;
use db::{
    postgres::{pg_pool_from_env, PgConn, PgPool},
    redis::{redis_pool_from_env, RedisPool},
};
use email::SmtpConnection;
use models::User;
use types::EmailAddress;

/// Login using email and password.
pub fn login_with_password(conn: &PgConn, email: &EmailAddress, password: &str) -> Result<User> {
    let user = User::find_by_email(conn, email)?;

    verify_password(password.as_bytes(), &user.hash())?;

    Ok(user)
}

#[derive(Clone)]
pub struct AppConfig {
    pub pg: PgPool,
    pub redis: RedisPool,
    pub smtp: SmtpConnection,
    pub client: ClientInfoConfig,
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            redis: redis_pool_from_env(),
            smtp: SmtpConnection::from_env(),
            pg: pg_pool_from_env(),
            client: ClientInfoConfig::from_env(),
        }
    }
}

#[macro_export]
macro_rules! create_app {
    ($config:expr) => {{
        use actix_web::middleware::{normalize, Logger};
        use actix_web::{web, App};

        let auth1::AppConfig {
            pg,
            smtp,
            redis,
            client,
        } = $config;

        App::new()
            .data(pg)
            .data(redis)
            .data(smtp)
            .app_data(client)
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
