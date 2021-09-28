pub mod client_info;
pub mod crypto;
pub mod db;
pub mod email;
pub mod errors;
pub mod identity;
pub mod models;
pub mod rate_limit;
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

use crate::errors::AppResult;
use client_info::ClientInfoConfig;
use crypto::verify_password;
use db::{
    postgres::{pg_pool_from_env, PgConn, PgPool},
    redis::{redis_pool_from_env, RedisPool},
};
use email::Emails;
use models::User;
use types::{EmailAddress, Password};

/// Login using email and password.
pub fn login_with_password(
    conn: &PgConn,
    email: &EmailAddress,
    password: &Password,
) -> AppResult<User> {
    let user = User::find_by_email(conn, email)?;

    verify_password(password.as_bytes(), &user.hash())?;

    Ok(user)
}

#[derive(Clone)]
pub struct AppConfig {
    pub pg: PgPool,
    pub redis: RedisPool,
    pub emails: Emails,
    pub client: ClientInfoConfig,
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            redis: redis_pool_from_env(),
            emails: Emails::from_env(),
            pg: pg_pool_from_env(),
            client: ClientInfoConfig::from_env(),
        }
    }
}

#[macro_export]
macro_rules! create_app {
    ($config:expr) => {{
        use actix_cors::Cors;
        use actix_web::middleware::{normalize, Logger};
        use actix_web::{web, App};

        let auth1::AppConfig {
            pg,
            emails,
            redis,
            client,
        } = $config;

        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allow_any_method()
            .allow_any_header();

        App::new()
            .data(pg)
            .data(redis)
            .data(emails)
            .app_data(client)
            .app_data(
                web::JsonConfig::default()
                    .error_handler(|err, _req| actix_web::error::ErrorBadRequest(err)),
            )
            .wrap(cors)
            .wrap(normalize::NormalizePath::new(
                normalize::TrailingSlash::Trim,
            ))
            .configure(auth1::routes::configure)
            .wrap(Logger::default())
    }};
}
