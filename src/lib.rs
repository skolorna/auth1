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
pub mod util;

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
use email::SmtpConnSpec;
use models::User;

/// Login using email and password.
pub fn login_with_password(conn: &PgConn, email: &str, password: &str) -> Result<User> {
    let user = User::find_by_email(conn, email)?;

    verify_password(password.as_bytes(), &user.hash())?;

    Ok(user)
}

#[derive(Clone)]
pub struct Data {
    pub pg: PgPool,
    pub redis: RedisPool,
    pub smtp: SmtpConnSpec,
    pub client: ClientInfoConfig,
}

impl Data {
    pub fn from_env() -> Self {
        Self {
            redis: redis_pool_from_env(),
            smtp: SmtpConnSpec::from_env(),
            pg: pg_pool_from_env(),
            client: ClientInfoConfig { trust_proxy: false },
        }
    }
}

#[macro_export]
macro_rules! create_app {
    ($data:expr) => {{
        use actix_web::middleware::{normalize, Logger};
        use actix_web::{web, App};

        let auth1::Data {
            pg,
            smtp,
            redis,
            client,
        } = $data;

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
