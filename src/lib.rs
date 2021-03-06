pub mod client_info;
pub mod db;
pub mod email;
pub mod password;
pub mod x509;
#[macro_use]
pub mod errors;
pub mod identity;
pub mod models;
pub mod rate_limit;
pub mod routes;
pub mod schema;
pub mod token;
pub mod types;
pub mod util;

#[macro_use]
extern crate diesel;

#[macro_use]
extern crate diesel_migrations;

use std::fmt::Debug;

use client_info::ClientInfoConfig;
use db::{
    postgres::{pg_pool_from_env, PgPool},
    redis::{redis_pool_from_env, RedisPool},
};
use email::Emails;
use util::FromEnvironment;
use x509::ca::CertificateAuthority;

#[derive(Clone)]
pub struct AppConfig {
    pub pg: PgPool,
    pub redis: RedisPool,
    pub emails: Emails,
    pub client: ClientInfoConfig,
    pub ca: CertificateAuthority,
}

impl FromEnvironment for AppConfig {
    fn from_env() -> Self {
        Self {
            redis: redis_pool_from_env(),
            emails: Emails::from_env(),
            pg: pg_pool_from_env(),
            client: ClientInfoConfig::from_env(),
            ca: CertificateAuthority::from_env(),
        }
    }
}

impl Debug for AppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig")
            .field("pg", &self.pg.state())
            .field("redis", &self.redis)
            .field("emails", &self.emails)
            .field("client", &self.client)
            .field("ca", &self.ca)
            .finish()
    }
}

#[macro_export]
macro_rules! create_app {
    ($config:expr) => {{
        use ::actix_cors::Cors;
        use ::actix_web::middleware::{normalize, Logger};
        use ::actix_web::{web, App};
        use ::auth1::errors::AppError;

        let ::auth1::AppConfig {
            pg,
            emails,
            redis,
            client,
            ca,
        } = $config;

        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allow_any_method()
            .allow_any_header()
            .max_age(600);

        App::new()
            .data(pg)
            .data(redis)
            .data(emails)
            .data(ca)
            .app_data(client)
            .app_data(
                web::JsonConfig::default()
                    .limit(1 << 30) // 1 MiB
                    .error_handler(|err, _req| AppError::from(err).into()),
            )
            .wrap(cors)
            .wrap(normalize::NormalizePath::new(
                normalize::TrailingSlash::Trim,
            ))
            .configure(auth1::routes::configure)
            .wrap(Logger::default())
    }};
}
