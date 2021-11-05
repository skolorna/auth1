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

use client_info::ClientInfoOpt;
use db::{
    postgres::{PgOpt, PgPool},
    redis::{RedisOpt, RedisPool},
};
use email::{EmailOpt, Emails};
use structopt::StructOpt;
use util::FromOpt;
use x509::ca::{CertificateAuthority, CertificateAuthorityOpt};

#[derive(Clone)]
pub struct AppData {
    pub pg: PgPool,
    pub redis: RedisPool,
    pub emails: Emails,
    pub client: ClientInfoOpt,
    pub ca: CertificateAuthority,
}

#[derive(Debug, StructOpt)]
pub struct AppOpt {
    #[structopt(flatten)]
    email: EmailOpt,

    #[structopt(flatten)]
    ca: CertificateAuthorityOpt,

    #[structopt(flatten)]
    client_info: ClientInfoOpt,

    #[structopt(flatten)]
    redis: RedisOpt,

    #[structopt(flatten)]
    postgres: PgOpt,
}

impl FromOpt for AppData {
    type Opt = AppOpt;

    fn from_opt(opt: Self::Opt) -> Self {
        let AppOpt {
            email,
            ca,
            client_info,
            redis,
            postgres,
        } = opt;

        Self {
            redis: RedisPool::from_opt(redis),
            emails: Emails::from_opt(email),
            pg: PgPool::from_opt(postgres),
            client: client_info,
            ca: CertificateAuthority::from_opt(ca),
        }
    }
}

impl Debug for AppData {
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

        let ::auth1::AppData {
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
