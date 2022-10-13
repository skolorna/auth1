use std::path::PathBuf;

use anyhow::bail;
use lettre::{transport::smtp::authentication::Credentials, AsyncSmtpTransport, Tokio1Executor};
use sentry::types::Dsn;
use tracing::warn;

pub mod email;
pub mod http;
pub mod jwt;
pub mod x509;

#[derive(clap::Parser)]
pub struct Config {
    #[clap(long, env)]
    pub ca_cert: Option<PathBuf>,

    #[clap(long, env)]
    pub ca_key: Option<PathBuf>,

    #[clap(long, env)]
    pub database_url: String,

    #[clap(long, env, default_value = "10")]
    pub max_database_connections: u32,

    #[clap(long, env, default_value = "2")]
    pub min_database_connections: u32,

    #[clap(env)]
    pub smtp_host: Option<String>,

    #[clap(env)]
    pub smtp_username: Option<String>,

    #[clap(env)]
    pub smtp_password: Option<String>,

    /// Email verification url template. Use `{token}` in place of the token.
    #[clap(long, env)]
    pub verification_url: String,

    /// Password reset template. Use `{token}` in place of the token.
    #[clap(long, env)]
    pub password_reset_url: String,

    #[clap(env)]
    pub sentry_dsn: Option<Dsn>,

    #[clap(env)]
    pub sentry_environment: Option<String>,

    #[clap(env, default_value = "1.0")]
    pub traces_sample_rate: f32,
}

impl Config {
    pub fn email_client(&self) -> anyhow::Result<email::Client> {
        let transport = if let Some(ref host) = self.smtp_host {
            let mut smtp = AsyncSmtpTransport::<Tokio1Executor>::relay(host)?;

            match (self.smtp_username.as_ref(), self.smtp_password.as_ref()) {
                (Some(username), Some(password)) => {
                    smtp = smtp.credentials(Credentials::new(username.clone(), password.clone()));
                }
                _ => warn!("smtp credentials are missing; skipping auth"),
            }

            email::Transport::Smtp(smtp.build())
        } else {
            email::Transport::File
        };

        let mut templates = email::Templates::new();

        templates.insert(
            "login",
            include_str!("templates/login.mjml"),
            include_str!("templates/login.txt"),
        )?;

        Ok(email::Client {
            from: "Skolorna <system@skolorna.com>"
                .parse()
                .expect("failed to parse default mailbox"),
            reply_to: None,
            transport,
            verification_url: self.verification_url.clone(),
            password_reset_url: self.password_reset_url.clone(),
            templates,
        })
    }

    pub fn ca(&self) -> anyhow::Result<x509::Authority> {
        match (self.ca_cert.as_ref(), self.ca_key.as_ref()) {
            (Some(cert), Some(key)) => x509::Authority::from_files(cert, key),
            (Some(_), None) => bail!("no key specified"),
            (None, Some(_)) => bail!("no certificate specified"),
            (None, None) => x509::Authority::self_signed().map_err(Into::into),
        }
    }
}
