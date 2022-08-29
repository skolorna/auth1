use http::Result;
use lettre::{transport::smtp::authentication::Credentials, AsyncSmtpTransport, Tokio1Executor};
use tracing::warn;

pub mod email;
pub mod http;
pub mod jwk;
pub mod jwt;
pub mod x509;

#[derive(clap::Parser)]
pub struct Config {
    #[clap(long, env)]
    pub database_url: String,

    #[clap(long, env, default_value = "50")]
    pub max_database_connections: u32,

    #[clap(env)]
    pub smtp_host: Option<String>,

    #[clap(env)]
    pub smtp_username: Option<String>,

    #[clap(env)]
    pub smtp_password: Option<String>,
}

impl Config {
    pub fn email_client(&self) -> Result<email::Client> {
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

        Ok(email::Client {
            from: "Skolorna <system@skolorna.com>"
                .parse()
                .expect("failed to parse default mailbox"),
            reply_to: None,
            transport,
        })
    }
}
