use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::bail;
use lettre::{
    transport::smtp::authentication::Credentials, AsyncFileTransport, AsyncSmtpTransport,
    Tokio1Executor,
};
use notify::{RecommendedWatcher, Watcher};
use oidc::{Oidc, ProviderInfo};
use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

pub mod email;
pub mod http;
pub mod jwt;
pub mod oidc;
pub mod oob;
pub mod util;
pub mod x509;

#[derive(clap::Parser)]
pub struct Config {
    /// PEM-encoded CA certificate chain.
    #[clap(long, env)]
    pub ca_cert: Option<PathBuf>,

    /// PEM-encoded CA key.
    #[clap(long, env)]
    pub ca_key: Option<PathBuf>,

    #[clap(long, env)]
    pub database_url: String,

    /// OTP email login url template. Use `{otp}` in place of the one time password.
    #[clap(long, env)]
    pub login_url: email::LoginUrl,

    #[clap(long, env)]
    pub smtp_host: Option<String>,

    #[clap(long, env)]
    pub smtp_username: Option<String>,

    #[clap(long, env)]
    pub smtp_password: Option<String>,

    #[clap(long, env, default_value = "http://localhost:8000")]
    pub public_url: String,

    #[clap(env)]
    pub google_client_id: String,

    #[clap(env)]
    pub google_client_secret: String,

    #[clap(long, env, default_value = "10")]
    pub max_database_connections: u32,

    #[clap(long, env, default_value = "2")]
    pub min_database_connections: u32,

    #[clap(env, default_value = "http://localhost:4317")]
    pub otlp_endpoint: String,

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
            let dir = Path::new("./mail");
            std::fs::create_dir_all(dir)?;
            info!("saving mail to {dir:?}");

            email::Transport::File(AsyncFileTransport::new(dir))
        };

        let mut templates = email::Templates::new(self.login_url.clone());

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
            templates,
        })
    }

    pub fn ca(&self) -> anyhow::Result<Arc<RwLock<x509::Authority>>> {
        match (self.ca_cert.as_ref(), self.ca_key.as_ref()) {
            (Some(cert), Some(key)) => watch_ca(cert, key),
            (Some(_), None) => bail!("no key specified"),
            (None, Some(_)) => bail!("no certificate specified"),
            (None, None) => x509::Authority::self_signed()
                .map(|ca| Arc::new(RwLock::new(ca)))
                .map_err(Into::into),
        }
    }

    pub fn oidc(&self) -> anyhow::Result<Oidc> {
        Ok(Oidc {
            google: ProviderInfo {
                issuer_url: IssuerUrl::new("https://accounts.google.com".to_owned())?,
                client_id: ClientId::new(self.google_client_id.clone()),
                client_secret: ClientSecret::new(self.google_client_secret.clone()),
                redirect_url: RedirectUrl::new(format!("{}/login/google/code", self.public_url))?,
            },
        })
    }
}

fn async_watcher() -> notify::Result<(
    RecommendedWatcher,
    mpsc::Receiver<notify::Result<notify::Event>>,
)> {
    let (tx, rx) = mpsc::channel(1);

    let watcher = RecommendedWatcher::new(
        move |res| tx.blocking_send(res).unwrap(),
        notify::Config::default(),
    )?;

    Ok((watcher, rx))
}

fn watch_ca(cert: &Path, key: &Path) -> anyhow::Result<Arc<RwLock<x509::Authority>>> {
    let ca = x509::Authority::from_files(cert, key)?;
    let ca_arc = Arc::new(RwLock::new(ca));

    let (mut watcher, mut rx) = async_watcher()?;

    let cert = cert.to_owned();
    let key = key.to_owned();

    let ret = ca_arc.clone();

    tokio::spawn(async move {
        watcher
            .watch(&cert, notify::RecursiveMode::Recursive)
            .unwrap();
        watcher
            .watch(&key, notify::RecursiveMode::Recursive)
            .unwrap();

        while let Some(res) = rx.recv().await {
            let e = match res {
                Ok(e) => e,
                Err(e) => {
                    error!("notify error: {e}");
                    continue;
                }
            };

            if !e.kind.is_modify() {
                continue;
            }

            match x509::Authority::from_files(&cert, &key) {
                Ok(ca) => {
                    *ca_arc.write().await = ca;
                    info!("reloaded certificate authority");
                }
                Err(e) => {
                    warn!("failed to reload certificate authority: {e}");
                }
            };
        }

        panic!("channel closed");
    });

    Ok(ret)
}
