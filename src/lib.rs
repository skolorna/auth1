use lettre::transport::smtp::authentication::Credentials;

pub mod email;
pub mod http;
pub mod jwt;

#[derive(clap::Parser)]
pub struct Config {
    #[clap(long, env)]
    pub database_url: String,

    #[clap(long, env, default_value = "50")]
    pub max_database_connections: u32,

    #[clap(env)]
    pub smtp_host: String,

    #[clap(env)]
    pub smtp_username: String,

    #[clap(env)]
    pub smtp_password: String,
}

impl Config {
    pub fn smtp_credentials(&self) -> Credentials {
        Credentials::new(self.smtp_username.clone(), self.smtp_password.clone())
    }
}
