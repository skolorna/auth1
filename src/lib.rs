pub mod http;
pub mod jwt;

#[derive(clap::Parser)]
pub struct Config {
    #[clap(long, env)]
    pub database_url: String,

    #[clap(long, env, default_value = "50")]
    pub max_database_connections: u32,
}
