use std::net::SocketAddr;

use actix_web::HttpServer;
use auth1::{create_app, util::FromEnvironment, AppConfig};
use dotenv::dotenv;
use tracing::debug;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    let config = AppConfig::from_env();

    debug!("{:?}", config);

    let addr: SocketAddr = "0.0.0.0:8000".parse().unwrap();

    eprintln!("Binding {}", addr);

    HttpServer::new(move || create_app!(config.clone()))
        .bind(addr)?
        .run()
        .await
}
