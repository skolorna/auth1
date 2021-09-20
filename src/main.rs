use std::net::SocketAddr;

use actix_web::HttpServer;
use auth1::{create_app, AppConfig};
use dotenv::dotenv;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let config = AppConfig::from_env();

    let addr: SocketAddr = "0.0.0.0:8000".parse().unwrap();

    eprintln!("Binding {}", addr);

    HttpServer::new(move || create_app!(config.clone()))
        .bind(addr)?
        .run()
        .await
}
