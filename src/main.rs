use std::net::SocketAddr;

use actix_web::HttpServer;
use auth1::{create_app, util::FromOpt, AppData, AppOpt};
use dotenv::dotenv;
use structopt::StructOpt;
use tracing::debug;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    let opt = AppOpt::from_args();
    let data = AppData::from_opt(opt);

    debug!("{:?}", data);

    let addr: SocketAddr = "0.0.0.0:8000".parse().unwrap();

    eprintln!("Binding {}", addr);

    HttpServer::new(move || create_app!(data.clone()))
        .bind(addr)?
        .run()
        .await
}
