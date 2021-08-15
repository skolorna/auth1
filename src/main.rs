use std::{env, net::SocketAddr};

use actix_web::{App, HttpServer};
use auth1::{create_pool, email::SmtpConnSpec};
use dotenv::dotenv;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set");
    let pool = create_pool(&database_url);

    let smtp_host = env::var("SMTP_HOST").expect("SMTP_HOST is not set");
    let smtp_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME is not set");
    let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD is not set");
    let smtp_spec = SmtpConnSpec::new(smtp_host, smtp_username, smtp_password);

    let addr: SocketAddr = "0.0.0.0:8000".parse().unwrap();

    eprintln!("Binding {}", addr);

    HttpServer::new(move || {
        App::new()
            .data(pool.clone())
            .data(smtp_spec.clone())
            .configure(auth1::routes::configure)
    })
    .bind(addr)?
    .run()
    .await
}
