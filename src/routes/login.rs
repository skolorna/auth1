use actix_web::{post, web, HttpResponse};
use serde::Deserialize;

use crate::db::postgres::PgPool;
use crate::db::redis::RedisPool;
use crate::login_with_password;
use crate::models::Session;
use crate::rate_limit::{RateLimit, SlidingWindow};
use crate::remote_ip::RemoteIp;
use crate::result::Result;

#[derive(Debug, Deserialize)]
struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[post("")]
async fn handle_login(
    pg: web::Data<PgPool>,
    redis: web::Data<RedisPool>,
    credentials: web::Json<LoginRequest>,
    remote_ip: RemoteIp,
) -> Result<HttpResponse> {
    const RATE_LIMIT: SlidingWindow = SlidingWindow::new("login", 60, 60);

    web::block(move || RATE_LIMIT.remaining_requests(&remote_ip.into(), &mut redis.get()?)).await?;

    let pg = pg.get()?;
    let res = web::block(move || {
        let user = login_with_password(&pg, &credentials.email, &credentials.password)?;
        Session::create(&pg, user.id)
    })
    .await?;

    Ok(HttpResponse::Ok().json(res))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(handle_login);
}
