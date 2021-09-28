use actix_web::{post, web, HttpResponse};
use serde::Deserialize;

use crate::client_info::ClientInfo;
use crate::db::postgres::PgPool;
use crate::db::redis::RedisPool;
use crate::errors::AppResult;
use crate::login_with_password;
use crate::models::Session;
use crate::rate_limit::{RateLimit, SlidingWindow};
use crate::types::{EmailAddress, Password};

#[derive(Debug, Deserialize)]
struct LoginRequest {
    pub email: EmailAddress,
    pub password: Password,
}

#[post("")]
async fn handle_login(
    pg: web::Data<PgPool>,
    redis: web::Data<RedisPool>,
    credentials: web::Json<LoginRequest>,
    client_info: ClientInfo,
) -> AppResult<HttpResponse> {
    const RATE_LIMIT: SlidingWindow = SlidingWindow::new("login", 60, 10);

    let client = format!("{}/{}", client_info.addr, &credentials.email);
    web::block(move || RATE_LIMIT.remaining_requests(&client, &mut redis.get()?)).await?;

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
