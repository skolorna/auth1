use actix_web::{web, HttpResponse};
use serde::Deserialize;

use crate::client_info::ClientInfo;
use crate::crypto::verify_password;
use crate::db::postgres::PgPool;
use crate::db::redis::RedisPool;
use crate::errors::{AppError, AppResult};
use crate::models::User;
use crate::rate_limit::{RateLimit, SlidingWindow};
use crate::token::{AccessToken, TokenResponse};
use crate::types::EmailAddress;

#[derive(Debug, Deserialize)]
struct LoginRequest {
    pub email: EmailAddress,
    pub password: String,
}

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
        let user =
            User::find_by_email(&pg, &credentials.email)?.ok_or(AppError::InvalidEmailPassword)?;

        verify_password(&credentials.password, &user.hash()?)?;

        AccessToken::sign(&pg, user.id).map(|access_token| TokenResponse { access_token })
    })
    .await?;

    Ok(HttpResponse::Ok().json(res))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("").route(web::post().to(handle_login)));
}
