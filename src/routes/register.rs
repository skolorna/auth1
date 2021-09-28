use actix_web::{post, web, HttpResponse};

use crate::client_info::ClientInfo;
use crate::db::postgres::PgPool;
use crate::db::redis::RedisPool;
use crate::email::Emails;
use crate::errors::AppResult;
use crate::models::user::{CreateUser, NewUser};
use crate::rate_limit::{RateLimit, SlidingWindow};

#[post("")]
async fn handle_registration(
    pg: web::Data<PgPool>,
    redis: web::Data<RedisPool>,
    emails: web::Data<Emails>,
    web::Json(data): web::Json<CreateUser>,
    client_info: ClientInfo,
) -> AppResult<HttpResponse> {
    const RATE_LIMIT: SlidingWindow = SlidingWindow::new("create_user", 3600, 100);

    web::block(move || RATE_LIMIT.remaining_requests(&client_info.to_string(), &mut redis.get()?))
        .await?;

    let pg = pg.get()?;

    let created_user = NewUser::new(&data)?.create(&pg, emails.as_ref())?;

    Ok(HttpResponse::Created().json(created_user))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(handle_registration);
}
