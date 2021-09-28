use actix_web::{post, web, HttpResponse};

use crate::client_info::ClientInfo;
use crate::db::postgres::PgPool;
use crate::db::redis::RedisPool;
use crate::email::{send_verification_email, SmtpConnection};
use crate::models::user::CreateUser;
use crate::models::User;
use crate::rate_limit::{RateLimit, SlidingWindow};
use crate::result::{Error, Result};

#[post("")]
async fn handle_registration(
    pg: web::Data<PgPool>,
    redis: web::Data<RedisPool>,
    smtp: web::Data<SmtpConnection>,
    data: web::Json<CreateUser>,
    client_info: ClientInfo,
) -> Result<HttpResponse> {
    const RATE_LIMIT: SlidingWindow = SlidingWindow::new("create_user", 3600, 100);

    web::block(move || RATE_LIMIT.remaining_requests(&client_info.to_string(), &mut redis.get()?))
        .await?;

    let pg = pg.get()?;
    let created_user = web::block::<_, _, Error>(move || {
        let created_user = User::create(&pg, &data)?;
        send_verification_email(smtp.as_ref(), &created_user)?;
        Ok(created_user)
    })
    .await?;

    Ok(HttpResponse::Created().json(created_user))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(handle_registration);
}
