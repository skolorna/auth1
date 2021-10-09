use actix_web::{web, HttpResponse};

use crate::client_info::ClientInfo;
use crate::db::postgres::PgPool;
use crate::db::redis::RedisPool;
use crate::email::Emails;
use crate::errors::AppResult;
use crate::models::user::{NewUser, RegisterUser};
use crate::rate_limit::{RateLimit, SlidingWindow};
use crate::token::{AccessToken, TokenResponse};

async fn handle_registration(
    pg: web::Data<PgPool>,
    redis: web::Data<RedisPool>,
    emails: web::Data<Emails>,
    web::Json(data): web::Json<RegisterUser>,
    client_info: ClientInfo,
) -> AppResult<HttpResponse> {
    const RATE_LIMIT: SlidingWindow = SlidingWindow::new("create_user", 3600, 100);

    web::block(move || RATE_LIMIT.remaining_requests(&client_info.to_string(), &mut redis.get()?))
        .await?;

    let pg = pg.get()?;

    let res = web::block(move || {
        let user = NewUser::new(&data)?.create(&pg, emails.as_ref())?;

        AccessToken::sign(&pg, user.id).map(|access_token| TokenResponse { access_token })
    })
    .await?;

    Ok(HttpResponse::Ok().json(res))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("").route(web::post().to(handle_registration)));
}
