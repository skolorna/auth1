use axum::{response::IntoResponse, routing::post, Extension, Json, Router};
use serde::{Deserialize, Serialize};

use crate::jwt::verification_token;

use super::{ApiContext, Result};

#[derive(Debug, Serialize, Deserialize)]
struct VerifyRequest {
    token: String,
}

async fn verify(
    ctx: Extension<ApiContext>,
    Json(req): Json<VerifyRequest>,
) -> Result<impl IntoResponse> {
    verification_token::verify(&req.token, &mut ctx.db.acquire().await?).await?;

    Ok("verified")
}

pub fn routes() -> Router {
    Router::new().route("/", post(verify))
}