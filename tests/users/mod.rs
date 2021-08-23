use actix_web::http::StatusCode;
use auth1::token::AccessTokenClaims;
use jsonwebtoken::{DecodingKey, Validation};
use serde_json::json;

use crate::common::Server;

async fn test_login(server: &Server, email: &str, password: &str, user_id: &str) {
    let (res, status) = server
        .post_json(
            "/login",
            json!({
                "email": "user1@example.com",
                "password": "d0ntpwnme", // should end with 3
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (res, status) = server
        .post_json(
            "/login",
            json!({
                "email": "user1@example.com",
                "password": "d0ntpwnm3",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let refresh_token = res["refresh_token"].as_str().unwrap();
    let access_token = res["access_token"].as_str().unwrap();
    let key_id = jsonwebtoken::decode_header(access_token)
        .unwrap()
        .kid
        .unwrap();

    let (pem, status) = server.get(format!("/keys/{}", key_id)).await;
    assert_eq!(status, StatusCode::OK);
    let decoding_key = DecodingKey::from_rsa_pem(&pem).unwrap();

    let token_data = jsonwebtoken::decode::<AccessTokenClaims>(
        access_token,
        &decoding_key,
        &Validation::new(jsonwebtoken::Algorithm::RS256),
    )
    .unwrap();

    assert_eq!(token_data.claims.sub.to_string(), user_id);
}

#[actix_rt::test]
async fn create_user_and_login() {
    let server = Server::new();

    let user1 = json!({
        "email": "user1@example.com",
        "password": "d0ntpwnm3",
    });
    let (res, status) = server.post_json("/users", user1.clone()).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "if this fails, your database is probably not clean"
    );
    let uid = res["id"].as_str().unwrap();

    // Email addresses are not reusable!
    let (res, status) = server.post_json("/users", user1).await;
    assert_eq!(status, StatusCode::CONFLICT);

    test_login(&server, "user1@example.com", "d0ntpwnm3", uid).await;
}
