use std::str::FromStr;

use actix_web::{http::StatusCode, test};
use auth1::{create_app, token::AccessTokenClaims};
use jsonwebtoken::{DecodingKey, Validation};
use lettre::EmailAddress;
use regex::Regex;
use serde_json::{json, Value};

use crate::common::Server;

#[actix_rt::test]
async fn get_nonexistent_user() {
    let server = Server::new();

    let (res, status) = server
        .post(
            "/login",
            json!({
                "email": "nonexistentuserpleasedontuse@example.com",
                "password": "perf3ctlÿf1nepassw0rd",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
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

    let (access_token, refresh_token) =
        test_login(&server, "user1@example.com", "d0ntpwnm3", uid).await;

    let me = get_me(&server, &access_token).await;
    assert!(!me["verified"].as_bool().unwrap());

    test_verify_email(&server, "user1@example.com").await;

    let me = get_me(&server, &access_token).await;
    assert!(me["verified"].as_bool().unwrap());

    let (res, status) = server
        .post_json(
            "/refresh",
            json!({
                "token": refresh_token,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let me = get_me(&server, res["access_token"].as_str().unwrap()).await;
}

async fn get_me(server: &Server, access_token: &str) -> Value {
    let mut app = test::init_service(create_app!(server.0.clone())).await;

    let req = test::TestRequest::get()
        .uri("/users/@me")
        .header("Authorization", format!("Bearer {}", access_token))
        .to_request();
    let res = test::call_service(&mut app, req).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = test::read_body(res).await;

    serde_json::from_slice(&body).unwrap_or_default()
}

async fn test_login(
    server: &Server,
    email: &str,
    password: &str,
    user_id: &str,
) -> (String, String) {
    let (res, status) = server
        .post_json(
            "/login",
            json!({
                "email": email,
                "password": "d0ntpwnme", // should end with 3
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (res, status) = server
        .post_json(
            "/login",
            json!({
                "email": email,
                "password": password,
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

    (access_token.to_owned(), refresh_token.to_owned())
}

async fn test_verify_email(server: &Server, email: &str) {
    let (email_envelope, email_message) = {
        let mut inbox = server.0.smtp.get_test_inbox();
        inbox.pop().unwrap()
    };
    let recipients = email_envelope.to();
    assert_eq!(recipients, [EmailAddress::from_str(email).unwrap()],);
    let jwt_re = Regex::new(r"[0-9a-zA-Z_-]+\.[0-9a-zA-Z_-]+\.[0-9a-zA-Z_-]+").unwrap();
    let verification_token = jwt_re.find(&email_message).unwrap().as_str();

    let (res, status) = server
        .post(
            "/verify",
            json!({
                "token": verification_token,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&res));
}
