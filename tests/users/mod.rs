mod email;
mod sessions;
mod update;

use actix_web::{http::StatusCode, test};
use auth1::{create_app, email::StoredEmail, token::AccessTokenClaims};
use jsonwebtoken::{DecodingKey, Validation};
use regex::Regex;
use serde_json::{json, Value};

use crate::common::Server;

#[actix_rt::test]
async fn get_nonexistent_user() {
    let server = Server::new();

    let (_, status) = server
        .login_user(
            "nonexistentuserpleasedontuse@example.com",
            "perf3ctlÿf1nepassw0rd",
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn create_user_and_login() {
    let server = Server::new();

    let _ = server
        .create_user("User no. 1", "user1@example.com", "d0ntpwnm3")
        .await;

    // Email addresses are not reusable!
    let (_, status) = server
        .post_json(
            "/register",
            json!({
                "email": "user1@example.com",
                "full_name": "Juan",
                "password": "l1lxazJDJZWQnNBQ"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (access_token, refresh_token) = test_login(&server, "user1@example.com", "d0ntpwnm3").await;

    let me = get_me(&server, &access_token).await;
    assert!(!me["verified"].as_bool().unwrap());

    test_verify_email(&server, "user1@example.com").await;

    let me = get_me(&server, &access_token).await;
    assert!(me["verified"].as_bool().unwrap());

    let (res, status) = server
        .post_json(
            "/token",
            json!({
                "refresh_token": refresh_token,
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let me = get_me(&server, res["access_token"].as_str().unwrap()).await;
    assert_eq!(me["email"], json!("user1@example.com"));
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

async fn test_login(server: &Server, email: &str, password: &str) -> (String, String) {
    let (_, status) = server
        .post_json(
            "/login",
            json!({
                "email": email,
                "password": "d0ntpwnme", // should end with 3
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

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

    let _ = jsonwebtoken::decode::<AccessTokenClaims>(
        access_token,
        &decoding_key,
        &Validation::new(jsonwebtoken::Algorithm::RS256),
    )
    .unwrap();

    (access_token.to_owned(), refresh_token.to_owned())
}

async fn test_verify_email(server: &Server, email: &str) {
    let StoredEmail {
        to,
        subject: _,
        body,
    } = server.pop_mail().unwrap();
    assert!(to.contains(email));
    let jwt_re = Regex::new(r"[0-9a-zA-Z_-]+\.[0-9a-zA-Z_-]+\.[0-9a-zA-Z_-]+").unwrap();
    let verification_token = jwt_re.find(&body).unwrap().as_str();

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
