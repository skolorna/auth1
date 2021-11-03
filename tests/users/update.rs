use actix_web::http::{Method, StatusCode};
use serde_json::json;

use crate::common::Server;

#[actix_rt::test]
async fn change_password() {
    let server = Server::new();

    let email = "passwordupdate@example.com";
    let user = server
        .create_user("Neo", email, "/+Rjj+6o+PZzxtnyOTOecPae")
        .await;

    let req = user
        .req()
        .method(Method::PATCH)
        .uri("/users/@me")
        .set_json(&json!({
            "password": "wrongpassword",
            "new_password": "süperstr0ngpas5word"
        }));
    let (_, status) = server.send_json(req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let req = user
        .req()
        .method(Method::PATCH)
        .uri("/users/@me")
        .set_json(&json!({
            "password": "/+Rjj+6o+PZzxtnyOTOecPae",
            "new_password": "süperstr0ngpas5word",
        }));
    let (res, status) = server.send_json(req).await;
    assert_eq!(status, StatusCode::OK, "{}", res);

    let (_, status) = server.login_user(email, "weakpassword").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (_, status) = server.login_user(email, "süperstr0ngpas5word").await;
    assert_eq!(status, StatusCode::OK);
}

#[actix_rt::test]
async fn no_updates() {
    let server = Server::new();

    let user = server
        .create_user(
            "Winnie the Pooh",
            "noupdates@example.com",
            "Za91Wt7PDa+NQ4l4xyONa3B+a76CgpHF",
        )
        .await;

    let req = user
        .req()
        .method(Method::PATCH)
        .uri("/users/@me")
        .set_json(&json!({
            "password": "Za91Wt7PDa+NQ4l4xyONa3B+a76CgpHF",
        }));
    let (body, status) = server.send(req).await;
    let body = String::from_utf8(body).unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("No changes specified"), "{}", body);
}
