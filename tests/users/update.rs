use actix_web::http::{Method, StatusCode};
use serde_json::json;

use crate::common::Server;

#[actix_rt::test]
async fn change_password() {
    let server = Server::new();

    let email = "passwordupdate@example.com";
    let user = server.create_user("Neo", email, "weakpassword").await;

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
            "password": "weakpassword",
            "new_password": "süperstr0ngpas5word",
        }));
    let (_, status) = server.send_json(req).await;
    assert_eq!(status, StatusCode::OK);

    let (_, status) = server.login_user(email, "weakpassword").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (_, status) = server.login_user(email, "süperstr0ngpas5word").await;
    assert_eq!(status, StatusCode::OK);
}
