use actix_web::http::{Method, StatusCode};
use serde_json::json;

use crate::common::Server;

#[actix_rt::test]
async fn update_email() {
    let server = Server::new();

    let alice = server
        .create_user("Alice", "alice@example.com", "hunter4$$")
        .await;

    // Expect one verification email
    assert!(server.pop_mail().is_some());
    assert!(server.pop_mail().is_none());

    let _bob = server
        .create_user("Bob", "bob@example.com", "bobrocks")
        .await;

    // Expect one verification email
    assert!(server.pop_mail().is_some());
    assert!(server.pop_mail().is_none());

    let req = alice
        .req()
        .method(Method::PATCH)
        .uri("/users/@me")
        .set_json(&json!({
                "password": "hunter4$$",
                "email": "bob@example.com"
        }));
    let (_, status) = server.send_json(req).await;
    assert_eq!(status, StatusCode::CONFLICT); // Email in use by Bob

    let req = alice
        .req()
        .method(Method::PATCH)
        .uri("/users/@me")
        .set_json(&json!({
            "password": "hunter4$$",
            "email": "coolalice@example.com"
        }));
    let (res, status) = server.send_json(req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(res["email"].as_str(), Some("coolalice@example.com"));
    assert_eq!(res["verified"].as_bool(), Some(false));

    // Email verification request
    assert!(server.pop_mail().is_some());
    assert!(server.pop_mail().is_none());

    let req = alice.req().method(Method::POST).uri("/verify/resend");
    let (res, status) = server.send(req).await;
    assert!(res.is_empty());
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert!(server.pop_mail().is_some());
    assert!(server.pop_mail().is_none());
}
