use actix_web::http::StatusCode;
use serde_json::json;

use crate::common::{test_user::TestUser, Server};

#[actix_rt::test]
async fn refresh_token() {
    let server = Server::new();

    let user = server
        .create_user("James Bond", "007@example.com", "6YXZltH8VSl0nT5L")
        .await;

    let (res, status) = server
        .post_json(
            "/token",
            json!({
                "refresh_token": user.refresh_token.unwrap(),
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let access_token = res["access_token"].as_str().unwrap();

    let user = TestUser::new(access_token.to_owned(), None);

    let (res, status) = server.send_json(user.req().uri("/users/@me")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(res["full_name"].as_str(), Some("James Bond"));
}
