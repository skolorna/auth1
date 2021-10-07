use actix_web::http::Method;

use crate::common::Server;

#[actix_rt::test]
async fn list_sessions() {
    let server = Server::new();

    let u = server
        .create_user("The One", "neo@example.com", "mBMsaiArFUvydLuN")
        .await;

    let req = u.req().method(Method::GET).uri("/users/@me/sessions");
    let (res, _) = server.send_json(req).await;
    let sessions = res.as_array().unwrap();

    assert_eq!(sessions.len(), 1);
}
