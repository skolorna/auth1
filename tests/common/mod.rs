pub mod test_user;

use std::sync::MutexGuard;

use actix_web::{
    http::StatusCode,
    test::{self, TestRequest},
};
use auth1::{
    client_info::ClientInfoConfig,
    create_app,
    db::{postgres::pg_pool_from_env, redis::redis_pool_from_env},
    email::SmtpConnection,
    Data,
};
use dotenv::dotenv;
use lettre::Envelope;
use serde_json::{json, Value};

use self::test_user::TestUser;

pub type TestResponse = (Value, StatusCode);

pub struct Server(pub Data);

impl Server {
    pub fn new() -> Self {
        dotenv().ok();

        Self(Data {
            redis: redis_pool_from_env(),
            pg: pg_pool_from_env(),
            smtp: SmtpConnection::new_test_inbox(),
            client: ClientInfoConfig::default(),
        })
    }

    pub async fn send(&self, req: TestRequest) -> (Vec<u8>, StatusCode) {
        let mut app = test::init_service(create_app!(self.0.clone())).await;

        let res = test::call_service(&mut app, req.to_request()).await;

        let status_code = res.status();
        let body = test::read_body(res).await;

        (body.to_vec(), status_code)
    }

    pub async fn send_json(&self, req: TestRequest) -> TestResponse {
        let (body, status) = self.send(req).await;
        let response = serde_json::from_slice(&body).unwrap_or_default();
        (response, status)
    }

    pub async fn post(&self, url: impl AsRef<str>, body: Value) -> (Vec<u8>, StatusCode) {
        let mut app = test::init_service(create_app!(self.0.clone())).await;

        let req = test::TestRequest::post()
            .uri(url.as_ref())
            .set_json(&body)
            .to_request();
        let res = test::call_service(&mut app, req).await;
        let status_code = res.status();
        let body = test::read_body(res).await;

        (body.to_vec(), status_code)
    }

    pub async fn post_json(&self, url: impl AsRef<str>, body: Value) -> TestResponse {
        let (body, status_code) = self.post(url, body).await;
        let response = serde_json::from_slice(&body).unwrap_or_default();
        (response, status_code)
    }

    pub async fn get(&self, url: impl AsRef<str>) -> (Vec<u8>, StatusCode) {
        let mut app = test::init_service(create_app!(self.0.clone())).await;

        let req = test::TestRequest::get().uri(url.as_ref()).to_request();
        let res = test::call_service(&mut app, req).await;
        let status_code = res.status();
        let body = test::read_body(res).await;

        (body.to_vec(), status_code)
    }

    pub async fn create_user(&self, email: &str, password: &str) -> TestUser {
        let (_, status) = self
            .post_json(
                "/users",
                json!({
                    "email": email,
                    "password": password,
                }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "failed to create user {}",
            email
        );

        let (res, status) = self.login_user(email, password).await;
        assert_eq!(status, StatusCode::OK);

        TestUser::new(res["access_token"].as_str().unwrap().to_owned())
    }

    pub async fn login_user(&self, email: &str, password: &str) -> (Value, StatusCode) {
        self.post_json(
            "/login",
            json!({
                "email": email,
                "password": password,
            }),
        )
        .await
    }

    pub fn inbox(&self) -> MutexGuard<Vec<(Envelope, String)>> {
        self.0.smtp.get_test_inbox()
    }

    pub fn pop_email(&self) -> Option<(Envelope, String)> {
        self.inbox().pop()
    }
}
