use actix_web::{http::StatusCode, test};
use auth1::{
    client_info::ClientInfoConfig,
    create_app,
    db::{postgres::pg_pool_from_env, redis::redis_pool_from_env},
    email::SmtpConnSpec,
    Data,
};
use dotenv::dotenv;
use serde_json::Value;

pub struct Server(pub Data);

impl Server {
    pub fn new() -> Self {
        dotenv().ok();

        Self(Data {
            redis: redis_pool_from_env(),
            pg: pg_pool_from_env(),
            smtp: SmtpConnSpec::new_test_inbox(),
            client: ClientInfoConfig::default(),
        })
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

    pub async fn post_json(&self, url: impl AsRef<str>, body: Value) -> (Value, StatusCode) {
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

    pub async fn get_json(&self, url: impl AsRef<str>) -> (Value, StatusCode) {
        let (body, status_code) = self.get(url).await;
        let response = serde_json::from_slice(&body).unwrap_or_default();
        (response, status_code)
    }
}
