use actix_web::{http::header, test::TestRequest};

pub struct TestUser {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

impl TestUser {
    pub fn new(access_token: String, refresh_token: Option<String>) -> Self {
        Self {
            access_token,
            refresh_token,
        }
    }

    pub fn req(&self) -> TestRequest {
        TestRequest::with_header(
            header::AUTHORIZATION,
            format!("Bearer {}", self.access_token),
        )
    }
}
