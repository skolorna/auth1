use actix_web::{http::header, test::TestRequest};

pub struct TestUser {
    access_token: String,
}

impl TestUser {
    pub fn new(access_token: String) -> Self {
        Self { access_token }
    }

    pub fn req(&self) -> TestRequest {
        TestRequest::with_header(
            header::AUTHORIZATION,
            format!("Bearer {}", self.access_token),
        )
    }
}
