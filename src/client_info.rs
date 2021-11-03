use std::{
    env,
    fmt::Display,
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
};

use actix_web::{FromRequest, HttpRequest};
use futures_util::Future;

use crate::{errors::AppError, util::FromEnvironment};

#[derive(Debug, Clone, Copy)]
pub struct ClientInfoConfig {
    pub trust_proxy: bool,
}

const DEFAULT_CONFIG: ClientInfoConfig = ClientInfoConfig { trust_proxy: false };

impl ClientInfoConfig {
    pub fn from_req(req: &HttpRequest) -> &Self {
        req.app_data::<Self>().unwrap_or(&DEFAULT_CONFIG)
    }
}

impl FromEnvironment for ClientInfoConfig {
    fn from_env() -> Self {
        Self {
            trust_proxy: env::var("TRUST_PROXY")
                .map(|s| s.parse().expect("TRUST_PROXY is not a boolean value"))
                .unwrap_or(false),
        }
    }
}

impl Default for ClientInfoConfig {
    fn default() -> Self {
        DEFAULT_CONFIG
    }
}

#[derive(Debug)]
pub struct ClientInfo {
    pub addr: String,
}

impl FromRequest for ClientInfo {
    type Error = AppError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;
    type Config = ClientInfoConfig;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let ClientInfoConfig { trust_proxy } = ClientInfoConfig::from_req(req);

        let addr = if *trust_proxy {
            req.connection_info()
                .realip_remote_addr()
                .unwrap()
                .to_owned()
        } else {
            req.peer_addr()
                .map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |s| s.ip())
                .to_string()
        };

        Box::pin(async move { Ok(Self { addr }) })
    }
}

impl Display for ClientInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use actix_web::{dev::Payload, test::TestRequest};

    use super::*;

    #[actix_rt::test]
    async fn trust_proxy() {
        let req = TestRequest::with_header("X-Forwarded-For", "1.1.1.1")
            .app_data(ClientInfoConfig { trust_proxy: true })
            .to_http_request();
        let info = ClientInfo::from_request(&req, &mut Payload::None)
            .await
            .unwrap();
        assert_eq!(info.addr, "1.1.1.1");
    }

    #[actix_rt::test]
    async fn simple() {
        let req = TestRequest::with_header("X-Forwarded-For", "8.8.8.8")
            .peer_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 80))
            .app_data(ClientInfoConfig { trust_proxy: false })
            .to_http_request();
        let info = ClientInfo::from_request(&req, &mut Payload::None)
            .await
            .unwrap();
        assert_eq!(info.addr, "1.1.1.1");
    }
}
