use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr},
    pin::Pin,
};

use actix_web::{FromRequest, HttpRequest};
use futures_util::Future;

use crate::result::Error;

#[derive(Debug)]
pub struct RemoteIp(IpAddr);

impl FromRequest for RemoteIp {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = core::result::Result<Self, Error>>>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let ip = req
            .peer_addr()
            .map(|addr| addr.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));

        Box::pin(async move { Ok(Self(ip)) })
    }
}

impl Display for RemoteIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<RemoteIp> for IpAddr {
    fn from(RemoteIp(ip): RemoteIp) -> Self {
        ip
    }
}
