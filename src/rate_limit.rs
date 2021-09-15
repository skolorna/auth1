use std::net::IpAddr;

use r2d2_redis::redis::Commands;

use crate::{
    db::redis::RedisConn,
    result::{Error, Result},
};

pub trait RateLimited {
    /// Get the number of remaining requests, and fail if the quota has been exceeded.
    fn remaining_requests(&self, remote_ip: &IpAddr, redis: &mut RedisConn) -> Result<u32>;
}

pub struct SimpleRateLimit {
    key: &'static str,
    window_secs: usize,
    max_requests: u32,
}

impl SimpleRateLimit {
    pub const fn new(key: &'static str, window_secs: usize, max_requests: u32) -> Self {
        Self {
            key,
            window_secs,
            max_requests,
        }
    }
}

impl RateLimited for SimpleRateLimit {
    fn remaining_requests(&self, remote_ip: &IpAddr, redis: &mut RedisConn) -> Result<u32> {
        let key = format!("{}:{}", self.key, remote_ip);

        dbg!(&key);

        let request_count: u32 = redis.incr(&key, 1)?;
        redis.expire(&key, self.window_secs)?;

        if request_count > self.max_requests {
            Err(Error::RateLimitExceeded { retry_after: None })
        } else {
            Ok(self.max_requests - request_count)
        }
    }
}
