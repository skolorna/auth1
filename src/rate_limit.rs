use std::{
    ops::DerefMut,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use r2d2_redis::redis;

use crate::{
    db::redis::RedisConn,
    result::{Error, Result},
};

pub trait RateLimit {
    /// Get the number of remaining requests, and fail if the quota has been exceeded.
    fn remaining_requests(&self, client: &str, redis: &mut RedisConn) -> Result<u64>;
}

pub struct SlidingWindow {
    key_prefix: &'static str,
    window_secs: u64,
    max_requests: u64,
}

impl SlidingWindow {
    pub const fn new(key_prefix: &'static str, window_secs: u64, max_requests: u64) -> Self {
        Self {
            key_prefix,
            window_secs,
            max_requests,
        }
    }

    fn window_id(&self, ts: Duration) -> u64 {
        ts.as_secs() / self.window_secs
    }

    fn key(&self, client: &str, window_id: u64) -> String {
        format!("{}:{}:{}", self.key_prefix, client, window_id)
    }

    fn count(&self, previous: Option<u64>, current: Option<u64>, now: Duration) -> u64 {
        let weight = (now.as_secs_f64() / (self.window_secs as f64)).fract();

        current.unwrap_or(0) + (previous.unwrap_or(0) as f64 * weight).round() as u64
    }

    fn record(&self, client: &str, conn: &mut RedisConn) -> Result<u64> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let current_window = self.window_id(now);
        let current_key = self.key(client, self.window_id(now));
        let previous_key = self.key(client, current_window - 1);

        let (previous_count, current_count): (Option<u64>, Option<u64>) = redis::pipe()
            .atomic()
            .get(&previous_key)
            .incr(&current_key, 1)
            .expire(&current_key, (self.window_secs * 2) as usize)
            .ignore()
            .query(conn.deref_mut())?;

        Ok(self.count(previous_count, current_count, now))
    }
}

impl RateLimit for SlidingWindow {
    fn remaining_requests(&self, client: &str, redis: &mut RedisConn) -> Result<u64> {
        let count = self.record(client, redis)?;

        if count > self.max_requests {
            Err(Error::RateLimitExceeded { retry_after: None })
        } else {
            Ok(self.max_requests - count)
        }
    }
}
