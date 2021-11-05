use std::env;

use dotenv::dotenv;
use r2d2_redis::RedisConnectionManager;
use structopt::StructOpt;

use crate::util::FromOpt;

use super::DbPool;

pub type RedisPool = r2d2::Pool<RedisConnectionManager>;
pub type RedisConn = r2d2::PooledConnection<RedisConnectionManager>;

const REDIS_URL_ENV: &str = "REDIS_URL";

#[derive(Debug, StructOpt)]
pub struct RedisOpt {
    #[structopt(long, env = REDIS_URL_ENV)]
    redis_url: String,
}

impl DbPool for RedisPool {
    fn initialize(url: &str) -> Self {
        eprintln!("Initializing Redis pool");
        let manager = RedisConnectionManager::new(url).unwrap();
        let pool = r2d2::Pool::builder().build(manager).unwrap();

        eprintln!("Redis pool initialized!");

        pool
    }

    fn for_tests() -> Self {
        dotenv().ok();
        Self::initialize(&env::var(REDIS_URL_ENV).unwrap())
    }
}

impl FromOpt for RedisPool {
    type Opt = RedisOpt;

    fn from_opt(opt: Self::Opt) -> Self {
        Self::initialize(&opt.redis_url)
    }
}
