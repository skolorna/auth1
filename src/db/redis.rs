use std::env;

use r2d2_redis::RedisConnectionManager;

pub type RedisPool = r2d2::Pool<RedisConnectionManager>;

pub fn initialize_redis_pool(redis_url: &str) -> RedisPool {
    eprintln!("Initializing Redis pool");
    let manager = RedisConnectionManager::new(redis_url).unwrap();
    let pool = r2d2::Pool::builder().build(manager).unwrap();

    eprintln!("Redis pool initialized!");

    pool
}

pub fn redis_pool_from_env() -> RedisPool {
    let redis_url = env::var("REDIS_URL").expect("REDIS_URL is not set");

    initialize_redis_pool(&redis_url)
}
