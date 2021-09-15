use std::{env, sync::Mutex};

use diesel::{r2d2::ConnectionManager, PgConnection};
use once_cell::sync::Lazy;

pub type PgPool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type PgConn = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

/// Parallel migrations don't work that well. This is mostly for test environments.
static MIGRATION_MUTEX: Lazy<Mutex<()>> = Lazy::new(Mutex::default);

/// Create a database pool and run the necessary migrations.
pub fn initialize_pg_pool(database_url: &str) -> PgPool {
    let _shared = MIGRATION_MUTEX.lock().expect("failed to acquire lock");

    embed_migrations!();

    eprintln!("Connecting to Postgres");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("failed to create pool");

    eprintln!("Running migrations");
    let conn = pool.get().expect("failed to get connection");
    embedded_migrations::run_with_output(&conn, &mut std::io::stderr()).expect("migrations failed");
    println!("Database initialized!");

    pool
}

pub fn pg_pool_from_env() -> PgPool {
    let db_url = env::var("POSTGRES_URL").expect("POSTGRES_URL is not set");

    initialize_pg_pool(&db_url)
}

pub fn pg_test_pool() -> PgPool {
    dotenv::dotenv().ok();
    pg_pool_from_env()
}

pub fn pg_test_conn() -> PgConn {
    let pool = pg_test_pool();
    pool.get().unwrap()
}
