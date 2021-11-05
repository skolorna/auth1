use std::sync::Mutex;

use diesel::{r2d2::ConnectionManager, PgConnection};
use dotenv::dotenv;
use once_cell::sync::Lazy;
use structopt::StructOpt;

use crate::util::FromOpt;

use super::DbPool;

pub type PgPool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type PgConn = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

/// Parallel migrations don't work that well. This is mostly for test environments.
static MIGRATION_MUTEX: Lazy<Mutex<()>> = Lazy::new(Mutex::default);

impl DbPool for PgPool {
    /// Create a PostgreSQL pool and run the necessary migrations.
    fn initialize(url: &str) -> Self {
        embed_migrations!();

        eprintln!("Connecting to Postgres");
        let manager = ConnectionManager::<PgConnection>::new(url);
        let pool = r2d2::Pool::builder()
            .build(manager)
            .expect("failed to create pool");

        let _shared = MIGRATION_MUTEX.lock().expect("failed to acquire lock");

        eprintln!("Running migrations");
        let conn = pool.get().expect("failed to get connection");
        embedded_migrations::run_with_output(&conn, &mut std::io::stderr())
            .expect("migrations failed");
        println!("Database initialized!");

        pool
    }

    fn for_tests() -> Self {
        dotenv().ok();
        PgPool::from_opt(PgOpt::from_args())
    }
}

#[derive(Debug, StructOpt)]
pub struct PgOpt {
    #[structopt(long, env, hide_env_values = true)]
    pub postgres_url: String,
}

impl FromOpt for PgPool {
    type Opt = PgOpt;

    fn from_opt(opt: Self::Opt) -> Self {
        PgPool::initialize(&opt.postgres_url)
    }
}
