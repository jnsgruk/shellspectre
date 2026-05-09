//! Database connection pool setup.

use std::path::Path;

use anyhow::{Context, Result};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OpenFlags;

/// Type alias for the connection pool.
pub type DbPool = Pool<SqliteConnectionManager>;

/// Create a read-only connection pool to a SQLite database.
///
/// Returns an error if the database file is missing or cannot be opened.
pub fn create_pool(db_path: &str) -> Result<DbPool> {
    if !Path::new(db_path).exists() {
        anyhow::bail!(
            "database not found at {db_path}; the collector must create it before starting shspectr-web"
        );
    }

    let manager = SqliteConnectionManager::file(db_path)
        .with_flags(OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX);

    let pool = Pool::builder()
        .max_size(4)
        .build(manager)
        .context("failed to create SQLite connection pool")?;

    // Verify the schema exists by checking for the events table.
    {
        let conn = pool.get().context("failed to get connection from pool")?;
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='events'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .context("failed to verify schema")?;
    }

    Ok(pool)
}

/// Create an in-memory pool for testing. Initializes the schema.
///
/// Uses a single connection (in-memory DBs are per-connection).
#[doc(hidden)]
pub fn create_test_pool() -> Result<DbPool> {
    let manager = SqliteConnectionManager::memory();

    let pool = Pool::builder()
        .max_size(1)
        .build(manager)
        .context("failed to create test pool")?;

    {
        let conn = pool.get().context("failed to get test connection")?;
        init_schema(&conn)?;
    }

    Ok(pool)
}

/// Additional index needed by the web crate's ppid queries.
const EXTRA_SCHEMA: &str = "CREATE INDEX IF NOT EXISTS idx_events_ppid ON events(ppid);";

/// Initialize the database schema (base + web-specific indexes).
fn init_schema(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(shspectr_common::SCHEMA)
        .context("failed to initialize database schema")?;
    conn.execute_batch(EXTRA_SCHEMA)
        .context("failed to create extra indexes")?;
    Ok(())
}
