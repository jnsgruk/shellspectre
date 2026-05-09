//! Database connection pool setup.

use std::path::Path;

use anyhow::{Context, Result};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OpenFlags;

/// Type alias for the connection pool.
pub type DbPool = Pool<SqliteConnectionManager>;

/// Create a read-only connection pool to an existing SQLite database.
///
/// The database must already exist and have the oxilog schema.
/// This function does NOT create tables.
///
/// # Errors
///
/// Returns an error if the database file doesn't exist or the pool
/// cannot be created.
pub fn create_pool(db_path: &str) -> Result<DbPool> {
    anyhow::ensure!(
        Path::new(db_path).exists(),
        "database file not found: {db_path}"
    );

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
        conn.execute_batch(TEST_SCHEMA)
            .context("failed to create test schema")?;
    }

    Ok(pool)
}

/// Schema for tests — duplicated from `oxilog/src/sqlite_sink.rs`.
/// We duplicate rather than depend on the oxilog crate because the web
/// crate must not depend on the eBPF-loading binary crate.
#[doc(hidden)]
pub const TEST_SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    started_at  TEXT NOT NULL,
    ended_at    TEXT,
    root_pid    INTEGER NOT NULL,
    root_comm   TEXT,
    uid         INTEGER NOT NULL,
    euid        INTEGER NOT NULL,
    tty_nr      INTEGER,
    cgroup_id   INTEGER
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL REFERENCES sessions(id),
    event_type  TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    pid         INTEGER NOT NULL,
    ppid        INTEGER NOT NULL,
    uid         INTEGER NOT NULL,
    gid         INTEGER NOT NULL,
    euid        INTEGER NOT NULL,
    comm        TEXT,
    tty_nr      INTEGER,
    filename    TEXT,
    argv        TEXT,
    fd          INTEGER,
    data        TEXT,
    data_len    INTEGER,
    byte_count  INTEGER,
    exit_code   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(session_id, event_type);
";
