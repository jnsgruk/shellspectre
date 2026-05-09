/// SQL schema for the sessions and events tables. Shared between the
/// CLI writer (`shspectr`) and the web reader (`shspectr-web`).
pub const SCHEMA: &str = r"
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
    event_type  INTEGER NOT NULL,
    timestamp   TEXT NOT NULL,
    pid         INTEGER NOT NULL,
    ppid        INTEGER NOT NULL,
    uid         INTEGER NOT NULL,
    gid         INTEGER NOT NULL,
    euid        INTEGER NOT NULL,
    comm        TEXT,
    tty_nr      INTEGER,
    execution_id INTEGER NOT NULL DEFAULT 0,
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
CREATE INDEX IF NOT EXISTS idx_events_execution ON events(session_id, pid, execution_id, event_type, id);
";
