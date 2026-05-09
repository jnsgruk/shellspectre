//! SQLite sink: stores session events in a local SQLite database.
//!
//! Schema follows the spec in `docs/01-spec.md`. Sessions are created on
//! first event and updated on last exit. Events are inserted as they arrive.

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::event::{ParsedExecEvent, ParsedExitEvent, ParsedIoEvent};

/// Info needed to create a session row.
pub struct SessionInfo<'a> {
    pub session_id: &'a str,
    pub pid: u32,
    pub comm: &'a str,
    pub uid: u32,
    pub euid: u32,
    pub tty_nr: u32,
    pub cgroup_id: u64,
}

/// A SQLite event sink.
pub struct SqliteSink {
    conn: Connection,
}

impl SqliteSink {
    /// Open (or create) a SQLite database at the given path and initialize
    /// the schema.
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).context("open SQLite database")?;
        conn.execute_batch(shspectr_common::SCHEMA)
            .context("create SQLite schema")?;
        ensure_schema_compat(&conn)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .context("set SQLite pragmas")?;
        Ok(Self { conn })
    }

    /// Open an in-memory database (for testing).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("open in-memory SQLite")?;
        conn.execute_batch(shspectr_common::SCHEMA)
            .context("create SQLite schema")?;
        ensure_schema_compat(&conn)?;
        Ok(Self { conn })
    }

    /// Ensure a session row exists. Creates it on first call for a given
    /// session_id.
    pub fn ensure_session(&self, info: &SessionInfo<'_>) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT OR IGNORE INTO sessions (id, started_at, root_pid, root_comm, uid, euid, tty_nr, cgroup_id)
                 VALUES (?1, datetime('now'), ?2, ?3, ?4, ?5, ?6, ?7)",
            )?
            .execute(rusqlite::params![
                info.session_id,
                info.pid,
                info.comm,
                info.uid,
                info.euid,
                info.tty_nr,
                i64::try_from(info.cgroup_id).unwrap_or(i64::MAX)
            ])
            .context("insert session")?;
        Ok(())
    }

    /// Record an exec event.
    pub fn insert_exec(&self, session_id: &str, event: &ParsedExecEvent) -> Result<()> {
        let argv_json = serde_json::to_string(&event.argv).unwrap_or_default();
        self.conn
            .prepare_cached(
                "INSERT INTO events (session_id, event_type, timestamp, pid, ppid, uid, gid, euid, comm, tty_nr, execution_id, filename, argv)
                 VALUES (?1, 'exec', datetime('now'), ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )?
            .execute(
                rusqlite::params![
                    session_id,
                    event.pid,
                    event.ppid,
                    event.uid,
                    event.gid,
                    event.euid,
                    event.comm,
                    event.tty_nr,
                    i64::try_from(event.execution_id).unwrap_or(i64::MAX),
                    event.filename,
                    argv_json,
                ],
            )
            .context("insert exec event")?;
        Ok(())
    }

    /// Record an exit event and optionally close the session.
    pub fn insert_exit(
        &self,
        session_id: &str,
        event: &ParsedExitEvent,
        session_complete: bool,
    ) -> Result<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO events (session_id, event_type, timestamp, pid, ppid, uid, gid, euid, comm, tty_nr, execution_id, exit_code)
                 VALUES (?1, 'exit', datetime('now'), ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?
            .execute(
                rusqlite::params![
                    session_id,
                    event.pid,
                    event.ppid,
                    event.uid,
                    event.gid,
                    event.euid,
                    event.comm,
                    event.tty_nr,
                    i64::try_from(event.execution_id).unwrap_or(i64::MAX),
                    event.exit_code,
                ],
            )
            .context("insert exit event")?;

        // Backfill exit_code onto the most recent exec row for this pid,
        // so the web UI can read it without joining the exit row.
        self.conn
            .prepare_cached(
                "UPDATE events SET exit_code = ?1 \
                 WHERE id = ( \
                     SELECT id FROM events \
                     WHERE session_id = ?2 AND pid = ?3 AND execution_id = ?4 AND event_type = 'exec' \
                     ORDER BY id DESC LIMIT 1 \
                  )",
            )?
            .execute(rusqlite::params![
                event.exit_code,
                session_id,
                event.pid,
                i64::try_from(event.execution_id).unwrap_or(i64::MAX)
            ])
            .context("backfill exit_code onto exec row")?;

        if session_complete {
            self.conn
                .prepare_cached("UPDATE sessions SET ended_at = datetime('now') WHERE id = ?1")?
                .execute(rusqlite::params![session_id])
                .context("update session ended_at")?;
        }
        Ok(())
    }

    /// Record an I/O event.
    pub fn insert_io(
        &self,
        session_id: &str,
        event: &ParsedIoEvent,
        event_type: &str,
    ) -> Result<()> {
        let data_str = String::from_utf8_lossy(&event.data);
        self.conn
            .prepare_cached(
                "INSERT INTO events (session_id, event_type, timestamp, pid, ppid, uid, gid, euid, comm, tty_nr, execution_id, fd, data, data_len, byte_count)
                 VALUES (?1, ?2, datetime('now'), ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            )?
            .execute(
                rusqlite::params![
                    session_id,
                    event_type,
                    event.pid,
                    event.ppid,
                    event.uid,
                    event.gid,
                    event.euid,
                    event.comm,
                    event.tty_nr,
                    i64::try_from(event.execution_id).unwrap_or(i64::MAX),
                    event.fd,
                    data_str.as_ref(),
                    i64::try_from(event.data.len()).unwrap_or(i64::MAX),
                    i64::try_from(event.count).unwrap_or(i64::MAX),
                ],
            )
            .context("insert io event")?;
        Ok(())
    }
}

fn ensure_schema_compat(conn: &Connection) -> Result<()> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(events)")
        .context("inspect events schema")?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("read events schema")?;
    if !columns.iter().any(|column| column == "execution_id") {
        conn.execute(
            "ALTER TABLE events ADD COLUMN execution_id INTEGER NOT NULL DEFAULT 0",
            [],
        )
        .context("add execution_id column")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SessionInfoBuilder<'a> {
        session_id: &'a str,
        pid: u32,
        comm: &'a str,
        uid: u32,
        euid: u32,
        tty_nr: u32,
        cgroup_id: u64,
    }

    #[allow(dead_code)]
    impl<'a> SessionInfoBuilder<'a> {
        fn new(session_id: &'a str) -> Self {
            Self {
                session_id,
                pid: 100,
                comm: "bash",
                uid: 1000,
                euid: 1000,
                tty_nr: 42,
                cgroup_id: 99,
            }
        }

        fn pid(mut self, v: u32) -> Self {
            self.pid = v;
            self
        }
        fn comm(mut self, v: &'a str) -> Self {
            self.comm = v;
            self
        }
        fn uid(mut self, v: u32) -> Self {
            self.uid = v;
            self
        }
        fn euid(mut self, v: u32) -> Self {
            self.euid = v;
            self
        }
        fn tty_nr(mut self, v: u32) -> Self {
            self.tty_nr = v;
            self
        }
        fn cgroup_id(mut self, v: u64) -> Self {
            self.cgroup_id = v;
            self
        }

        fn build(self) -> SessionInfo<'a> {
            SessionInfo {
                session_id: self.session_id,
                pid: self.pid,
                comm: self.comm,
                uid: self.uid,
                euid: self.euid,
                tty_nr: self.tty_nr,
                cgroup_id: self.cgroup_id,
            }
        }
    }

    struct ParsedExecEventBuilder {
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        euid: u32,
        comm: String,
        tty_nr: u32,
        cgroup_id: u64,
        execution_id: u64,
        filename: String,
        argv: Vec<String>,
        retval: i64,
    }

    #[allow(dead_code)]
    impl ParsedExecEventBuilder {
        fn new() -> Self {
            Self {
                pid: 100,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                euid: 1000,
                comm: "ls".into(),
                tty_nr: 42,
                cgroup_id: 99,
                execution_id: 500,
                filename: "/usr/bin/ls".into(),
                argv: vec!["ls".into(), "-la".into()],
                retval: 0,
            }
        }

        fn pid(mut self, v: u32) -> Self {
            self.pid = v;
            self
        }
        fn ppid(mut self, v: u32) -> Self {
            self.ppid = v;
            self
        }
        fn uid(mut self, v: u32) -> Self {
            self.uid = v;
            self
        }
        fn gid(mut self, v: u32) -> Self {
            self.gid = v;
            self
        }
        fn euid(mut self, v: u32) -> Self {
            self.euid = v;
            self
        }
        fn comm(mut self, v: &str) -> Self {
            self.comm = v.into();
            self
        }
        fn tty_nr(mut self, v: u32) -> Self {
            self.tty_nr = v;
            self
        }
        fn cgroup_id(mut self, v: u64) -> Self {
            self.cgroup_id = v;
            self
        }
        fn execution_id(mut self, v: u64) -> Self {
            self.execution_id = v;
            self
        }
        fn filename(mut self, v: &str) -> Self {
            self.filename = v.into();
            self
        }
        fn argv(mut self, v: Vec<&str>) -> Self {
            self.argv = v.into_iter().map(Into::into).collect();
            self
        }
        fn retval(mut self, v: i64) -> Self {
            self.retval = v;
            self
        }

        fn build(self) -> ParsedExecEvent {
            ParsedExecEvent {
                pid: self.pid,
                ppid: self.ppid,
                uid: self.uid,
                gid: self.gid,
                euid: self.euid,
                comm: self.comm,
                tty_nr: self.tty_nr,
                cgroup_id: self.cgroup_id,
                execution_id: self.execution_id,
                filename: self.filename,
                argv: self.argv,
                retval: self.retval,
            }
        }
    }

    struct ParsedExitEventBuilder {
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        euid: u32,
        comm: String,
        tty_nr: u32,
        cgroup_id: u64,
        execution_id: u64,
        exit_code: i32,
    }

    #[allow(dead_code)]
    impl ParsedExitEventBuilder {
        fn new() -> Self {
            Self {
                pid: 100,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                euid: 1000,
                comm: "ls".into(),
                tty_nr: 42,
                cgroup_id: 99,
                execution_id: 500,
                exit_code: 0,
            }
        }

        fn pid(mut self, v: u32) -> Self {
            self.pid = v;
            self
        }
        fn ppid(mut self, v: u32) -> Self {
            self.ppid = v;
            self
        }
        fn uid(mut self, v: u32) -> Self {
            self.uid = v;
            self
        }
        fn gid(mut self, v: u32) -> Self {
            self.gid = v;
            self
        }
        fn euid(mut self, v: u32) -> Self {
            self.euid = v;
            self
        }
        fn comm(mut self, v: &str) -> Self {
            self.comm = v.into();
            self
        }
        fn tty_nr(mut self, v: u32) -> Self {
            self.tty_nr = v;
            self
        }
        fn cgroup_id(mut self, v: u64) -> Self {
            self.cgroup_id = v;
            self
        }
        fn execution_id(mut self, v: u64) -> Self {
            self.execution_id = v;
            self
        }
        fn exit_code(mut self, v: i32) -> Self {
            self.exit_code = v;
            self
        }

        fn build(self) -> ParsedExitEvent {
            ParsedExitEvent {
                pid: self.pid,
                ppid: self.ppid,
                uid: self.uid,
                gid: self.gid,
                euid: self.euid,
                comm: self.comm,
                tty_nr: self.tty_nr,
                cgroup_id: self.cgroup_id,
                execution_id: self.execution_id,
                exit_code: self.exit_code,
            }
        }
    }

    #[test]
    fn schema_creation() -> Result<()> {
        let sink = SqliteSink::open_in_memory()?;
        // Verify tables exist by querying them.
        let count: i64 = sink
            .conn
            .query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))?;
        assert_eq!(count, 0);
        let count: i64 = sink
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        assert_eq!(count, 0);
        Ok(())
    }

    #[test]
    fn ensure_session_creates_row() -> Result<()> {
        let sink = SqliteSink::open_in_memory()?;
        sink.ensure_session(&SessionInfoBuilder::new("ox_test1234").build())?;

        let (id, root_pid, uid): (String, i64, i64) = sink.conn.query_row(
            "SELECT id, root_pid, uid FROM sessions WHERE id = ?1",
            ["ox_test1234"],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        assert_eq!(id, "ox_test1234");
        assert_eq!(root_pid, 100);
        assert_eq!(uid, 1000);
        Ok(())
    }

    #[test]
    fn ensure_session_idempotent() -> Result<()> {
        let sink = SqliteSink::open_in_memory()?;
        sink.ensure_session(&SessionInfoBuilder::new("ox_test1234").build())?;
        sink.ensure_session(
            &SessionInfoBuilder::new("ox_test1234")
                .pid(200)
                .comm("zsh")
                .uid(2000)
                .euid(2000)
                .tty_nr(0)
                .cgroup_id(0)
                .build(),
        )?;

        // Should still have original values (INSERT OR IGNORE).
        let root_pid: i64 = sink.conn.query_row(
            "SELECT root_pid FROM sessions WHERE id = ?1",
            ["ox_test1234"],
            |r| r.get(0),
        )?;
        assert_eq!(root_pid, 100);
        Ok(())
    }

    #[test]
    fn insert_exec_event() -> Result<()> {
        let sink = SqliteSink::open_in_memory()?;
        sink.ensure_session(&SessionInfoBuilder::new("ox_abc").build())?;
        sink.insert_exec("ox_abc", &ParsedExecEventBuilder::new().build())?;

        let (event_type, pid, execution_id, filename): (String, i64, i64, String) =
            sink.conn.query_row(
                "SELECT event_type, pid, execution_id, filename FROM events WHERE session_id = ?1",
                ["ox_abc"],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
        assert_eq!(event_type, "exec");
        assert_eq!(pid, 100);
        assert_eq!(execution_id, 500);
        assert_eq!(filename, "/usr/bin/ls");
        Ok(())
    }

    #[test]
    fn insert_exit_only_closes_session_when_requested() -> Result<()> {
        let sink = SqliteSink::open_in_memory()?;
        sink.ensure_session(&SessionInfoBuilder::new("ox_abc").build())?;
        sink.insert_exit(
            "ox_abc",
            &ParsedExitEventBuilder::new()
                .comm("bash")
                .exit_code(0)
                .build(),
            false,
        )?;

        let ended_at: Option<String> = sink.conn.query_row(
            "SELECT ended_at FROM sessions WHERE id = ?1",
            ["ox_abc"],
            |r| r.get(0),
        )?;
        assert!(
            ended_at.is_none(),
            "ended_at should remain unset until session completion"
        );

        sink.insert_exit(
            "ox_abc",
            &ParsedExitEventBuilder::new()
                .pid(101)
                .execution_id(501)
                .exit_code(0)
                .build(),
            true,
        )?;
        let ended_at: Option<String> = sink.conn.query_row(
            "SELECT ended_at FROM sessions WHERE id = ?1",
            ["ox_abc"],
            |r| r.get(0),
        )?;
        assert!(ended_at.is_some(), "ended_at should be set on final exit");
        Ok(())
    }

    #[test]
    fn insert_io_event() -> Result<()> {
        let sink = SqliteSink::open_in_memory()?;
        sink.ensure_session(&SessionInfoBuilder::new("ox_abc").build())?;

        let io = ParsedIoEvent {
            pid: 100,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            euid: 1000,
            comm: "echo".into(),
            tty_nr: 42,
            cgroup_id: 99,
            execution_id: 500,
            fd: 1,
            data: b"hello world\n".to_vec(),
            count: 12,
        };
        sink.insert_io("ox_abc", &io, "write")?;

        let (event_type, execution_id, fd, data): (String, i64, i64, String) =
            sink.conn.query_row(
                "SELECT event_type, execution_id, fd, data FROM events WHERE session_id = ?1",
                ["ox_abc"],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
        assert_eq!(event_type, "write");
        assert_eq!(execution_id, 500);
        assert_eq!(fd, 1);
        assert_eq!(data, "hello world\n");
        Ok(())
    }

    #[test]
    fn insert_exit_backfills_exit_code_on_exec_row() -> Result<()> {
        let sink = SqliteSink::open_in_memory()?;
        sink.ensure_session(&SessionInfoBuilder::new("ox_abc").build())?;
        sink.insert_exec("ox_abc", &ParsedExecEventBuilder::new().build())?;
        sink.insert_exit(
            "ox_abc",
            &ParsedExitEventBuilder::new().exit_code(42).build(),
            true,
        )?;

        // The exec row for pid 100 must now have exit_code = 42.
        let exit_code: Option<i64> = sink.conn.query_row(
            "SELECT exit_code FROM events WHERE session_id = ?1 AND event_type = 'exec' AND pid = ?2",
            rusqlite::params!["ox_abc", 100i64],
            |r| r.get(0),
        )?;
        assert_eq!(
            exit_code,
            Some(42),
            "exec row should have exit_code backfilled"
        );
        Ok(())
    }

    #[test]
    fn query_events_by_session_and_type() -> Result<()> {
        let sink = SqliteSink::open_in_memory()?;
        sink.ensure_session(&SessionInfoBuilder::new("ox_abc").build())?;
        sink.insert_exec("ox_abc", &ParsedExecEventBuilder::new().build())?;
        sink.insert_exit(
            "ox_abc",
            &ParsedExitEventBuilder::new().exit_code(0).build(),
            true,
        )?;

        // Query using the index.
        let count: i64 = sink.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE session_id = ?1 AND event_type = ?2",
            rusqlite::params!["ox_abc", "exec"],
            |r| r.get(0),
        )?;
        assert_eq!(count, 1);

        let total: i64 = sink.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE session_id = ?1",
            ["ox_abc"],
            |r| r.get(0),
        )?;
        assert_eq!(total, 2);
        Ok(())
    }

    #[test]
    fn insert_exit_backfills_matching_execution_only() -> Result<()> {
        let sink = SqliteSink::open_in_memory()?;
        sink.ensure_session(&SessionInfoBuilder::new("ox_abc").build())?;
        sink.insert_exec(
            "ox_abc",
            &ParsedExecEventBuilder::new()
                .pid(100)
                .execution_id(10)
                .build(),
        )?;
        sink.insert_exec(
            "ox_abc",
            &ParsedExecEventBuilder::new()
                .pid(100)
                .execution_id(11)
                .build(),
        )?;

        sink.insert_exit(
            "ox_abc",
            &ParsedExitEventBuilder::new()
                .pid(100)
                .execution_id(10)
                .exit_code(7)
                .build(),
            false,
        )?;

        let exit_codes: Vec<(i64, Option<i64>)> = {
            let mut stmt = sink.conn.prepare(
                "SELECT execution_id, exit_code FROM events WHERE session_id = ?1 AND event_type = 'exec' ORDER BY execution_id ASC",
            )?;
            stmt.query_map(["ox_abc"], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        assert_eq!(exit_codes, vec![(10, Some(7)), (11, None)]);
        Ok(())
    }
}
