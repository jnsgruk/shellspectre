//! SQLite implementation of the `EventRepository` trait.

use anyhow::{Context, Result};
use rusqlite::{params, OptionalExtension};

use crate::domain::event::{EventDetail, EventFilter, EventSummary, IoChunk};
use crate::domain::listing::{ListRequest, Page};
use crate::domain::repositories::EventRepository;
use crate::infrastructure::database::DbPool;

/// SQLite-backed event repository (read-only).
pub struct SqlEventRepository {
    pool: DbPool,
}

impl SqlEventRepository {
    /// Create a new repository backed by the given connection pool.
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

/// Build a WHERE clause and positional parameters from a filter.
fn build_where_clause(filter: &EventFilter) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    // Default to exec events only in list view.
    conditions.push("event_type = 'exec'".to_owned());

    if let Some(ref comm) = filter.comm {
        let like_pattern = comm.replace('*', "%").replace('?', "_");
        conditions.push(format!("comm LIKE ?{}", params.len() + 1));
        params.push(Box::new(like_pattern));
    }

    if let Some(exit_code) = filter.exit_code {
        conditions.push(format!("exit_code = ?{}", params.len() + 1));
        params.push(Box::new(exit_code));
    }

    if let Some(ref session_id) = filter.session_id {
        conditions.push(format!("session_id LIKE ?{}", params.len() + 1));
        params.push(Box::new(format!("{session_id}%")));
    }

    if let Some(pid) = filter.pid {
        conditions.push(format!("pid = ?{}", params.len() + 1));
        params.push(Box::new(pid));
    }

    if let Some(ref uid_name) = filter.user
        && let Ok(uid) = uid_name.parse::<u32>()
    {
        conditions.push(format!("uid = ?{}", params.len() + 1));
        params.push(Box::new(uid));
    }

    if let Some(ref text) = filter.text {
        let idx = params.len() + 1;
        conditions.push(format!(
            "(comm LIKE ?{idx} OR filename LIKE ?{idx} OR argv LIKE ?{idx})"
        ));
        params.push(Box::new(format!("%{text}%")));
    }

    let clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    (clause, params)
}

/// Map a row to an `EventSummary`.
fn row_to_summary(row: &rusqlite::Row<'_>) -> rusqlite::Result<EventSummary> {
    Ok(EventSummary {
        id: row.get(0)?,
        timestamp: row.get(1)?,
        session_id: row.get(2)?,
        event_type: row.get(3)?,
        pid: row.get(4)?,
        ppid: row.get(5)?,
        uid: row.get(6)?,
        euid: row.get(7)?,
        comm: row.get(8)?,
        filename: row.get(9)?,
        argv: row.get(10)?,
        exit_code: row.get(11)?,
    })
}

/// Fetch I/O chunks for a given session + PID and populate the detail.
fn fetch_io_chunks(
    conn: &rusqlite::Connection,
    detail: &mut EventDetail,
) -> Result<()> {
    let mut io_stmt = conn
        .prepare(
            "SELECT timestamp, fd, data, byte_count \
             FROM events \
             WHERE session_id = ?1 AND pid = ?2 \
               AND event_type IN ('read', 'write') \
             ORDER BY id ASC",
        )
        .context("failed to prepare I/O query")?;

    let io_rows = io_stmt
        .query_map(
            params![detail.summary.session_id, detail.summary.pid],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<u32>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<u64>>(3)?,
                ))
            },
        )
        .context("failed to query I/O events")?;

    for row in io_rows {
        let (timestamp, fd, data, byte_count) = row.context("failed to map I/O row")?;
        let chunk = IoChunk {
            timestamp,
            data: data.unwrap_or_default(),
            byte_count: byte_count.unwrap_or(0),
        };
        match fd {
            Some(0) => detail.stdin_data.push(chunk),
            Some(1 | 2) => detail.stdout_data.push(chunk),
            _ => {} // Ignore other FDs
        }
    }

    Ok(())
}

impl EventRepository for SqlEventRepository {
    fn list(&self, req: &ListRequest, filter: &EventFilter) -> Result<Page<EventSummary>> {
        let conn = self.pool.get().context("failed to get DB connection")?;

        let (where_clause, param_values) = build_where_clause(filter);

        // Count total matching items.
        let count_sql = format!("SELECT COUNT(*) FROM events {where_clause}");
        let total_items: u64 = conn
            .query_row(
                &count_sql,
                rusqlite::params_from_iter(param_values.iter().map(AsRef::as_ref)),
                |row| row.get(0),
            )
            .context("failed to count events")?;

        // Fetch page of items.
        let order_col = req.sort.as_sql_column();
        let order_dir = req.direction.as_sql();

        let select_sql = format!(
            "SELECT id, timestamp, session_id, event_type, pid, ppid, uid, euid, \
                    comm, filename, argv, exit_code \
             FROM events {where_clause} \
             ORDER BY {order_col} {order_dir}, id DESC \
             LIMIT ?{limit_idx} OFFSET ?{offset_idx}",
            limit_idx = param_values.len() + 1,
            offset_idx = param_values.len() + 2,
        );

        let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> =
            param_values.into_iter().collect();
        all_params.push(Box::new(req.page_size));
        all_params.push(Box::new(req.offset()));

        let mut stmt = conn
            .prepare(&select_sql)
            .context("failed to prepare query")?;
        let items = stmt
            .query_map(
                rusqlite::params_from_iter(all_params.iter().map(AsRef::as_ref)),
                row_to_summary,
            )
            .context("failed to query events")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to map event rows")?;

        Ok(Page {
            items,
            page: req.page,
            page_size: req.page_size,
            total_items,
        })
    }

    fn get_detail(&self, id: i64) -> Result<Option<EventDetail>> {
        let conn = self.pool.get().context("failed to get DB connection")?;

        let mut stmt = conn
            .prepare(
                "SELECT id, timestamp, session_id, event_type, pid, ppid, uid, gid, euid, \
                        comm, filename, argv, exit_code, tty_nr, fd, data, data_len, byte_count \
                 FROM events WHERE id = ?1",
            )
            .context("failed to prepare detail query")?;

        let result = stmt
            .query_row(params![id], |row| {
                let summary = EventSummary {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    session_id: row.get(2)?,
                    event_type: row.get(3)?,
                    pid: row.get(4)?,
                    ppid: row.get(5)?,
                    uid: row.get(6)?,
                    euid: row.get(8)?,
                    comm: row.get(9)?,
                    filename: row.get(10)?,
                    argv: row.get(11)?,
                    exit_code: row.get(12)?,
                };
                Ok(EventDetail {
                    gid: row.get(7)?,
                    tty_nr: row.get(13)?,
                    fd: row.get(14)?,
                    data: row.get(15)?,
                    data_len: row.get(16)?,
                    byte_count: row.get(17)?,
                    summary,
                    stdin_data: Vec::new(),
                    stdout_data: Vec::new(),
                })
            })
            .optional()
            .context("failed to query event detail")?;

        let Some(mut detail) = result else {
            return Ok(None);
        };

        fetch_io_chunks(&conn, &mut detail)?;

        Ok(Some(detail))
    }

    fn list_since(&self, after_id: i64, filter: &EventFilter) -> Result<Vec<EventSummary>> {
        let conn = self.pool.get().context("failed to get DB connection")?;

        let (where_clause, mut param_values) = build_where_clause(filter);

        // Add the `id > after_id` condition.
        let id_condition = format!("id > ?{}", param_values.len() + 1);
        param_values.push(Box::new(after_id));

        // Combine: the existing where_clause already starts with "WHERE ..."
        // so we append with AND.
        let full_where = if where_clause.is_empty() {
            format!("WHERE {id_condition}")
        } else {
            format!("{where_clause} AND {id_condition}")
        };

        let sql = format!(
            "SELECT id, timestamp, session_id, event_type, pid, ppid, uid, euid, \
                    comm, filename, argv, exit_code \
             FROM events {full_where} \
             ORDER BY id ASC \
             LIMIT 100"
        );

        let mut stmt = conn.prepare(&sql).context("failed to prepare list_since query")?;
        let items = stmt
            .query_map(
                rusqlite::params_from_iter(param_values.iter().map(AsRef::as_ref)),
                row_to_summary,
            )
            .context("failed to query events since")?
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to map event rows")?;

        Ok(items)
    }

    fn max_event_id(&self) -> Result<i64> {
        let conn = self.pool.get().context("failed to get DB connection")?;
        let max_id: i64 = conn
            .query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |row| {
                row.get(0)
            })
            .context("failed to query max event id")?;
        Ok(max_id)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::infrastructure::database::create_test_pool;

    fn insert_test_session(conn: &rusqlite::Connection, id: &str) {
        conn.execute(
            "INSERT INTO sessions (id, started_at, root_pid, uid, euid) \
             VALUES (?1, datetime('now'), 100, 1000, 1000)",
            params![id],
        )
        .expect("insert test session");
    }

    fn insert_test_exec(
        conn: &rusqlite::Connection,
        session_id: &str,
        pid: u32,
        comm: &str,
        filename: &str,
        argv: &str,
        exit_code: Option<i32>,
    ) {
        conn.execute(
            "INSERT INTO events \
             (session_id, event_type, timestamp, pid, ppid, uid, gid, euid, comm, filename, argv, exit_code) \
             VALUES (?1, 'exec', datetime('now'), ?2, 1, 1000, 1000, 1000, ?3, ?4, ?5, ?6)",
            params![session_id, pid, comm, filename, argv, exit_code],
        )
        .expect("insert test exec event");
    }

    fn insert_test_io(
        conn: &rusqlite::Connection,
        session_id: &str,
        pid: u32,
        event_type: &str,
        fd: u32,
        data: &str,
    ) {
        conn.execute(
            "INSERT INTO events \
             (session_id, event_type, timestamp, pid, ppid, uid, gid, euid, fd, data, data_len, byte_count) \
             VALUES (?1, ?2, datetime('now'), ?3, 1, 1000, 1000, 1000, ?4, ?5, ?6, ?7)",
            params![session_id, event_type, pid, fd, data, data.len(), data.len()],
        )
        .expect("insert test io event");
    }

    #[test]
    fn list_returns_exec_events_only() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool.clone());

        {
            let conn = pool.get()?;
            insert_test_session(&conn, "s1");
            insert_test_exec(&conn, "s1", 100, "ls", "/usr/bin/ls", "[\"ls\"]", Some(0));
            insert_test_io(&conn, "s1", 100, "write", 1, "hello");
        }

        let page = repo.list(&ListRequest::default(), &EventFilter::default())?;
        assert_eq!(page.items.len(), 1, "should only return exec events");
        assert_eq!(page.items[0].event_type, "exec");
        assert_eq!(page.total_items, 1);
        Ok(())
    }

    #[test]
    fn list_pagination() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool.clone());

        {
            let conn = pool.get()?;
            insert_test_session(&conn, "s1");
            for i in 0..10 {
                insert_test_exec(
                    &conn,
                    "s1",
                    100 + i,
                    &format!("cmd{i}"),
                    "/usr/bin/cmd",
                    "[]",
                    Some(0),
                );
            }
        }

        let req = ListRequest {
            page: 1,
            page_size: 3,
            ..ListRequest::default()
        };
        let page = repo.list(&req, &EventFilter::default())?;
        assert_eq!(page.items.len(), 3, "first page should have 3 items");
        assert_eq!(page.total_items, 10);
        assert_eq!(page.total_pages(), 4);

        let req2 = ListRequest {
            page: 4,
            page_size: 3,
            ..ListRequest::default()
        };
        let page2 = repo.list(&req2, &EventFilter::default())?;
        assert_eq!(page2.items.len(), 1, "last page should have 1 item");
        Ok(())
    }

    #[test]
    fn list_filter_by_comm() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool.clone());

        {
            let conn = pool.get()?;
            insert_test_session(&conn, "s1");
            insert_test_exec(&conn, "s1", 100, "bash", "/usr/bin/bash", "[]", Some(0));
            insert_test_exec(&conn, "s1", 101, "ls", "/usr/bin/ls", "[]", Some(0));
            insert_test_exec(&conn, "s1", 102, "cat", "/usr/bin/cat", "[]", Some(0));
        }

        let filter = EventFilter::parse("comm:bash");
        let page = repo.list(&ListRequest::default(), &filter)?;
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].comm.as_deref(), Some("bash"));
        Ok(())
    }

    #[test]
    fn list_filter_by_comm_glob() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool.clone());

        {
            let conn = pool.get()?;
            insert_test_session(&conn, "s1");
            insert_test_exec(&conn, "s1", 100, "bash", "/usr/bin/bash", "[]", Some(0));
            insert_test_exec(&conn, "s1", 101, "sh", "/usr/bin/sh", "[]", Some(0));
        }

        let filter = EventFilter::parse("comm:*sh");
        let page = repo.list(&ListRequest::default(), &filter)?;
        assert_eq!(page.items.len(), 2, "glob *sh should match bash and sh");
        Ok(())
    }

    #[test]
    fn list_filter_by_exit_code() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool.clone());

        {
            let conn = pool.get()?;
            insert_test_session(&conn, "s1");
            insert_test_exec(&conn, "s1", 100, "cmd1", "/cmd1", "[]", Some(0));
            insert_test_exec(&conn, "s1", 101, "cmd2", "/cmd2", "[]", Some(1));
        }

        let filter = EventFilter::parse("exit:1");
        let page = repo.list(&ListRequest::default(), &filter)?;
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].exit_code, Some(1));
        Ok(())
    }

    #[test]
    fn list_filter_by_session_prefix() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool.clone());

        {
            let conn = pool.get()?;
            insert_test_session(&conn, "ox_abc123");
            insert_test_session(&conn, "ox_def456");
            insert_test_exec(&conn, "ox_abc123", 100, "ls", "/ls", "[]", Some(0));
            insert_test_exec(&conn, "ox_def456", 101, "cat", "/cat", "[]", Some(0));
        }

        let filter = EventFilter::parse("session:ox_abc");
        let page = repo.list(&ListRequest::default(), &filter)?;
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].session_id, "ox_abc123");
        Ok(())
    }

    #[test]
    fn list_filter_by_pid() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool.clone());

        {
            let conn = pool.get()?;
            insert_test_session(&conn, "s1");
            insert_test_exec(&conn, "s1", 100, "ls", "/ls", "[]", Some(0));
            insert_test_exec(&conn, "s1", 200, "cat", "/cat", "[]", Some(0));
        }

        let filter = EventFilter::parse("pid:200");
        let page = repo.list(&ListRequest::default(), &filter)?;
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].pid, 200);
        Ok(())
    }

    #[test]
    fn list_filter_bare_text() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool.clone());

        {
            let conn = pool.get()?;
            insert_test_session(&conn, "s1");
            insert_test_exec(
                &conn,
                "s1",
                100,
                "cargo",
                "/usr/bin/cargo",
                "[\"cargo\",\"build\"]",
                Some(0),
            );
            insert_test_exec(&conn, "s1", 101, "ls", "/usr/bin/ls", "[\"ls\"]", Some(0));
        }

        let filter = EventFilter::parse("build");
        let page = repo.list(&ListRequest::default(), &filter)?;
        assert_eq!(page.items.len(), 1, "bare text should match argv");
        assert_eq!(page.items[0].comm.as_deref(), Some("cargo"));
        Ok(())
    }

    #[test]
    fn list_empty_result() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool);

        let page = repo.list(&ListRequest::default(), &EventFilter::default())?;
        assert!(page.items.is_empty());
        assert_eq!(page.total_items, 0);
        Ok(())
    }

    #[test]
    fn get_detail_found() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool.clone());

        let id = {
            let conn = pool.get()?;
            insert_test_session(&conn, "s1");
            insert_test_exec(
                &conn,
                "s1",
                100,
                "cat",
                "/usr/bin/cat",
                "[\"cat\",\"file.txt\"]",
                Some(0),
            );
            conn.query_row("SELECT id FROM events LIMIT 1", [], |r| r.get::<_, i64>(0))?
        };

        let detail = repo.get_detail(id)?;
        assert!(detail.is_some(), "should find the event");
        let detail = detail.expect("checked above");
        assert_eq!(detail.summary.comm.as_deref(), Some("cat"));
        assert_eq!(detail.gid, 1000);
        Ok(())
    }

    #[test]
    fn get_detail_not_found() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool);

        let detail = repo.get_detail(99999)?;
        assert!(detail.is_none(), "should return None for missing event");
        Ok(())
    }

    #[test]
    fn get_detail_includes_io_data() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool.clone());

        let id = {
            let conn = pool.get()?;
            insert_test_session(&conn, "s1");
            insert_test_exec(&conn, "s1", 100, "cat", "/cat", "[]", Some(0));
            insert_test_io(&conn, "s1", 100, "read", 0, "input data");
            insert_test_io(&conn, "s1", 100, "write", 1, "output line 1\n");
            insert_test_io(&conn, "s1", 100, "write", 2, "error output\n");
            // I/O for a different PID — should NOT appear.
            insert_test_io(&conn, "s1", 200, "write", 1, "other process");
            conn.query_row(
                "SELECT id FROM events WHERE event_type = 'exec' LIMIT 1",
                [],
                |r| r.get::<_, i64>(0),
            )?
        };

        let detail = repo.get_detail(id)?.expect("event should exist");
        assert_eq!(detail.stdin_data.len(), 1, "should have 1 stdin chunk");
        assert_eq!(detail.stdin_data[0].data, "input data");
        assert_eq!(
            detail.stdout_data.len(),
            2,
            "should have 2 stdout/stderr chunks"
        );
        Ok(())
    }

    #[test]
    fn list_since_returns_new_events() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool.clone());

        let conn = pool.get()?;
        insert_test_session(&conn, "s1");
        insert_test_exec(&conn, "s1", 100, "ls", "/ls", "[]", Some(0));
        insert_test_exec(&conn, "s1", 101, "cat", "/cat", "[]", Some(0));
        insert_test_exec(&conn, "s1", 102, "pwd", "/pwd", "[]", Some(0));
        drop(conn);

        // Get all events to find the first ID.
        let all = repo.list(&ListRequest::default(), &EventFilter::default())?;
        assert_eq!(all.items.len(), 3);

        // list_since(id of first event) should return the next two.
        // Events are returned DESC by list(), so last item is oldest.
        let first_id = all.items.last().expect("has items").id;
        let since = repo.list_since(first_id, &EventFilter::default())?;
        assert_eq!(since.len(), 2, "should return 2 events after first_id");
        assert!(since[0].id > first_id);
        assert!(since[1].id > since[0].id, "should be ordered ASC");
        Ok(())
    }

    #[test]
    fn list_since_respects_filter() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool.clone());

        let conn = pool.get()?;
        insert_test_session(&conn, "s1");
        insert_test_exec(&conn, "s1", 100, "ls", "/ls", "[]", Some(0));
        insert_test_exec(&conn, "s1", 101, "bash", "/bash", "[]", Some(0));
        drop(conn);

        let filter = EventFilter::parse("comm:bash");
        let since = repo.list_since(0, &filter)?;
        assert_eq!(since.len(), 1);
        assert_eq!(since[0].comm.as_deref(), Some("bash"));
        Ok(())
    }

    #[test]
    fn list_since_empty_when_no_new() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool.clone());

        let conn = pool.get()?;
        insert_test_session(&conn, "s1");
        insert_test_exec(&conn, "s1", 100, "ls", "/ls", "[]", Some(0));
        drop(conn);

        let max = repo.max_event_id()?;
        let since = repo.list_since(max, &EventFilter::default())?;
        assert!(since.is_empty(), "no new events after max_id");
        Ok(())
    }

    #[test]
    fn max_event_id_empty_db() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool);
        assert_eq!(repo.max_event_id()?, 0);
        Ok(())
    }

    #[test]
    fn max_event_id_with_data() -> Result<()> {
        let pool = create_test_pool()?;
        let repo = SqlEventRepository::new(pool.clone());

        let conn = pool.get()?;
        insert_test_session(&conn, "s1");
        insert_test_exec(&conn, "s1", 100, "ls", "/ls", "[]", Some(0));
        insert_test_exec(&conn, "s1", 101, "cat", "/cat", "[]", Some(0));
        drop(conn);

        let max = repo.max_event_id()?;
        assert!(max > 0);
        Ok(())
    }
}
