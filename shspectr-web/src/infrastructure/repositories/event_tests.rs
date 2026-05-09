//! Tests for `SqlEventRepository`.

use super::*;

use anyhow::Result;
use rusqlite::params;

use crate::domain::filter::EventFilter;
use crate::domain::listing::ListRequest;
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

/// Extended helper that accepts ppid, gid, euid, and tty_nr.
fn insert_test_exec_full(
    conn: &rusqlite::Connection,
    session_id: &str,
    pid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    euid: u32,
    tty_nr: Option<u32>,
    comm: &str,
    filename: &str,
    argv: &str,
    exit_code: Option<i32>,
) {
    conn.execute(
        "INSERT INTO events \
         (session_id, event_type, timestamp, pid, ppid, uid, gid, euid, tty_nr, comm, filename, argv, exit_code) \
         VALUES (?1, 'exec', datetime('now'), ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![session_id, pid, ppid, uid, gid, euid, tty_nr, comm, filename, argv, exit_code],
    )
    .expect("insert test exec event (full)");
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

#[test]
fn filter_by_ppid() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let conn = pool.get()?;
    insert_test_session(&conn, "s1");
    insert_test_exec_full(
        &conn,
        "s1",
        100,
        1,
        1000,
        1000,
        1000,
        None,
        "ls",
        "/ls",
        "[]",
        Some(0),
    );
    insert_test_exec_full(
        &conn,
        "s1",
        101,
        2,
        1000,
        1000,
        1000,
        None,
        "cat",
        "/cat",
        "[]",
        Some(0),
    );
    drop(conn);

    let filter = EventFilter::parse("ppid:1");
    let page = repo.list(&ListRequest::default(), &filter)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].ppid, 1);
    Ok(())
}

#[test]
fn filter_by_gid() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let conn = pool.get()?;
    insert_test_session(&conn, "s1");
    insert_test_exec_full(
        &conn,
        "s1",
        100,
        1,
        1000,
        1000,
        1000,
        None,
        "ls",
        "/ls",
        "[]",
        Some(0),
    );
    insert_test_exec_full(
        &conn,
        "s1",
        101,
        1,
        1000,
        2000,
        1000,
        None,
        "cat",
        "/cat",
        "[]",
        Some(0),
    );
    drop(conn);

    let filter = EventFilter::parse("gid:2000");
    let page = repo.list(&ListRequest::default(), &filter)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].comm.as_deref(), Some("cat"));
    Ok(())
}

#[test]
fn filter_by_tty() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let conn = pool.get()?;
    insert_test_session(&conn, "s1");
    insert_test_exec_full(
        &conn,
        "s1",
        100,
        1,
        1000,
        1000,
        1000,
        Some(34816),
        "ls",
        "/ls",
        "[]",
        Some(0),
    );
    insert_test_exec_full(
        &conn,
        "s1",
        101,
        1,
        1000,
        1000,
        1000,
        None,
        "cat",
        "/cat",
        "[]",
        Some(0),
    );
    drop(conn);

    let filter = EventFilter::parse("tty:34816");
    let page = repo.list(&ListRequest::default(), &filter)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].comm.as_deref(), Some("ls"));
    Ok(())
}

#[test]
fn filter_by_file_glob() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let conn = pool.get()?;
    insert_test_session(&conn, "s1");
    insert_test_exec(&conn, "s1", 100, "ls", "/usr/bin/ls", "[]", Some(0));
    insert_test_exec(&conn, "s1", 101, "cat", "/usr/sbin/cat", "[]", Some(0));
    drop(conn);

    let filter = EventFilter::parse("file:/usr/bin/*");
    let page = repo.list(&ListRequest::default(), &filter)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].comm.as_deref(), Some("ls"));
    Ok(())
}

#[test]
fn filter_negation_exit() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let conn = pool.get()?;
    insert_test_session(&conn, "s1");
    insert_test_exec(&conn, "s1", 100, "ok", "/ok", "[]", Some(0));
    insert_test_exec(&conn, "s1", 101, "fail", "/fail", "[]", Some(1));
    drop(conn);

    let filter = EventFilter::parse("!exit:0");
    let page = repo.list(&ListRequest::default(), &filter)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].exit_code, Some(1));
    Ok(())
}

#[test]
fn filter_negation_comm() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let conn = pool.get()?;
    insert_test_session(&conn, "s1");
    insert_test_exec(&conn, "s1", 100, "bash", "/bash", "[]", Some(0));
    insert_test_exec(&conn, "s1", 101, "ls", "/ls", "[]", Some(0));
    drop(conn);

    let filter = EventFilter::parse("!comm:bash");
    let page = repo.list(&ListRequest::default(), &filter)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].comm.as_deref(), Some("ls"));
    Ok(())
}

#[test]
fn filter_by_user_name() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let conn = pool.get()?;
    insert_test_session(&conn, "s1");
    insert_test_exec_full(
        &conn,
        "s1",
        100,
        1,
        0,
        0,
        0,
        None,
        "ls",
        "/ls",
        "[]",
        Some(0),
    );
    insert_test_exec_full(
        &conn,
        "s1",
        101,
        1,
        1000,
        1000,
        1000,
        None,
        "cat",
        "/cat",
        "[]",
        Some(0),
    );
    drop(conn);

    let filter = EventFilter::parse("user:root");
    let page = repo.list(&ListRequest::default(), &filter)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].uid, 0);
    Ok(())
}

#[test]
fn filter_cmd_exact() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let conn = pool.get()?;
    insert_test_session(&conn, "s1");
    insert_test_exec(&conn, "s1", 100, "ps", "/usr/bin/ps", "[]", Some(0));
    insert_test_exec(
        &conn,
        "s1",
        101,
        "git",
        "/usr/lib/git-core/git",
        "[]",
        Some(0),
    );
    insert_test_exec(&conn, "s1", 102, "ls", "/usr/bin/ls", "[]", Some(0));
    drop(conn);

    let filter = EventFilter::parse("cmd:ps");
    let page = repo.list(&ListRequest::default(), &filter)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].filename.as_deref(), Some("/usr/bin/ps"));
    Ok(())
}

#[test]
fn filter_cmd_glob() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let conn = pool.get()?;
    insert_test_session(&conn, "s1");
    insert_test_exec(&conn, "s1", 100, "git", "/usr/bin/git", "[]", Some(0));
    insert_test_exec(&conn, "s1", 101, "gitk", "/usr/bin/gitk", "[]", Some(0));
    insert_test_exec(&conn, "s1", 102, "ls", "/usr/bin/ls", "[]", Some(0));
    drop(conn);

    let filter = EventFilter::parse("cmd:git*");
    let page = repo.list(&ListRequest::default(), &filter)?;
    assert_eq!(page.items.len(), 2);
    Ok(())
}

#[test]
fn filter_cmd_negated() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let conn = pool.get()?;
    insert_test_session(&conn, "s1");
    insert_test_exec(
        &conn,
        "s1",
        100,
        "git",
        "/usr/lib/git-core/git",
        "[]",
        Some(0),
    );
    insert_test_exec(&conn, "s1", 101, "ps", "/usr/bin/ps", "[]", Some(0));
    insert_test_exec(&conn, "s1", 102, "ls", "/usr/bin/ls", "[]", Some(0));
    drop(conn);

    let filter = EventFilter::parse("!cmd:git");
    let page = repo.list(&ListRequest::default(), &filter)?;
    assert_eq!(page.items.len(), 2);
    let filenames: Vec<_> = page
        .items
        .iter()
        .filter_map(|e| e.filename.as_deref())
        .collect();
    assert!(!filenames.contains(&"/usr/lib/git-core/git"));
    Ok(())
}
