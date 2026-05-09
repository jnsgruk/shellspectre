//! Tests for `SqlEventRepository`.

use super::*;

use anyhow::Result;

use crate::domain::filter::EventFilter;
use crate::domain::listing::ListRequest;
use crate::infrastructure::database::create_test_pool;

use super::test_fixtures::{ExecEventRow, IoEventRow, SessionRow};

#[test]
fn list_returns_exec_events_only() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    {
        let conn = pool.get()?;
        SessionRow::new("s1").insert(&conn);
        ExecEventRow::new("s1")
            .comm("ls")
            .filename("/usr/bin/ls")
            .argv("[\"ls\"]")
            .insert(&conn);
        IoEventRow::new("s1").data("hello").insert(&conn);
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
        SessionRow::new("s1").insert(&conn);
        for i in 0..10 {
            ExecEventRow::new("s1")
                .pid(100 + i)
                .comm(&format!("cmd{i}"))
                .filename("/usr/bin/cmd")
                .insert(&conn);
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
        SessionRow::new("s1").insert(&conn);
        ExecEventRow::new("s1")
            .comm("bash")
            .filename("/usr/bin/bash")
            .insert(&conn);
        ExecEventRow::new("s1")
            .pid(101)
            .comm("ls")
            .filename("/usr/bin/ls")
            .insert(&conn);
        ExecEventRow::new("s1")
            .pid(102)
            .comm("cat")
            .filename("/usr/bin/cat")
            .insert(&conn);
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
        SessionRow::new("s1").insert(&conn);
        ExecEventRow::new("s1")
            .comm("bash")
            .filename("/usr/bin/bash")
            .insert(&conn);
        ExecEventRow::new("s1")
            .pid(101)
            .comm("sh")
            .filename("/usr/bin/sh")
            .insert(&conn);
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
        SessionRow::new("s1").insert(&conn);
        ExecEventRow::new("s1")
            .comm("cmd1")
            .filename("/cmd1")
            .exit_code(0)
            .insert(&conn);
        ExecEventRow::new("s1")
            .pid(101)
            .comm("cmd2")
            .filename("/cmd2")
            .exit_code(1)
            .insert(&conn);
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
        SessionRow::new("ox_abc123").insert(&conn);
        SessionRow::new("ox_def456").insert(&conn);
        ExecEventRow::new("ox_abc123")
            .comm("ls")
            .filename("/ls")
            .insert(&conn);
        ExecEventRow::new("ox_def456")
            .pid(101)
            .comm("cat")
            .filename("/cat")
            .insert(&conn);
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
        SessionRow::new("s1").insert(&conn);
        ExecEventRow::new("s1")
            .comm("ls")
            .filename("/ls")
            .insert(&conn);
        ExecEventRow::new("s1")
            .pid(200)
            .comm("cat")
            .filename("/cat")
            .insert(&conn);
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
        SessionRow::new("s1").insert(&conn);
        ExecEventRow::new("s1")
            .comm("cargo")
            .filename("/usr/bin/cargo")
            .argv("[\"cargo\",\"build\"]")
            .insert(&conn);
        ExecEventRow::new("s1")
            .pid(101)
            .comm("ls")
            .filename("/usr/bin/ls")
            .argv("[\"ls\"]")
            .insert(&conn);
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
        SessionRow::new("s1").insert(&conn);
        ExecEventRow::new("s1")
            .comm("cat")
            .filename("/usr/bin/cat")
            .argv("[\"cat\",\"file.txt\"]")
            .insert(&conn);
        conn.query_row("SELECT id FROM events LIMIT 1", [], |r| r.get::<_, i64>(0))?
    };

    let detail = repo.get_detail(id)?;
    assert!(detail.is_some(), "should find the event");
    let detail = detail.expect("checked above");
    assert_eq!(detail.summary.comm.as_deref(), Some("cat"));
    assert_eq!(detail.summary.execution_id, 100);
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
        SessionRow::new("s1").insert(&conn);
        ExecEventRow::new("s1")
            .comm("cat")
            .filename("/cat")
            .insert(&conn);
        IoEventRow::new("s1")
            .event_type("read")
            .fd(0)
            .data("input data")
            .insert(&conn);
        IoEventRow::new("s1")
            .event_type("write")
            .fd(1)
            .data("output line 1\n")
            .insert(&conn);
        IoEventRow::new("s1")
            .event_type("write")
            .fd(2)
            .data("error output\n")
            .insert(&conn);
        // I/O for a different PID — should NOT appear.
        IoEventRow::new("s1")
            .pid(200)
            .data("other process")
            .insert(&conn);
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
fn get_detail_scopes_io_to_matching_execution_id() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let id = {
        let conn = pool.get()?;
        SessionRow::new("s1").insert(&conn);
        ExecEventRow::new("s1")
            .pid(100)
            .execution_id(10)
            .comm("bash")
            .insert(&conn);
        ExecEventRow::new("s1")
            .pid(100)
            .execution_id(11)
            .comm("python")
            .insert(&conn);
        IoEventRow::new("s1")
            .pid(100)
            .execution_id(10)
            .event_type("write")
            .fd(1)
            .data("first exec")
            .insert(&conn);
        IoEventRow::new("s1")
            .pid(100)
            .execution_id(11)
            .event_type("write")
            .fd(1)
            .data("second exec")
            .insert(&conn);
        conn.query_row(
            "SELECT id FROM events WHERE event_type = 'exec' AND execution_id = 11 LIMIT 1",
            [],
            |r| r.get::<_, i64>(0),
        )?
    };

    let detail = repo.get_detail(id)?.expect("event should exist");
    assert_eq!(detail.stdout_data.len(), 1);
    assert_eq!(detail.stdout_data[0].data, "second exec");
    Ok(())
}

#[test]
fn list_since_returns_new_events() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let conn = pool.get()?;
    SessionRow::new("s1").insert(&conn);
    ExecEventRow::new("s1")
        .comm("ls")
        .filename("/ls")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(101)
        .comm("cat")
        .filename("/cat")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(102)
        .comm("pwd")
        .filename("/pwd")
        .insert(&conn);
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
    SessionRow::new("s1").insert(&conn);
    ExecEventRow::new("s1")
        .comm("ls")
        .filename("/ls")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(101)
        .comm("bash")
        .filename("/bash")
        .insert(&conn);
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
    SessionRow::new("s1").insert(&conn);
    ExecEventRow::new("s1")
        .comm("ls")
        .filename("/ls")
        .insert(&conn);
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
    SessionRow::new("s1").insert(&conn);
    ExecEventRow::new("s1")
        .comm("ls")
        .filename("/ls")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(101)
        .comm("cat")
        .filename("/cat")
        .insert(&conn);
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
    SessionRow::new("s1").insert(&conn);
    ExecEventRow::new("s1")
        .ppid(1)
        .comm("ls")
        .filename("/ls")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(101)
        .ppid(2)
        .comm("cat")
        .filename("/cat")
        .insert(&conn);
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
    SessionRow::new("s1").insert(&conn);
    ExecEventRow::new("s1")
        .gid(1000)
        .comm("ls")
        .filename("/ls")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(101)
        .gid(2000)
        .comm("cat")
        .filename("/cat")
        .insert(&conn);
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
    SessionRow::new("s1").insert(&conn);
    ExecEventRow::new("s1")
        .tty_nr(34816)
        .comm("ls")
        .filename("/ls")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(101)
        .comm("cat")
        .filename("/cat")
        .insert(&conn);
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
    SessionRow::new("s1").insert(&conn);
    ExecEventRow::new("s1")
        .comm("ls")
        .filename("/usr/bin/ls")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(101)
        .comm("cat")
        .filename("/usr/sbin/cat")
        .insert(&conn);
    drop(conn);

    let filter = EventFilter::parse("file:/usr/bin/*");
    let page = repo.list(&ListRequest::default(), &filter)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].comm.as_deref(), Some("ls"));
    Ok(())
}

#[test]
fn filter_file_treats_percent_and_underscore_as_literals() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let conn = pool.get()?;
    SessionRow::new("s1").insert(&conn);
    ExecEventRow::new("s1")
        .filename("/tmp/a_b")
        .comm("under")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(101)
        .filename("/tmp/acb")
        .comm("wild")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(102)
        .filename("/tmp/100%")
        .comm("percent")
        .insert(&conn);
    drop(conn);

    let underscore = repo.list(
        &ListRequest::default(),
        &EventFilter::parse("file:/tmp/a_b"),
    )?;
    assert_eq!(underscore.items.len(), 1);
    assert_eq!(underscore.items[0].comm.as_deref(), Some("under"));

    let percent = repo.list(
        &ListRequest::default(),
        &EventFilter::parse("file:/tmp/100%"),
    )?;
    assert_eq!(percent.items.len(), 1);
    assert_eq!(percent.items[0].comm.as_deref(), Some("percent"));
    Ok(())
}

#[test]
fn filter_negation_exit() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let conn = pool.get()?;
    SessionRow::new("s1").insert(&conn);
    ExecEventRow::new("s1")
        .comm("ok")
        .filename("/ok")
        .exit_code(0)
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(101)
        .comm("fail")
        .filename("/fail")
        .exit_code(1)
        .insert(&conn);
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
    SessionRow::new("s1").insert(&conn);
    ExecEventRow::new("s1")
        .comm("bash")
        .filename("/bash")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(101)
        .comm("ls")
        .filename("/ls")
        .insert(&conn);
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
    SessionRow::new("s1").insert(&conn);
    ExecEventRow::new("s1")
        .uid(0)
        .gid(0)
        .euid(0)
        .comm("ls")
        .filename("/ls")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(101)
        .uid(1000)
        .gid(1000)
        .euid(1000)
        .comm("cat")
        .filename("/cat")
        .insert(&conn);
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
    SessionRow::new("s1").insert(&conn);
    // comm differs from filename basename to verify cmd: uses filename.
    ExecEventRow::new("s1")
        .comm("bash")
        .filename("/usr/bin/ps")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(101)
        .comm("opencode")
        .filename("/usr/lib/git-core/git")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(102)
        .comm("fish")
        .filename("/usr/bin/ls")
        .insert(&conn);
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
    SessionRow::new("s1").insert(&conn);
    // comm differs from filename basename to verify cmd: uses filename.
    ExecEventRow::new("s1")
        .comm("bash")
        .filename("/usr/bin/git")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(101)
        .comm("bash")
        .filename("/usr/bin/gitk")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(102)
        .comm("bash")
        .filename("/usr/bin/ls")
        .insert(&conn);
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
    SessionRow::new("s1").insert(&conn);
    // comm differs from filename basename to verify cmd: uses filename.
    ExecEventRow::new("s1")
        .comm("bash")
        .filename("/usr/lib/git-core/git")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(101)
        .comm("bash")
        .filename("/usr/bin/ps")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(102)
        .comm("bash")
        .filename("/usr/bin/ls")
        .insert(&conn);
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

#[test]
fn filter_cmd_pipe_or() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let conn = pool.get()?;
    SessionRow::new("s1").insert(&conn);
    ExecEventRow::new("s1")
        .comm("bash")
        .filename("/usr/bin/git")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(101)
        .comm("bash")
        .filename("/usr/bin/ps")
        .insert(&conn);
    ExecEventRow::new("s1")
        .pid(102)
        .comm("bash")
        .filename("/usr/bin/ls")
        .insert(&conn);
    drop(conn);

    // Positive OR: should match git and ps.
    let filter = EventFilter::parse("cmd:git|ps");
    let page = repo.list(&ListRequest::default(), &filter)?;
    assert_eq!(page.items.len(), 2);

    // Negated OR: should exclude git and ps, leaving only ls.
    let filter = EventFilter::parse("!cmd:git|ps");
    let page = repo.list(&ListRequest::default(), &filter)?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].filename.as_deref(), Some("/usr/bin/ls"));

    Ok(())
}

#[test]
fn get_detail_includes_children() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let parent_id = {
        let conn = pool.get()?;
        SessionRow::new("s1").insert(&conn);
        // Parent process (pid=100)
        ExecEventRow::new("s1")
            .pid(100)
            .comm("bash")
            .filename("/usr/bin/bash")
            .insert(&conn);
        // Child 1 (pid=200, ppid=100)
        ExecEventRow::new("s1")
            .pid(200)
            .ppid(100)
            .execution_id(200)
            .comm("ls")
            .filename("/usr/bin/ls")
            .exit_code(0)
            .insert(&conn);
        // Child 2 (pid=201, ppid=100)
        ExecEventRow::new("s1")
            .pid(201)
            .ppid(100)
            .execution_id(201)
            .comm("cat")
            .filename("/usr/bin/cat")
            .exit_code(1)
            .insert(&conn);
        // Unrelated process (different ppid)
        ExecEventRow::new("s1")
            .pid(300)
            .ppid(999)
            .execution_id(300)
            .comm("unrelated")
            .filename("/unrelated")
            .insert(&conn);
        conn.query_row(
            "SELECT id FROM events WHERE pid = 100 AND event_type = 'exec' LIMIT 1",
            [],
            |r| r.get::<_, i64>(0),
        )?
    };

    let detail = repo.get_detail(parent_id)?.expect("should find parent");
    assert_eq!(detail.children.len(), 2, "should have 2 children");
    assert_eq!(detail.children[0].comm.as_deref(), Some("ls"));
    assert_eq!(detail.children[1].comm.as_deref(), Some("cat"));
    Ok(())
}

#[test]
fn get_detail_includes_parent() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let child_id = {
        let conn = pool.get()?;
        SessionRow::new("s1").insert(&conn);
        // Parent (pid=100)
        ExecEventRow::new("s1")
            .pid(100)
            .comm("bash")
            .filename("/usr/bin/bash")
            .argv("[\"bash\"]")
            .insert(&conn);
        // Child (pid=200, ppid=100)
        ExecEventRow::new("s1")
            .pid(200)
            .ppid(100)
            .execution_id(200)
            .comm("ls")
            .filename("/usr/bin/ls")
            .insert(&conn);
        conn.query_row(
            "SELECT id FROM events WHERE pid = 200 AND event_type = 'exec' LIMIT 1",
            [],
            |r| r.get::<_, i64>(0),
        )?
    };

    let detail = repo.get_detail(child_id)?.expect("should find child");
    assert!(detail.parent.is_some(), "should have parent");
    let parent = detail.parent.expect("checked above");
    assert_eq!(parent.comm.as_deref(), Some("bash"));
    assert_eq!(parent.filename.as_deref(), Some("/usr/bin/bash"));
    Ok(())
}

#[test]
fn get_detail_child_has_io_flag() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let parent_id = {
        let conn = pool.get()?;
        SessionRow::new("s1").insert(&conn);
        ExecEventRow::new("s1")
            .pid(100)
            .comm("bash")
            .filename("/bash")
            .insert(&conn);
        // Child with I/O
        ExecEventRow::new("s1")
            .pid(200)
            .ppid(100)
            .execution_id(200)
            .comm("cat")
            .filename("/cat")
            .insert(&conn);
        IoEventRow::new("s1")
            .pid(200)
            .execution_id(200)
            .data("output")
            .insert(&conn);
        // Child without I/O
        ExecEventRow::new("s1")
            .pid(201)
            .ppid(100)
            .execution_id(201)
            .comm("true")
            .filename("/true")
            .insert(&conn);
        conn.query_row(
            "SELECT id FROM events WHERE pid = 100 AND event_type = 'exec' LIMIT 1",
            [],
            |r| r.get::<_, i64>(0),
        )?
    };

    let detail = repo.get_detail(parent_id)?.expect("should find parent");
    assert_eq!(detail.children.len(), 2);
    let cat_child = detail
        .children
        .iter()
        .find(|c| c.comm.as_deref() == Some("cat"))
        .expect("should find cat child");
    assert!(cat_child.has_io, "cat should have I/O");
    let true_child = detail
        .children
        .iter()
        .find(|c| c.comm.as_deref() == Some("true"))
        .expect("should find true child");
    assert!(!true_child.has_io, "true should not have I/O");
    Ok(())
}

#[test]
fn get_detail_no_parent_when_not_in_session() -> Result<()> {
    let pool = create_test_pool()?;
    let repo = SqlEventRepository::new(pool.clone());

    let id = {
        let conn = pool.get()?;
        SessionRow::new("s1").insert(&conn);
        // Process whose ppid (999) has no exec event in this session
        ExecEventRow::new("s1")
            .pid(100)
            .ppid(999)
            .comm("orphan")
            .filename("/orphan")
            .insert(&conn);
        conn.query_row("SELECT id FROM events WHERE pid = 100 LIMIT 1", [], |r| {
            r.get::<_, i64>(0)
        })?
    };

    let detail = repo.get_detail(id)?.expect("should find event");
    assert!(detail.parent.is_none(), "should have no parent");
    assert!(detail.children.is_empty(), "should have no children");
    Ok(())
}
