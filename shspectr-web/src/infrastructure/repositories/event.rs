//! SQLite implementation of the `EventRepository` trait.

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};

use crate::domain::event::{ChildProcess, EventDetail, EventSummary, IoChunk, ParentProcess};
use crate::domain::filter::{EventFilter, FilterValue};
use crate::domain::listing::{ListRequest, Page};
use crate::domain::repositories::EventRepository;
use crate::infrastructure::database::DbPool;
use crate::presentation::web::username::resolve_username;
use shspectr_common::EventType;

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

/// Add an exact-match condition, respecting negation.
/// For negated filters on nullable columns, use `(col IS NULL OR col != ?N)`.
fn add_exact<T: rusqlite::types::ToSql + Clone + 'static>(
    conditions: &mut Vec<String>,
    params: &mut Vec<Box<dyn rusqlite::types::ToSql>>,
    column: &str,
    fv: &FilterValue<T>,
    nullable: bool,
) {
    let idx = params.len() + 1;
    if fv.negated {
        if nullable {
            conditions.push(format!("({column} IS NULL OR {column} != ?{idx})"));
        } else {
            conditions.push(format!("{column} != ?{idx}"));
        }
    } else {
        conditions.push(format!("{column} = ?{idx}"));
    }
    params.push(Box::new(fv.value.clone()));
}

/// Add a LIKE condition, respecting negation.
///
/// The pattern may contain `|`-separated alternatives (e.g. `git|ps`).
/// For non-negated filters this produces `(col LIKE A OR col LIKE B)`.
/// For negated filters: `(col NOT LIKE A AND col NOT LIKE B)` (plus
/// the nullable `IS NULL` prefix when required).
fn add_like(
    conditions: &mut Vec<String>,
    params: &mut Vec<Box<dyn rusqlite::types::ToSql>>,
    column: &str,
    pattern: String,
    negated: bool,
    nullable: bool,
) {
    let alternatives: Vec<&str> = pattern.split('|').collect();
    if alternatives.len() == 1 {
        // Fast path: single pattern, no alternation.
        let idx = params.len() + 1;
        if negated {
            if nullable {
                conditions.push(format!(
                    "({column} IS NULL OR {column} NOT LIKE ?{idx} ESCAPE '\\')"
                ));
            } else {
                conditions.push(format!("{column} NOT LIKE ?{idx} ESCAPE '\\'"));
            }
        } else {
            conditions.push(format!("{column} LIKE ?{idx} ESCAPE '\\'"));
        }
        params.push(Box::new(pattern));
        return;
    }

    // Multiple alternatives separated by `|`.
    let mut parts = Vec::with_capacity(alternatives.len());
    for alt in alternatives {
        let idx = params.len() + 1;
        if negated {
            parts.push(format!("{column} NOT LIKE ?{idx} ESCAPE '\\'"));
        } else {
            parts.push(format!("{column} LIKE ?{idx} ESCAPE '\\'"));
        }
        params.push(Box::new(alt.to_owned()));
    }

    let joiner = if negated { " AND " } else { " OR " };
    let combined = parts.join(joiner);
    if negated && nullable {
        conditions.push(format!("({column} IS NULL OR ({combined}))"));
    } else {
        conditions.push(format!("({combined})"));
    }
}

fn escape_like_pattern(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn glob_to_like_pattern(value: &str) -> String {
    escape_like_pattern(value)
        .replace('*', "%")
        .replace('?', "_")
}

/// Build a WHERE clause and positional parameters from a filter.
#[allow(clippy::too_many_lines)]
fn build_where_clause(filter: &EventFilter) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    // Default to exec events only in list view.
    conditions.push(format!("event_type = {}", EventType::Exec.as_wire()));

    if let Some(ref fv) = filter.comm {
        let like_pattern = glob_to_like_pattern(&fv.value);
        add_like(
            &mut conditions,
            &mut params,
            "comm",
            like_pattern,
            fv.negated,
            true,
        );
    }

    if let Some(ref fv) = filter.exit_code {
        add_exact(&mut conditions, &mut params, "exit_code", fv, true);
    }

    if let Some(ref fv) = filter.session_id {
        let pattern = format!("{}%", escape_like_pattern(&fv.value));
        add_like(
            &mut conditions,
            &mut params,
            "session_id",
            pattern,
            fv.negated,
            false,
        );
    }

    if let Some(ref fv) = filter.pid {
        add_exact(&mut conditions, &mut params, "pid", fv, false);
    }

    if let Some(ref fv) = filter.ppid {
        add_exact(&mut conditions, &mut params, "ppid", fv, false);
    }

    if let Some(ref fv) = filter.gid {
        add_exact(&mut conditions, &mut params, "gid", fv, false);
    }

    if let Some(ref fv) = filter.euid {
        add_exact(&mut conditions, &mut params, "euid", fv, false);
    }

    if let Some(ref fv) = filter.tty {
        add_exact(&mut conditions, &mut params, "tty_nr", fv, true);
    }

    if let Some(ref fv) = filter.file {
        let like_pattern = glob_to_like_pattern(&fv.value);
        add_like(
            &mut conditions,
            &mut params,
            "filename",
            like_pattern,
            fv.negated,
            true,
        );
    }

    if let Some(ref fv) = filter.cmd {
        // Match the basename of `filename` (the executed binary path).
        // Prepend `%/` to each `|`-separated alternative so `cmd:rg`
        // becomes `LIKE '%/rg'` and `cmd:git|ps` becomes
        // `(LIKE '%/git' OR LIKE '%/ps')`.
        let like_pattern = fv
            .value
            .split('|')
            .map(|alt| format!("%/{}", glob_to_like_pattern(alt)))
            .collect::<Vec<_>>()
            .join("|");
        add_like(
            &mut conditions,
            &mut params,
            "filename",
            like_pattern,
            fv.negated,
            true,
        );
    }

    if let Some(ref fv) = filter.user {
        // Try numeric UID first, then resolve username.
        let uid = fv
            .value
            .parse::<u32>()
            .ok()
            .or_else(|| resolve_username(&fv.value));
        if let Some(uid) = uid {
            let uid_fv = FilterValue {
                value: uid,
                negated: fv.negated,
            };
            add_exact(&mut conditions, &mut params, "uid", &uid_fv, false);
        }
    }

    if let Some(ref text) = filter.text {
        let idx = params.len() + 1;
        conditions.push(format!(
            "(comm LIKE ?{idx} ESCAPE '\\' OR filename LIKE ?{idx} ESCAPE '\\' OR argv LIKE ?{idx} ESCAPE '\\')"
        ));
        params.push(Box::new(format!("%{}%", escape_like_pattern(text))));
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
    let event_type_int: u32 = row.get(3)?;
    let event_type = EventType::from_wire(event_type_int).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Integer,
            format!("unknown event type discriminant {event_type_int}").into(),
        )
    })?;
    Ok(EventSummary {
        id: row.get(0)?,
        timestamp: row.get(1)?,
        session_id: row.get(2)?,
        event_type,
        execution_id: row.get(4)?,
        pid: row.get(5)?,
        ppid: row.get(6)?,
        uid: row.get(7)?,
        euid: row.get(8)?,
        comm: row.get(9)?,
        filename: row.get(10)?,
        argv: row.get(11)?,
        exit_code: row.get(12)?,
    })
}

/// Fetch I/O chunks for a given execution and populate the detail.
fn fetch_io_chunks(conn: &rusqlite::Connection, detail: &mut EventDetail) -> Result<()> {
    let mut io_stmt = conn
        .prepare(
            "SELECT timestamp, fd, data, byte_count \
             FROM events \
             WHERE session_id = ?1 AND pid = ?2 AND execution_id = ?3 \
               AND event_type IN (?4, ?5) \
             ORDER BY id ASC",
        )
        .context("failed to prepare I/O query")?;

    let io_rows = io_stmt
        .query_map(
            params![
                detail.summary.session_id,
                detail.summary.pid,
                detail.summary.execution_id,
                EventType::Read.as_wire(),
                EventType::Write.as_wire(),
            ],
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

/// Fetch child processes for a given exec event's PID within the same session.
fn fetch_children(conn: &rusqlite::Connection, detail: &EventDetail) -> Result<Vec<ChildProcess>> {
    let mut stmt = conn
        .prepare(
            "SELECT e.id, e.pid, e.comm, e.filename, e.argv, e.exit_code, \
                    EXISTS(SELECT 1 FROM events io \
                           WHERE io.session_id = e.session_id AND io.pid = e.pid \
                             AND io.execution_id = e.execution_id \
                             AND io.event_type IN (?3, ?4) LIMIT 1) as has_io \
             FROM events e \
             WHERE e.session_id = ?1 AND e.ppid = ?2 AND e.event_type = ?5 \
             ORDER BY e.id ASC",
        )
        .context("failed to prepare children query")?;

    let rows = stmt
        .query_map(
            params![
                detail.summary.session_id,
                detail.summary.pid,
                EventType::Read.as_wire(),
                EventType::Write.as_wire(),
                EventType::Exec.as_wire(),
            ],
            |row| {
                Ok(ChildProcess {
                    id: row.get(0)?,
                    pid: row.get(1)?,
                    comm: row.get(2)?,
                    filename: row.get(3)?,
                    argv: row.get(4)?,
                    exit_code: row.get(5)?,
                    has_io: row.get(6)?,
                })
            },
        )
        .context("failed to query children")?;

    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to map child rows")
}

/// Fetch the parent process for a given exec event by looking up ppid in the same session.
fn fetch_parent(
    conn: &rusqlite::Connection,
    detail: &EventDetail,
) -> Result<Option<ParentProcess>> {
    conn.query_row(
        "SELECT id, comm, filename, argv \
         FROM events \
         WHERE session_id = ?1 AND pid = ?2 AND event_type = ?3 \
         ORDER BY id DESC LIMIT 1",
        params![
            detail.summary.session_id,
            detail.summary.ppid,
            EventType::Exec.as_wire(),
        ],
        |row| {
            Ok(ParentProcess {
                id: row.get(0)?,
                comm: row.get(1)?,
                filename: row.get(2)?,
                argv: row.get(3)?,
            })
        },
    )
    .optional()
    .context("failed to query parent process")
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
            "SELECT id, timestamp, session_id, event_type, execution_id, pid, ppid, uid, euid, \
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
                "SELECT id, timestamp, session_id, event_type, execution_id, pid, ppid, uid, gid, euid, \
                        comm, filename, argv, exit_code, tty_nr, fd, data, data_len, byte_count \
                  FROM events WHERE id = ?1",
            )
            .context("failed to prepare detail query")?;

        let result = stmt
            .query_row(params![id], |row| {
                let event_type_int: u32 = row.get(3)?;
                let event_type = EventType::from_wire(event_type_int).ok_or_else(|| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Integer,
                        format!("unknown event type discriminant {event_type_int}").into(),
                    )
                })?;
                let summary = EventSummary {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    session_id: row.get(2)?,
                    event_type,
                    execution_id: row.get(4)?,
                    pid: row.get(5)?,
                    ppid: row.get(6)?,
                    uid: row.get(7)?,
                    euid: row.get(9)?,
                    comm: row.get(10)?,
                    filename: row.get(11)?,
                    argv: row.get(12)?,
                    exit_code: row.get(13)?,
                };
                Ok(EventDetail {
                    gid: row.get(8)?,
                    tty_nr: row.get(14)?,
                    fd: row.get(15)?,
                    data: row.get(16)?,
                    data_len: row.get(17)?,
                    byte_count: row.get(18)?,
                    summary,
                    stdin_data: Vec::new(),
                    stdout_data: Vec::new(),
                    children: Vec::new(),
                    parent: None,
                })
            })
            .optional()
            .context("failed to query event detail")?;

        let Some(mut detail) = result else {
            return Ok(None);
        };

        fetch_io_chunks(&conn, &mut detail)?;
        detail.children = fetch_children(&conn, &detail)?;
        detail.parent = fetch_parent(&conn, &detail)?;

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
            "SELECT id, timestamp, session_id, event_type, execution_id, pid, ppid, uid, euid, \
                    comm, filename, argv, exit_code \
             FROM events {full_where} \
             ORDER BY id ASC \
             LIMIT 100"
        );

        let mut stmt = conn
            .prepare(&sql)
            .context("failed to prepare list_since query")?;
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
#[path = "test_fixtures.rs"]
mod test_fixtures;

#[cfg(test)]
#[allow(clippy::expect_used)]
#[path = "event_tests.rs"]
mod tests;
