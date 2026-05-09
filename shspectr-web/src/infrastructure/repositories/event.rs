//! SQLite implementation of the `EventRepository` trait.

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};

use crate::domain::event::{EventDetail, EventFilter, EventSummary, FilterValue, IoChunk};
use crate::domain::listing::{ListRequest, Page};
use crate::domain::repositories::EventRepository;
use crate::infrastructure::database::DbPool;
use crate::presentation::web::username::resolve_username;

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
fn add_like(
    conditions: &mut Vec<String>,
    params: &mut Vec<Box<dyn rusqlite::types::ToSql>>,
    column: &str,
    pattern: String,
    negated: bool,
    nullable: bool,
) {
    let idx = params.len() + 1;
    if negated {
        if nullable {
            conditions.push(format!("({column} IS NULL OR {column} NOT LIKE ?{idx})"));
        } else {
            conditions.push(format!("{column} NOT LIKE ?{idx}"));
        }
    } else {
        conditions.push(format!("{column} LIKE ?{idx}"));
    }
    params.push(Box::new(pattern));
}

/// Build a WHERE clause and positional parameters from a filter.
#[allow(clippy::too_many_lines)]
fn build_where_clause(filter: &EventFilter) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    // Default to exec events only in list view.
    conditions.push("event_type = 'exec'".to_owned());

    if let Some(ref fv) = filter.comm {
        let like_pattern = fv.value.replace('*', "%").replace('?', "_");
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
        let pattern = format!("{}%", fv.value);
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
        let like_pattern = fv.value.replace('*', "%").replace('?', "_");
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
        // Match basename of filename: prepend `%/` to anchor after the last slash.
        let glob = fv.value.replace('*', "%").replace('?', "_");
        let like_pattern = if glob.starts_with('%') {
            // Already starts with wildcard — no need for extra `%/` prefix.
            glob
        } else {
            format!("%/{glob}")
        };
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
fn fetch_io_chunks(conn: &rusqlite::Connection, detail: &mut EventDetail) -> Result<()> {
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
#[path = "event_tests.rs"]
mod tests;
