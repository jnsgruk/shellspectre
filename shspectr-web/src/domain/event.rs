//! Domain types for session events.

use serde::Serialize;

/// Summary of an event, used in list views.
/// Maps to columns in the `events` table.
#[derive(Debug, Clone, Serialize)]
pub struct EventSummary {
    /// `events.id` (INTEGER PRIMARY KEY AUTOINCREMENT).
    pub id: i64,
    /// `events.timestamp` (TEXT NOT NULL) — ISO 8601 datetime string.
    pub timestamp: String,
    /// `events.session_id` (TEXT NOT NULL).
    pub session_id: String,
    /// `events.event_type` (TEXT NOT NULL) — "exec", "exit", "read", "write".
    pub event_type: String,
    /// `events.execution_id` (INTEGER NOT NULL).
    pub execution_id: u64,
    /// `events.pid` (INTEGER NOT NULL).
    pub pid: u32,
    /// `events.ppid` (INTEGER NOT NULL).
    pub ppid: u32,
    /// `events.uid` (INTEGER NOT NULL).
    pub uid: u32,
    /// `events.euid` (INTEGER NOT NULL).
    pub euid: u32,
    /// `events.comm` (TEXT, nullable).
    pub comm: Option<String>,
    /// `events.filename` (TEXT, nullable).
    pub filename: Option<String>,
    /// `events.argv` (TEXT, nullable) — JSON array stored as string.
    pub argv: Option<String>,
    /// `events.exit_code` (INTEGER, nullable).
    pub exit_code: Option<i32>,
}

/// Full detail for a single event, including I/O data.
#[derive(Debug, Clone, Serialize)]
pub struct EventDetail {
    /// Core event fields.
    pub summary: EventSummary,
    /// `events.gid` (INTEGER NOT NULL).
    pub gid: u32,
    /// `events.tty_nr` (INTEGER, nullable).
    pub tty_nr: Option<u32>,
    /// `events.fd` (INTEGER, nullable).
    pub fd: Option<u32>,
    /// `events.data` (TEXT, nullable).
    pub data: Option<String>,
    /// `events.data_len` (INTEGER, nullable).
    pub data_len: Option<u32>,
    /// `events.byte_count` (INTEGER, nullable).
    pub byte_count: Option<u64>,
    /// I/O chunks for stdin (fd=0) related to this exec's PID+session.
    pub stdin_data: Vec<IoChunk>,
    /// I/O chunks for stdout/stderr (fd=1,2) related to this exec's PID+session.
    pub stdout_data: Vec<IoChunk>,
    /// Child processes spawned by this process (same session, ppid = this pid).
    pub children: Vec<ChildProcess>,
    /// Parent process summary (looked up by ppid in same session).
    pub parent: Option<ParentProcess>,
}

/// A single I/O data chunk from a read/write event.
#[derive(Debug, Clone, Serialize)]
pub struct IoChunk {
    /// Timestamp of the I/O event.
    pub timestamp: String,
    /// The data payload.
    pub data: String,
    /// Number of bytes in the original syscall.
    pub byte_count: u64,
}

/// Compact summary of a child process, shown in the parent's detail panel.
#[derive(Debug, Clone, Serialize)]
pub struct ChildProcess {
    /// Database event ID (for linking/navigation).
    pub id: i64,
    /// Child PID.
    pub pid: u32,
    /// Kernel comm name.
    pub comm: Option<String>,
    /// Executable path.
    pub filename: Option<String>,
    /// Arguments as JSON array string.
    pub argv: Option<String>,
    /// Exit code (None if still running).
    pub exit_code: Option<i32>,
    /// Whether this child has any captured I/O data.
    pub has_io: bool,
}

/// Compact summary of a parent process, shown in a child's detail panel.
#[derive(Debug, Clone, Serialize)]
pub struct ParentProcess {
    /// Database event ID (for linking/navigation).
    pub id: i64,
    /// Parent's comm name.
    pub comm: Option<String>,
    /// Parent's executable path.
    pub filename: Option<String>,
    /// Parent's arguments as JSON array string.
    pub argv: Option<String>,
}
