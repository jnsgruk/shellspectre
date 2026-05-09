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

/// Parsed filter from the `?q=...` query string.
///
/// The query string is a space-separated list of tokens:
/// - `user:<name>` — match UID (resolved externally)
/// - `comm:<pattern>` — match comm column (LIKE with glob-to-SQL conversion)
/// - `exit:<code>` — match `exit_code` exactly
/// - `session:<id>` — match `session_id` prefix
/// - `pid:<pid>` — match pid exactly
/// - bare words — substring match on comm + filename + argv
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventFilter {
    /// Raw query string (for display).
    pub raw: Option<String>,
    /// Parsed `user:<name>` token.
    pub user: Option<String>,
    /// Parsed `comm:<pattern>` token.
    pub comm: Option<String>,
    /// Parsed `exit:<code>` token.
    pub exit_code: Option<i32>,
    /// Parsed `session:<id>` token.
    pub session_id: Option<String>,
    /// Parsed `pid:<pid>` token.
    pub pid: Option<u32>,
    /// Remaining bare words joined by space.
    pub text: Option<String>,
}

impl EventFilter {
    /// Parse a query string into an `EventFilter`.
    ///
    /// Unrecognized `key:value` pairs are treated as bare text.
    pub fn parse(query: &str) -> Self {
        let query = query.trim();
        if query.is_empty() {
            return Self::default();
        }

        let mut filter = Self {
            raw: Some(query.to_owned()),
            ..Self::default()
        };

        let mut bare_words = Vec::new();

        for token in query.split_whitespace() {
            if let Some((key, value)) = token.split_once(':') {
                match key {
                    "user" => filter.user = Some(value.to_owned()),
                    "comm" => filter.comm = Some(value.to_owned()),
                    "exit" => filter.exit_code = value.parse().ok(),
                    "session" => filter.session_id = Some(value.to_owned()),
                    "pid" => filter.pid = value.parse().ok(),
                    _ => bare_words.push(token),
                }
            } else {
                bare_words.push(token);
            }
        }

        if !bare_words.is_empty() {
            filter.text = Some(bare_words.join(" "));
        }

        filter
    }

    /// Returns `true` if no filter criteria are set.
    pub fn is_empty(&self) -> bool {
        self.user.is_none()
            && self.comm.is_none()
            && self.exit_code.is_none()
            && self.session_id.is_none()
            && self.pid.is_none()
            && self.text.is_none()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_query() {
        let f = EventFilter::parse("");
        assert!(f.is_empty(), "empty string should produce empty filter");
        assert_eq!(f.raw, None);
    }

    #[test]
    fn parse_whitespace_query() {
        let f = EventFilter::parse("   ");
        assert!(f.is_empty(), "whitespace should produce empty filter");
    }

    #[test]
    fn parse_user_filter() {
        let f = EventFilter::parse("user:root");
        assert_eq!(f.user.as_deref(), Some("root"));
        assert!(f.text.is_none());
    }

    #[test]
    fn parse_comm_filter() {
        let f = EventFilter::parse("comm:bash");
        assert_eq!(f.comm.as_deref(), Some("bash"));
    }

    #[test]
    fn parse_exit_filter() {
        let f = EventFilter::parse("exit:0");
        assert_eq!(f.exit_code, Some(0));
    }

    #[test]
    fn parse_exit_filter_negative() {
        let f = EventFilter::parse("exit:-1");
        assert_eq!(f.exit_code, Some(-1));
    }

    #[test]
    fn parse_session_filter() {
        let f = EventFilter::parse("session:ox_abc");
        assert_eq!(f.session_id.as_deref(), Some("ox_abc"));
    }

    #[test]
    fn parse_pid_filter() {
        let f = EventFilter::parse("pid:1234");
        assert_eq!(f.pid, Some(1234));
    }

    #[test]
    fn parse_bare_words() {
        let f = EventFilter::parse("cargo build");
        assert_eq!(f.text.as_deref(), Some("cargo build"));
        assert!(f.comm.is_none());
    }

    #[test]
    fn parse_mixed_filters() {
        let f = EventFilter::parse("user:root comm:bash cargo exit:0");
        assert_eq!(f.user.as_deref(), Some("root"));
        assert_eq!(f.comm.as_deref(), Some("bash"));
        assert_eq!(f.exit_code, Some(0));
        assert_eq!(f.text.as_deref(), Some("cargo"));
    }

    #[test]
    fn parse_unknown_key_treated_as_bare_word() {
        let f = EventFilter::parse("foo:bar");
        assert_eq!(f.text.as_deref(), Some("foo:bar"));
    }

    #[test]
    fn parse_invalid_exit_ignored() {
        let f = EventFilter::parse("exit:notanumber");
        assert_eq!(f.exit_code, None, "invalid exit code should be None");
        // "exit:notanumber" is a recognized key — exit_code just fails to parse.
        // The token is consumed by the match arm, so it won't appear in text.
        assert!(f.text.is_none());
    }

    #[test]
    fn is_empty_with_no_criteria() {
        let f = EventFilter::default();
        assert!(f.is_empty());
    }

    #[test]
    fn is_empty_false_with_criteria() {
        let f = EventFilter::parse("pid:1");
        assert!(!f.is_empty());
    }
}
