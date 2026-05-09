//! Domain types for session events.

use std::fmt::Write as _;

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

/// Wrapper for filter values that supports negation (`!` prefix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterValue<T> {
    /// The parsed value.
    pub value: T,
    /// Whether this filter is negated (`!` prefix).
    pub negated: bool,
}

impl<T> FilterValue<T> {
    /// Create a non-negated filter value.
    pub fn new(value: T) -> Self {
        Self {
            value,
            negated: false,
        }
    }

    /// Create a negated filter value.
    pub fn negated(value: T) -> Self {
        Self {
            value,
            negated: true,
        }
    }
}

/// Parsed filter from the `?q=...` query string.
///
/// The query string is a space-separated list of tokens:
/// - `user:<name>` — match UID (resolved externally)
/// - `comm:<pattern>` — match comm column (LIKE with glob-to-SQL conversion)
/// - `exit:<code>` — match `exit_code` exactly
/// - `session:<id>` — match `session_id` prefix
/// - `pid:<pid>` — match pid exactly
/// - `ppid:<ppid>` — match ppid exactly
/// - `gid:<gid>` — match gid exactly
/// - `euid:<euid>` — match euid exactly
/// - `tty:<tty>` — match tty_nr exactly
/// - `file:<pattern>` — match filename (LIKE with glob-to-SQL conversion)
/// - `!keyword:value` — negate any keyword filter
/// - bare words — substring match on comm + filename + argv
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventFilter {
    /// Raw query string (for display).
    pub raw: Option<String>,
    /// Warnings from parsing (unknown keywords, invalid values).
    pub warnings: Vec<String>,
    /// Parsed `user:<name>` token.
    pub user: Option<FilterValue<String>>,
    /// Parsed `comm:<pattern>` token.
    pub comm: Option<FilterValue<String>>,
    /// Parsed `exit:<code>` token.
    pub exit_code: Option<FilterValue<i32>>,
    /// Parsed `session:<id>` token.
    pub session_id: Option<FilterValue<String>>,
    /// Parsed `pid:<pid>` token.
    pub pid: Option<FilterValue<u32>>,
    /// Parsed `ppid:<ppid>` token.
    pub ppid: Option<FilterValue<u32>>,
    /// Parsed `gid:<gid>` token.
    pub gid: Option<FilterValue<u32>>,
    /// Parsed `euid:<euid>` token.
    pub euid: Option<FilterValue<u32>>,
    /// Parsed `tty:<tty>` token.
    pub tty: Option<FilterValue<u32>>,
    /// Parsed `file:<pattern>` token.
    pub file: Option<FilterValue<String>>,
    /// Parsed `cmd:<pattern>` token (matches filename basename).
    pub cmd: Option<FilterValue<String>>,
    /// Remaining bare words joined by space.
    pub text: Option<String>,
}

/// Known filter keywords for "did you mean?" suggestions.
const KNOWN_KEYWORDS: &[&str] = &[
    "ppid", "pid", "user", "comm", "exit", "session", "gid", "euid", "tty", "file", "cmd",
];

/// Compute Levenshtein edit distance between two strings.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    let mut prev = (0..=n).collect::<Vec<_>>();
    let mut curr = vec![0; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

/// Find the closest known keyword within edit distance 2, if any.
/// On ties, prefer the keyword sharing the longest common prefix.
fn suggest_keyword(unknown: &str) -> Option<&'static str> {
    KNOWN_KEYWORDS
        .iter()
        .filter_map(|&kw| {
            let d = levenshtein(unknown, kw);
            if d > 0 && d <= 2 {
                let prefix_len = unknown
                    .chars()
                    .zip(kw.chars())
                    .take_while(|(a, b)| a == b)
                    .count();
                // Negate prefix_len so longer prefix sorts first.
                #[allow(clippy::cast_possible_wrap)]
                Some((kw, d, -(prefix_len as isize)))
            } else {
                None
            }
        })
        .min_by_key(|&(_, d, neg_prefix)| (d, neg_prefix))
        .map(|(kw, _, _)| kw)
}

impl EventFilter {
    /// Parse a query string into an `EventFilter`.
    ///
    /// Unrecognized `key:value` pairs are treated as bare text.
    /// A `!` prefix on a keyword negates the filter.
    #[allow(clippy::too_many_lines, clippy::similar_names)]
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
            // Check for negation: single `!` prefix before a keyword.
            let (negated, rest) = if let Some(stripped) = token.strip_prefix('!') {
                if stripped.is_empty() || stripped.starts_with('!') || !stripped.contains(':') {
                    // `!` alone, `!!...`, or `!word` (no colon) → bare text
                    bare_words.push(token);
                    continue;
                }
                (true, stripped)
            } else {
                (false, token)
            };

            if let Some((key, value)) = rest.split_once(':') {
                let wrap_str = |v: &str| {
                    if negated {
                        FilterValue::negated(v.to_owned())
                    } else {
                        FilterValue::new(v.to_owned())
                    }
                };
                let wrap_u32 = |v: u32| {
                    if negated {
                        FilterValue::negated(v)
                    } else {
                        FilterValue::new(v)
                    }
                };
                let wrap_i32 = |v: i32| {
                    if negated {
                        FilterValue::negated(v)
                    } else {
                        FilterValue::new(v)
                    }
                };

                match key {
                    "user" => filter.user = Some(wrap_str(value)),
                    "comm" => filter.comm = Some(wrap_str(value)),
                    "exit" => {
                        if let Ok(code) = value.parse::<i32>() {
                            filter.exit_code = Some(wrap_i32(code));
                        } else {
                            filter
                                .warnings
                                .push(format!("\"exit\" expects a number, got \"{value}\""));
                        }
                    }
                    "session" => filter.session_id = Some(wrap_str(value)),
                    "pid" => {
                        if let Ok(p) = value.parse::<u32>() {
                            filter.pid = Some(wrap_u32(p));
                        } else {
                            filter
                                .warnings
                                .push(format!("\"pid\" expects a number, got \"{value}\""));
                        }
                    }
                    "ppid" => {
                        if let Ok(p) = value.parse::<u32>() {
                            filter.ppid = Some(wrap_u32(p));
                        } else {
                            filter
                                .warnings
                                .push(format!("\"ppid\" expects a number, got \"{value}\""));
                        }
                    }
                    "gid" => {
                        if let Ok(g) = value.parse::<u32>() {
                            filter.gid = Some(wrap_u32(g));
                        } else {
                            filter
                                .warnings
                                .push(format!("\"gid\" expects a number, got \"{value}\""));
                        }
                    }
                    "euid" => {
                        if let Ok(e) = value.parse::<u32>() {
                            filter.euid = Some(wrap_u32(e));
                        } else {
                            filter
                                .warnings
                                .push(format!("\"euid\" expects a number, got \"{value}\""));
                        }
                    }
                    "tty" => {
                        if let Ok(t) = value.parse::<u32>() {
                            filter.tty = Some(wrap_u32(t));
                        } else {
                            filter
                                .warnings
                                .push(format!("\"tty\" expects a number, got \"{value}\""));
                        }
                    }
                    "file" => filter.file = Some(wrap_str(value)),
                    "cmd" => filter.cmd = Some(wrap_str(value)),
                    _ => {
                        let mut warning = format!("Unknown filter keyword \"{key}\"");
                        if let Some(suggestion) = suggest_keyword(key) {
                            let _ = write!(warning, " Did you mean \"{suggestion}\"?");
                        }
                        filter.warnings.push(warning);
                        bare_words.push(token);
                    }
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
            && self.ppid.is_none()
            && self.gid.is_none()
            && self.euid.is_none()
            && self.tty.is_none()
            && self.file.is_none()
            && self.cmd.is_none()
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
        assert_eq!(f.user, Some(FilterValue::new("root".to_owned())));
        assert!(f.text.is_none());
    }

    #[test]
    fn parse_comm_filter() {
        let f = EventFilter::parse("comm:bash");
        assert_eq!(f.comm, Some(FilterValue::new("bash".to_owned())));
    }

    #[test]
    fn parse_exit_filter() {
        let f = EventFilter::parse("exit:0");
        assert_eq!(f.exit_code, Some(FilterValue::new(0)));
    }

    #[test]
    fn parse_exit_filter_negative() {
        let f = EventFilter::parse("exit:-1");
        assert_eq!(f.exit_code, Some(FilterValue::new(-1)));
    }

    #[test]
    fn parse_session_filter() {
        let f = EventFilter::parse("session:ox_abc");
        assert_eq!(f.session_id, Some(FilterValue::new("ox_abc".to_owned())));
    }

    #[test]
    fn parse_pid_filter() {
        let f = EventFilter::parse("pid:1234");
        assert_eq!(f.pid, Some(FilterValue::new(1234)));
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
        assert_eq!(f.user, Some(FilterValue::new("root".to_owned())));
        assert_eq!(f.comm, Some(FilterValue::new("bash".to_owned())));
        assert_eq!(f.exit_code, Some(FilterValue::new(0)));
        assert_eq!(f.text.as_deref(), Some("cargo"));
    }

    #[test]
    fn parse_unknown_key_treated_as_bare_word() {
        let f = EventFilter::parse("foo:bar");
        assert_eq!(f.text.as_deref(), Some("foo:bar"));
        assert_eq!(f.warnings.len(), 1);
        assert!(f.warnings[0].contains("foo"));
    }

    #[test]
    fn parse_invalid_exit_ignored() {
        let f = EventFilter::parse("exit:notanumber");
        assert_eq!(f.exit_code, None, "invalid exit code should be None");
        // "exit:notanumber" is a recognized key — exit_code just fails to parse.
        // The token is consumed by the match arm, so it won't appear in text.
        assert!(f.text.is_none());
        assert_eq!(f.warnings.len(), 1);
        assert!(f.warnings[0].contains("expects a number"));
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

    // --- New filter keyword tests ---

    #[test]
    fn parse_ppid_filter() {
        let f = EventFilter::parse("ppid:1");
        assert_eq!(f.ppid, Some(FilterValue::new(1)));
    }

    #[test]
    fn parse_ppid_invalid() {
        let f = EventFilter::parse("ppid:abc");
        assert_eq!(f.ppid, None);
    }

    #[test]
    fn parse_gid_filter() {
        let f = EventFilter::parse("gid:1000");
        assert_eq!(f.gid, Some(FilterValue::new(1000)));
    }

    #[test]
    fn parse_euid_filter() {
        let f = EventFilter::parse("euid:0");
        assert_eq!(f.euid, Some(FilterValue::new(0)));
    }

    #[test]
    fn parse_tty_filter() {
        let f = EventFilter::parse("tty:0");
        assert_eq!(f.tty, Some(FilterValue::new(0)));
    }

    #[test]
    fn parse_file_filter() {
        let f = EventFilter::parse("file:/usr/bin/*");
        assert_eq!(f.file, Some(FilterValue::new("/usr/bin/*".to_owned())));
    }

    #[test]
    fn parse_file_glob_question_mark() {
        let f = EventFilter::parse("file:/usr/bin/bas?");
        assert_eq!(f.file, Some(FilterValue::new("/usr/bin/bas?".to_owned())));
    }

    // --- Negation tests ---

    #[test]
    fn parse_negation_exact() {
        let f = EventFilter::parse("!exit:0");
        assert_eq!(f.exit_code, Some(FilterValue::negated(0)));
    }

    #[test]
    fn parse_negation_glob() {
        let f = EventFilter::parse("!comm:bash");
        assert_eq!(f.comm, Some(FilterValue::negated("bash".to_owned())));
    }

    #[test]
    fn parse_negation_prefix() {
        let f = EventFilter::parse("!session:ox_");
        assert_eq!(f.session_id, Some(FilterValue::negated("ox_".to_owned())));
    }

    #[test]
    fn parse_bang_alone_is_bare() {
        let f = EventFilter::parse("!");
        assert_eq!(f.text.as_deref(), Some("!"));
    }

    #[test]
    fn parse_bang_no_keyword() {
        let f = EventFilter::parse("!foo");
        assert_eq!(f.text.as_deref(), Some("!foo"));
    }

    #[test]
    fn parse_double_bang() {
        let f = EventFilter::parse("!!exit:0");
        assert_eq!(f.text.as_deref(), Some("!!exit:0"));
        assert_eq!(f.exit_code, None);
    }

    #[test]
    fn parse_user_numeric() {
        let f = EventFilter::parse("user:1000");
        assert_eq!(f.user, Some(FilterValue::new("1000".to_owned())));
    }

    // --- Warning tests ---

    #[test]
    fn parse_unknown_keyword_warns() {
        let f = EventFilter::parse("foo:bar");
        assert_eq!(f.warnings.len(), 1);
        assert!(f.warnings[0].contains("foo"));
    }

    #[test]
    fn parse_known_keywords_no_warnings() {
        let f = EventFilter::parse("pid:1 comm:bash");
        assert!(f.warnings.is_empty());
    }

    #[test]
    fn parse_numeric_field_invalid_warns() {
        let f = EventFilter::parse("pid:abc");
        assert_eq!(f.warnings.len(), 1);
        assert!(f.warnings[0].contains("expects a number"));
        assert!(f.warnings[0].contains("abc"));
    }

    #[test]
    fn parse_numeric_field_valid_no_warning() {
        let f = EventFilter::parse("pid:123");
        assert!(f.warnings.is_empty());
    }

    #[test]
    fn parse_did_you_mean() {
        let f = EventFilter::parse("ppd:1");
        assert_eq!(f.warnings.len(), 1);
        assert!(f.warnings[0].contains("Did you mean \"ppid\"?"));
    }

    #[test]
    fn parse_did_you_mean_comm() {
        let f = EventFilter::parse("commm:bash");
        assert_eq!(f.warnings.len(), 1);
        assert!(f.warnings[0].contains("Did you mean \"comm\"?"));
    }

    #[test]
    fn parse_exit_invalid_warns() {
        let f = EventFilter::parse("exit:abc");
        assert_eq!(f.warnings.len(), 1);
        assert!(f.warnings[0].contains("expects a number"));
    }

    #[test]
    fn parse_warnings_dont_affect_is_empty() {
        let f = EventFilter::parse("foo:bar");
        // has warning and bare text, but bare text makes it non-empty
        assert!(!f.is_empty());
        // A filter with only warnings and no actual criteria would need
        // a token that doesn't become bare text — but unknown keys do
        // become bare text, so this is fine.
    }

    // --- cmd: filter tests ---

    #[test]
    fn parse_cmd_filter() {
        let f = EventFilter::parse("cmd:ps");
        assert_eq!(f.cmd, Some(FilterValue::new("ps".to_owned())));
    }

    #[test]
    fn parse_cmd_glob() {
        let f = EventFilter::parse("cmd:git*");
        assert_eq!(f.cmd, Some(FilterValue::new("git*".to_owned())));
    }

    #[test]
    fn parse_cmd_negated() {
        let f = EventFilter::parse("!cmd:git");
        assert_eq!(f.cmd, Some(FilterValue::negated("git".to_owned())));
    }
}
