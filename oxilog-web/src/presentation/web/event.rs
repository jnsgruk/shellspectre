//! Presentation view models for events.

use crate::domain::event::{EventDetail, EventSummary};

use super::username::resolve_uid;

/// Formatted event summary for display in the event table.
///
/// All fields are pre-formatted strings ready for template rendering.
#[derive(Debug, Clone)]
pub struct EventSummaryView {
    /// Database ID (for constructing detail URLs).
    pub id: i64,
    /// Formatted timestamp, e.g. "2026-05-10 14:32:01".
    pub timestamp: String,
    /// Session ID, truncated to 8 chars for display with "ox_" prefix.
    pub session_id_short: String,
    /// Full session ID (for tooltips / detail view).
    pub session_id: String,
    /// UID as string. Username resolution deferred to Stage 5.
    pub user: String,
    /// Command name, or "\u{2014}" if absent.
    pub comm: String,
    /// Command + args, truncated to `max_cmd_len` chars.
    pub command_display: String,
    /// Full command + args (for tooltip).
    pub command_full: String,
    /// Exit code display: "0", "1", "\u{2014}" (for None).
    pub exit_code: String,
    /// CSS class for exit code styling.
    pub exit_code_class: &'static str,
}

/// Maximum length for the truncated command display.
const MAX_CMD_DISPLAY_LEN: usize = 40;

impl EventSummaryView {
    /// Create a view from a domain `EventSummary`.
    pub fn from_summary(s: &EventSummary) -> Self {
        let comm = s.comm.clone().unwrap_or_else(|| "\u{2014}".to_owned());

        // Build full command string from filename + argv.
        let command_full = build_command_string(s);
        let command_display = truncate(&command_full, MAX_CMD_DISPLAY_LEN);

        // Truncate session ID for column display.
        let session_id_short = if s.session_id.len() > 10 {
            format!("{}\u{2026}", &s.session_id[..10])
        } else {
            s.session_id.clone()
        };

        // Format timestamp: strip fractional seconds if present.
        let timestamp = s
            .timestamp
            .split('.')
            .next()
            .unwrap_or(&s.timestamp)
            .to_owned();

        let (exit_code, exit_code_class) = match s.exit_code {
            Some(0) => ("0".to_owned(), "text-green-400"),
            Some(code) => (code.to_string(), "text-red-400"),
            None => ("\u{2014}".to_owned(), "text-gray-500"),
        };

        Self {
            id: s.id,
            timestamp,
            session_id_short,
            session_id: s.session_id.clone(),
            user: resolve_uid(s.uid),
            comm,
            command_display,
            command_full,
            exit_code,
            exit_code_class,
        }
    }
}

/// Build a display string from filename/argv.
///
/// Prefers argv if available (JSON array), falls back to filename, then comm.
pub fn build_command_string(s: &EventSummary) -> String {
    // Try parsing argv JSON array.
    if let Some(ref argv_str) = s.argv
        && let Ok(argv) = serde_json::from_str::<Vec<String>>(argv_str)
        && !argv.is_empty()
    {
        return argv.join(" ");
    }
    // Fallback to filename.
    if let Some(ref filename) = s.filename {
        return filename.clone();
    }
    // Fallback to comm.
    s.comm.clone().unwrap_or_default()
}

/// Formatted event detail for the expansion panel.
#[derive(Debug, Clone)]
pub struct EventDetailView {
    /// Event ID.
    pub id: i64,
    /// Full session ID.
    pub session_id: String,
    /// PID.
    pub pid: String,
    /// PPID.
    pub ppid: String,
    /// UID.
    pub uid: String,
    /// EUID.
    pub euid: String,
    /// GID.
    pub gid: String,
    /// TTY device string, e.g. "pts/3" or "\u{2014}".
    pub tty: String,
    /// Full command line (filename + argv joined).
    pub full_command: String,
    /// Event type.
    pub event_type: String,
    /// Timestamp.
    pub timestamp: String,
    /// Exit code display.
    pub exit_code: String,
    /// Whether there is any stdin data.
    pub has_stdin: bool,
    /// Concatenated stdin data for display in `<pre>`.
    pub stdin_data: String,
    /// Total stdin bytes.
    pub stdin_bytes: u64,
    /// Whether there is any stdout data.
    pub has_stdout: bool,
    /// Concatenated stdout data for display in `<pre>`.
    pub stdout_data: String,
    /// Total stdout bytes.
    pub stdout_bytes: u64,
}

impl EventDetailView {
    /// Create from a domain `EventDetail`.
    pub fn from_detail(d: &EventDetail) -> Self {
        let tty = match d.tty_nr {
            Some(nr) if nr > 0 => {
                let major = (nr >> 8) & 0xFF;
                let minor = nr & 0xFF;
                if major == 136 {
                    format!("pts/{minor}")
                } else {
                    format!("{major}/{minor}")
                }
            }
            _ => "\u{2014}".to_owned(),
        };

        let full_command = build_command_string(&d.summary);

        let stdin_data: String = d.stdin_data.iter().map(|c| c.data.as_str()).collect();
        let stdin_bytes: u64 = d.stdin_data.iter().map(|c| c.byte_count).sum();
        let stdout_data: String = d.stdout_data.iter().map(|c| c.data.as_str()).collect();
        let stdout_bytes: u64 = d.stdout_data.iter().map(|c| c.byte_count).sum();

        Self {
            id: d.summary.id,
            session_id: d.summary.session_id.clone(),
            pid: d.summary.pid.to_string(),
            ppid: d.summary.ppid.to_string(),
            uid: format!("{} ({})", resolve_uid(d.summary.uid), d.summary.uid),
            euid: format!("{} ({})", resolve_uid(d.summary.euid), d.summary.euid),
            gid: d.gid.to_string(),
            tty,
            full_command,
            event_type: d.summary.event_type.clone(),
            timestamp: d.summary.timestamp.clone(),
            exit_code: d.summary.exit_code
                .map_or_else(|| "\u{2014}".to_owned(), |c| c.to_string()),
            has_stdin: !d.stdin_data.is_empty(),
            stdin_data,
            stdin_bytes,
            has_stdout: !d.stdout_data.is_empty(),
            stdout_data,
            stdout_bytes,
        }
    }
}

/// Truncate a string to `max_len` chars, appending "\u{2026}" if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_owned()
    } else {
        let truncated: String = s.chars().take(max_len - 1).collect();
        format!("{truncated}\u{2026}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
use crate::domain::event::{EventDetail, EventSummary, IoChunk};

    fn make_summary() -> EventSummary {
        EventSummary {
            id: 1,
            timestamp: "2026-05-10T14:32:01.123456".to_owned(),
            session_id: "ox_abc123def456".to_owned(),
            event_type: "exec".to_owned(),
            pid: 1234,
            ppid: 1000,
            uid: 1000,
            euid: 1000,
            comm: Some("cargo".to_owned()),
            filename: Some("/usr/bin/cargo".to_owned()),
            argv: Some(r#"["cargo","build","--release"]"#.to_owned()),
            exit_code: Some(0),
        }
    }

    #[test]
    fn from_summary_formats_timestamp() {
        let view = EventSummaryView::from_summary(&make_summary());
        assert_eq!(view.timestamp, "2026-05-10T14:32:01");
    }

    #[test]
    fn from_summary_truncates_session_id() {
        let view = EventSummaryView::from_summary(&make_summary());
        assert_eq!(view.session_id_short, "ox_abc123d\u{2026}");
        assert_eq!(view.session_id, "ox_abc123def456");
    }

    #[test]
    fn from_summary_builds_command_from_argv() {
        let view = EventSummaryView::from_summary(&make_summary());
        assert_eq!(view.command_full, "cargo build --release");
    }

    #[test]
    fn from_summary_exit_code_zero_is_green() {
        let view = EventSummaryView::from_summary(&make_summary());
        assert_eq!(view.exit_code, "0");
        assert_eq!(view.exit_code_class, "text-green-400");
    }

    #[test]
    fn from_summary_exit_code_nonzero_is_red() {
        let mut s = make_summary();
        s.exit_code = Some(1);
        let view = EventSummaryView::from_summary(&s);
        assert_eq!(view.exit_code, "1");
        assert_eq!(view.exit_code_class, "text-red-400");
    }

    #[test]
    fn from_summary_exit_code_none_is_dash() {
        let mut s = make_summary();
        s.exit_code = None;
        let view = EventSummaryView::from_summary(&s);
        assert_eq!(view.exit_code, "\u{2014}");
        assert_eq!(view.exit_code_class, "text-gray-500");
    }

    #[test]
    fn from_summary_fallback_to_filename() {
        let mut s = make_summary();
        s.argv = None;
        let view = EventSummaryView::from_summary(&s);
        assert_eq!(view.command_full, "/usr/bin/cargo");
    }

    #[test]
    fn from_summary_fallback_to_comm() {
        let mut s = make_summary();
        s.argv = None;
        s.filename = None;
        let view = EventSummaryView::from_summary(&s);
        assert_eq!(view.command_full, "cargo");
    }

    #[test]
    fn truncate_long_string() {
        let long = "a".repeat(50);
        let result = truncate(&long, 40);
        assert_eq!(result.chars().count(), 40);
        assert!(result.ends_with('\u{2026}'));
    }

    #[test]
    fn truncate_short_string() {
        let result = truncate("short", 40);
        assert_eq!(result, "short");
    }

    fn make_detail() -> EventDetail {
        EventDetail {
            summary: EventSummary {
                id: 1,
                timestamp: "2026-05-10T14:32:01".to_owned(),
                session_id: "ox_abc123".to_owned(),
                event_type: "exec".to_owned(),
                pid: 4821,
                ppid: 4800,
                uid: 1000,
                euid: 1000,
                comm: Some("cat".to_owned()),
                filename: Some("/usr/bin/cat".to_owned()),
                argv: Some(r#"["cat","secret.txt"]"#.to_owned()),
                exit_code: Some(0),
            },
            gid: 1000,
            tty_nr: Some(0x8803), // major 136, minor 3 → pts/3
            fd: None,
            data: None,
            data_len: None,
            byte_count: None,
            stdin_data: vec![],
            stdout_data: vec![IoChunk {
                timestamp: "2026-05-10T14:32:02".to_owned(),
                data: "TOP SECRET\n".to_owned(),
                byte_count: 11,
            }],
        }
    }

    #[test]
    fn tty_nr_to_pts() {
        let view = EventDetailView::from_detail(&make_detail());
        assert_eq!(view.tty, "pts/3");
    }

    #[test]
    fn stdout_data_concatenated() {
        let view = EventDetailView::from_detail(&make_detail());
        assert_eq!(view.stdout_data, "TOP SECRET\n");
        assert_eq!(view.stdout_bytes, 11);
        assert!(view.has_stdout);
    }

    #[test]
    fn no_stdin_data() {
        let view = EventDetailView::from_detail(&make_detail());
        assert!(!view.has_stdin);
        assert!(view.stdin_data.is_empty());
    }

    #[test]
    fn full_command_from_argv() {
        let view = EventDetailView::from_detail(&make_detail());
        assert_eq!(view.full_command, "cat secret.txt");
    }

    #[test]
    fn tty_nr_zero_shows_dash() {
        let mut d = make_detail();
        d.tty_nr = Some(0);
        let view = EventDetailView::from_detail(&d);
        assert_eq!(view.tty, "\u{2014}");
    }

    #[test]
    fn tty_nr_none_shows_dash() {
        let mut d = make_detail();
        d.tty_nr = None;
        let view = EventDetailView::from_detail(&d);
        assert_eq!(view.tty, "\u{2014}");
    }
}
