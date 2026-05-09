//! Presentation view models for events.

use crate::domain::event::EventSummary;

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
            user: s.uid.to_string(),
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
    use crate::domain::event::EventSummary;

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
}
