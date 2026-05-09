//! Presentation view models for events.

use crate::domain::event::{ChildProcess, EventDetail, EventSummary};

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
    /// Basename of the executed binary, e.g. "ps", "cargo". Bold in UI.
    pub command_name: String,
    /// Directory portion of the full path, e.g. "/usr/bin/". Empty when
    /// only a bare name is available. Rendered in a lighter font.
    pub command_dir: String,
    /// Arguments (argv[1..]), truncated, for display after the name.
    pub command_args: String,
    /// Full command + args (for tooltip on the cell).
    pub command_full: String,
    /// Exit code display: "0", "1", "\u{2014}" (for None).
    pub exit_code: String,
    /// CSS class for exit code styling.
    pub exit_code_class: &'static str,
    /// Raw UID for click-to-filter.
    pub uid: u32,
    /// Raw exit code for click-to-filter (None when not yet exited).
    pub exit_code_raw: Option<i32>,
}

/// Maximum length for the truncated args display.
const MAX_ARGS_DISPLAY_LEN: usize = 40;

/// Check whether a path is an fd-based execution path (e.g. `/proc/self/fd/9`).
///
/// Matches:
/// - `/proc/self/fd/<N>`
/// - `/proc/<pid>/fd/<N>`
/// - `/dev/fd/<N>`
fn is_fd_path(path: &str) -> bool {
    if let Some(rest) = path.strip_prefix("/proc/") {
        // Either "self/fd/<N>" or "<pid>/fd/<N>"
        let after_segment = rest.split_once('/').map(|(_, tail)| tail);
        matches!(after_segment, Some(tail) if tail.strip_prefix("fd/")
            .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())))
    } else if let Some(rest) = path.strip_prefix("/dev/fd/") {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
    } else {
        false
    }
}

/// Extract `argv[0]` from an argv JSON string.
fn parse_argv0(argv: Option<&str>) -> Option<String> {
    argv.and_then(|a| serde_json::from_str::<Vec<String>>(a).ok())
        .and_then(|v| v.into_iter().next())
        .filter(|s| !s.is_empty())
}

impl EventSummaryView {
    /// Create a view from a domain `EventSummary`.
    #[allow(clippy::too_many_lines)]
    pub fn from_summary(s: &EventSummary) -> Self {
        let comm = s.comm.clone().unwrap_or_else(|| "\u{2014}".to_owned());

        // Check for fd-path executions first — when the kernel filename is an
        // fd path like `/proc/self/fd/9`, the basename is just the fd number
        // which is useless. Prefer argv[0] or comm in that case.
        let filename_ref = s.filename.as_deref().filter(|f| !f.is_empty());
        let is_fd = filename_ref.is_some_and(is_fd_path);

        let (command_dir, command_name) = if is_fd {
            let fd_path = filename_ref.unwrap_or_default().to_owned();
            let name = parse_argv0(s.argv.as_deref()).map_or_else(
                || comm.clone(),
                |a| {
                    // Use basename of argv[0] if it contains a path.
                    a.rsplit('/').next().unwrap_or(&a).to_owned()
                },
            );
            (fd_path, name)
        } else {
            // Resolve the full path: prefer filename, fall back to argv[0], then comm.
            let full_path = filename_ref
                .or_else(|| {
                    parse_argv0(s.argv.as_deref())
                        .as_deref()
                        .and(s.argv.as_deref())
                })
                .unwrap_or("")
                .to_owned();

            // Split path into directory and basename.
            // Only treat as a path if it contains a '/'.
            if full_path.contains('/') {
                let dir = full_path
                    .rfind('/')
                    .map(|i| format!("{}/", &full_path[..i]))
                    .unwrap_or_default();
                let name = full_path
                    .rfind('/')
                    .map_or_else(|| full_path.clone(), |i| full_path[i + 1..].to_owned());
                (dir, name)
            } else {
                // Bare name (e.g. "ps" without a path) — no dir to show.
                let name = if full_path.is_empty() {
                    comm.clone()
                } else {
                    full_path.clone()
                };
                (String::new(), name)
            }
        };

        // Args are argv[1..], joined with spaces.
        let command_args = parse_args_tail(s);
        let command_args = truncate(&command_args, MAX_ARGS_DISPLAY_LEN);

        // Full command for tooltip: name + args (dir shown separately in UI).
        let command_full = if command_args.is_empty() {
            command_name.clone()
        } else {
            format!("{command_name} {command_args}")
        };

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
            command_name,
            command_dir,
            command_args,
            command_full,
            exit_code,
            exit_code_class,
            uid: s.uid,
            exit_code_raw: s.exit_code,
        }
    }
}

/// Build a display string from filename/argv — used by the detail view.
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

/// Extract argv[1..] as a space-joined string (the arguments after the binary name).
fn parse_args_tail(s: &EventSummary) -> String {
    if let Some(ref argv_str) = s.argv
        && let Ok(argv) = serde_json::from_str::<Vec<String>>(argv_str)
        && argv.len() > 1
    {
        return argv[1..].join(" ");
    }
    String::new()
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
    /// Stdin data rendered as HTML (ANSI escape codes converted to `<span>` tags).
    pub stdin_html: String,
    /// Total stdin bytes.
    pub stdin_bytes: u64,
    /// Whether there is any stdout data.
    pub has_stdout: bool,
    /// Stdout/stderr data rendered as HTML (ANSI escape codes converted to `<span>` tags).
    pub stdout_html: String,
    /// Total stdout bytes.
    pub stdout_bytes: u64,
    /// Raw UID for click-to-filter.
    pub uid_raw: u32,
    /// Raw EUID for click-to-filter.
    pub euid_raw: u32,
    /// Raw TTY number for click-to-filter (None when no TTY).
    pub tty_nr_raw: Option<u32>,
    /// Raw exit code for click-to-filter (None when not yet exited).
    pub exit_code_raw: Option<i32>,
    /// Child processes spawned by this process.
    pub children: Vec<ChildProcessView>,
    /// Parent process info (if found in the same session).
    pub parent: Option<ParentProcessView>,
}

/// View model for a child process displayed in the parent's detail panel.
#[derive(Debug, Clone)]
pub struct ChildProcessView {
    /// Database event ID.
    pub id: i64,
    /// PID.
    pub pid: u32,
    /// Formatted command string.
    pub command: String,
    /// Exit code display.
    pub exit_code: String,
    /// CSS class for exit code.
    pub exit_code_class: &'static str,
    /// Whether this child has captured I/O.
    pub has_io: bool,
}

/// View model for a parent process link in the child's detail panel.
#[derive(Debug, Clone)]
pub struct ParentProcessView {
    /// Database event ID (for navigation).
    pub id: i64,
    /// Formatted command string.
    pub command: String,
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

        let stdin_raw: String = d.stdin_data.iter().map(|c| c.data.as_str()).collect();
        let stdin_bytes: u64 = d.stdin_data.iter().map(|c| c.byte_count).sum();
        let stdout_raw: String = d.stdout_data.iter().map(|c| c.data.as_str()).collect();
        let stdout_bytes: u64 = d.stdout_data.iter().map(|c| c.byte_count).sum();

        let stdin_html = ansi_to_html(&stdin_raw);
        let stdout_html = ansi_to_html(&stdout_raw);

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
            exit_code: d
                .summary
                .exit_code
                .map_or_else(|| "\u{2014}".to_owned(), |c| c.to_string()),
            has_stdin: !d.stdin_data.is_empty(),
            stdin_html,
            stdin_bytes,
            has_stdout: !d.stdout_data.is_empty(),
            stdout_html,
            stdout_bytes,
            uid_raw: d.summary.uid,
            euid_raw: d.summary.euid,
            tty_nr_raw: d.tty_nr.filter(|&nr| nr > 0),
            exit_code_raw: d.summary.exit_code,
            children: d
                .children
                .iter()
                .map(ChildProcessView::from_child)
                .collect(),
            parent: d.parent.as_ref().map(ParentProcessView::from_parent),
        }
    }
}

impl ChildProcessView {
    fn from_child(c: &ChildProcess) -> Self {
        let command = build_child_command_string(c);
        let (exit_code, exit_code_class) = match c.exit_code {
            Some(0) => ("0".to_owned(), "text-green-400"),
            Some(code) => (code.to_string(), "text-red-400"),
            None => ("\u{2014}".to_owned(), "text-gray-500"),
        };
        Self {
            id: c.id,
            pid: c.pid,
            command,
            exit_code,
            exit_code_class,
            has_io: c.has_io,
        }
    }
}

impl ParentProcessView {
    fn from_parent(p: &crate::domain::event::ParentProcess) -> Self {
        let command = if let Some(ref argv_str) = p.argv
            && let Ok(argv) = serde_json::from_str::<Vec<String>>(argv_str)
            && !argv.is_empty()
        {
            argv.join(" ")
        } else if let Some(ref filename) = p.filename {
            filename.clone()
        } else {
            p.comm.clone().unwrap_or_default()
        };
        Self { id: p.id, command }
    }
}

/// Build a display string from a child process's fields.
fn build_child_command_string(c: &ChildProcess) -> String {
    if let Some(ref argv_str) = c.argv
        && let Ok(argv) = serde_json::from_str::<Vec<String>>(argv_str)
        && !argv.is_empty()
    {
        return argv.join(" ");
    }
    if let Some(ref filename) = c.filename {
        return filename.clone();
    }
    c.comm.clone().unwrap_or_default()
}

/// Convert a raw string (possibly containing ANSI escape sequences) to HTML.
///
/// ANSI SGR codes (colours, bold, etc.) become `<span style="...">` elements.
/// 4-bit colours use CSS custom properties with an `ansi-` prefix
/// (e.g. `var(--ansi-red, #fallback)`), so the caller can theme them via CSS.
/// If conversion fails, the text is HTML-escaped and returned as plain text.
fn ansi_to_html(raw: &str) -> String {
    ansi_to_html::Converter::new()
        .four_bit_var_prefix(Some("ansi-".to_owned()))
        .convert(raw)
        .unwrap_or_else(|_| {
            // Fallback: HTML-escape the raw bytes so nothing leaks into the DOM.
            raw.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
        })
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
            execution_id: 1,
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
        // argv is ["cargo","build","--release"], filename is /usr/bin/cargo
        assert_eq!(view.command_name, "cargo");
        assert_eq!(view.command_dir, "/usr/bin/");
        assert_eq!(view.command_args, "build --release");
        assert_eq!(view.command_full, "cargo build --release");
    }

    #[test]
    fn from_summary_fallback_to_filename() {
        let mut s = make_summary();
        s.argv = None;
        let view = EventSummaryView::from_summary(&s);
        assert_eq!(view.command_name, "cargo");
        assert_eq!(view.command_dir, "/usr/bin/");
        assert_eq!(view.command_args, "");
        assert_eq!(view.command_full, "cargo");
    }

    #[test]
    fn from_summary_fallback_to_comm() {
        let mut s = make_summary();
        s.argv = None;
        s.filename = None;
        let view = EventSummaryView::from_summary(&s);
        assert_eq!(view.command_name, "cargo");
        assert_eq!(view.command_dir, "");
        assert_eq!(view.command_args, "");
        assert_eq!(view.command_full, "cargo");
    }

    #[test]
    fn from_summary_bare_command_no_dir() {
        let mut s = make_summary();
        s.filename = Some("ps".to_owned());
        s.argv = Some(r#"["ps","-ao","ppid,args"]"#.to_owned());
        let view = EventSummaryView::from_summary(&s);
        assert_eq!(view.command_name, "ps");
        assert_eq!(view.command_dir, "");
        assert_eq!(view.command_args, "-ao ppid,args");
    }

    #[test]
    fn from_summary_snap_path() {
        let mut s = make_summary();
        s.filename = Some("/snap/mise/111/bin/mise".to_owned());
        s.argv = Some(r#"["/snap/mise/111/bin/mise","hook-env","-s","fish"]"#.to_owned());
        let view = EventSummaryView::from_summary(&s);
        assert_eq!(view.command_name, "mise");
        assert_eq!(view.command_dir, "/snap/mise/111/bin/");
        assert_eq!(view.command_args, "hook-env -s fish");
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
                execution_id: 1,
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
            children: vec![],
            parent: None,
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
        // Plain text with no ANSI codes passes through as-is.
        assert_eq!(view.stdout_html, "TOP SECRET\n");
        assert_eq!(view.stdout_bytes, 11);
        assert!(view.has_stdout);
    }

    #[test]
    fn no_stdin_data() {
        let view = EventDetailView::from_detail(&make_detail());
        assert!(!view.has_stdin);
        assert!(view.stdin_html.is_empty());
    }

    #[test]
    fn ansi_colour_converted_to_span() {
        // Bold green "ok" followed by reset.
        let html = ansi_to_html("\x1b[1;32mok\x1b[0m");
        assert!(html.contains("<span"), "should produce span tags: {html}");
        assert!(html.contains("ok"), "should preserve text: {html}");
        assert!(
            !html.contains("\x1b"),
            "should strip escape sequences: {html}"
        );
        // 4-bit colours should use CSS custom properties with the ansi- prefix.
        assert!(
            html.contains("--ansi-"),
            "should use --ansi- CSS vars: {html}"
        );
    }

    #[test]
    fn ansi_plain_text_unchanged() {
        let html = ansi_to_html("hello world\n");
        assert_eq!(html, "hello world\n");
    }

    #[test]
    fn fd_path_proc_self_uses_argv0() {
        let mut s = make_summary();
        s.filename = Some("/proc/self/fd/9".to_owned());
        s.argv = Some(r#"["systemd-executor","--deserialize","57"]"#.to_owned());
        let view = EventSummaryView::from_summary(&s);
        assert_eq!(view.command_name, "systemd-executor");
        assert_eq!(view.command_dir, "/proc/self/fd/9");
        assert_eq!(view.command_args, "--deserialize 57");
    }

    #[test]
    fn fd_path_dev_fd_uses_argv0() {
        let mut s = make_summary();
        s.filename = Some("/dev/fd/3".to_owned());
        s.argv = Some(r#"["my-program","--flag"]"#.to_owned());
        let view = EventSummaryView::from_summary(&s);
        assert_eq!(view.command_name, "my-program");
        assert_eq!(view.command_dir, "/dev/fd/3");
    }

    #[test]
    fn fd_path_proc_pid_uses_argv0() {
        let mut s = make_summary();
        s.filename = Some("/proc/12345/fd/9".to_owned());
        s.argv = Some(r#"["some-daemon"]"#.to_owned());
        let view = EventSummaryView::from_summary(&s);
        assert_eq!(view.command_name, "some-daemon");
        assert_eq!(view.command_dir, "/proc/12345/fd/9");
    }

    #[test]
    fn fd_path_empty_argv_falls_back_to_comm() {
        let mut s = make_summary();
        s.filename = Some("/proc/self/fd/9".to_owned());
        s.argv = None;
        s.comm = Some("systemd-exec".to_owned());
        let view = EventSummaryView::from_summary(&s);
        assert_eq!(view.command_name, "systemd-exec");
        assert_eq!(view.command_dir, "/proc/self/fd/9");
    }

    #[test]
    fn normal_path_unaffected_by_fd_logic() {
        let view = EventSummaryView::from_summary(&make_summary());
        assert_eq!(view.command_name, "cargo");
        assert_eq!(view.command_dir, "/usr/bin/");
    }

    #[test]
    fn ansi_html_special_chars_escaped() {
        let html = ansi_to_html("<script>alert(1)</script>");
        assert!(
            !html.contains("<script>"),
            "should HTML-escape special chars: {html}"
        );
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
