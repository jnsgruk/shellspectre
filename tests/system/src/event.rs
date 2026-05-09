use serde::Deserialize;

/// A single event from shspectr JSONL output.
///
/// This is a test-only type. No equivalent exists in the main crates because
/// the JSONL output is produced by `tracing::info!()` with ad-hoc fields, not
/// by serialising a struct. The `Parsed*Event` types in `shspectr` are
/// per-variant and lack `Deserialize`; `EventSummary` in `shspectr-web`
/// derives only `Serialize` and has different fields.
///
/// Fields are optional because different event types carry different data.
#[derive(Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct Event {
    pub event: String,
    pub session_id: Option<String>,
    pub pid: Option<u64>,
    pub ppid: Option<u64>,
    pub uid: Option<u64>,
    pub gid: Option<u64>,
    pub euid: Option<u64>,
    pub comm: Option<String>,
    pub tty_nr: Option<u64>,
    pub cgroup_id: Option<u64>,
    pub execution_id: Option<u64>,
    // Exec-specific
    pub filename: Option<String>,
    pub argv: Option<String>,
    pub retval: Option<i64>,
    // Exit-specific
    pub exit_code: Option<i64>,
    // IO-specific
    pub fd: Option<u64>,
    pub data_len: Option<u64>,
    pub count: Option<u64>,
    pub data: Option<String>,
}

impl Event {
    pub fn is_exec(&self) -> bool {
        self.event == "exec"
    }

    pub fn is_exit(&self) -> bool {
        self.event == "exit"
    }

    pub fn is_read(&self) -> bool {
        self.event == "read"
    }

    pub fn is_write(&self) -> bool {
        self.event == "write"
    }
}

/// Parse JSONL lines into typed events.
///
/// Skips non-event lines (startup logs, tracing metadata) silently.
/// The tracing JSON formatter produces:
///
/// ```json
/// {"timestamp":"...","level":"INFO","fields":{"event":"exec",...},...}
/// ```
pub fn parse_events(lines: &[String]) -> Vec<Event> {
    lines
        .iter()
        .filter_map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            let fields = v.get("fields")?;
            serde_json::from_value::<Event>(fields.clone()).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXEC_LINE: &str = r#"{"timestamp":"2026-05-11T12:00:00Z","level":"INFO","fields":{"event":"exec","session_id":"ox_abc","pid":1234,"ppid":1,"uid":0,"gid":0,"euid":0,"comm":"ls","tty_nr":34816,"cgroup_id":1,"execution_id":42,"filename":"/usr/bin/ls","argv":"ls /tmp","retval":0},"target":"shspectr"}"#;
    const EXIT_LINE: &str = r#"{"timestamp":"2026-05-11T12:00:01Z","level":"INFO","fields":{"event":"exit","session_id":"ox_abc","pid":1234,"ppid":1,"uid":0,"gid":0,"euid":0,"comm":"ls","tty_nr":34816,"cgroup_id":1,"execution_id":42,"exit_code":0},"target":"shspectr"}"#;

    #[test]
    fn parses_exec_event_from_tracing_json() {
        let lines = vec![EXEC_LINE.to_string()];
        let events = parse_events(&lines);

        assert_eq!(events.len(), 1, "should parse exactly one event");
        let e = &events[0];
        assert!(e.is_exec(), "should be an exec event");
        assert_eq!(e.filename.as_deref(), Some("/usr/bin/ls"));
        assert_eq!(e.comm.as_deref(), Some("ls"));
        assert_eq!(e.pid, Some(1234));
        assert_eq!(e.tty_nr, Some(34816));
        assert_eq!(e.session_id.as_deref(), Some("ox_abc"));
        assert_eq!(e.execution_id, Some(42));
    }

    #[test]
    fn parses_exit_event_from_tracing_json() {
        let lines = vec![EXIT_LINE.to_string()];
        let events = parse_events(&lines);

        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert!(e.is_exit());
        assert_eq!(e.exit_code, Some(0));
        assert_eq!(e.comm.as_deref(), Some("ls"));
    }

    #[test]
    fn skips_non_json_and_non_event_lines() {
        let lines = vec![
            "INFO some startup log line".to_string(),
            r#"{"timestamp":"...","level":"INFO","target":"shspectr"}"#.to_string(),
            String::new(),
            EXEC_LINE.to_string(),
        ];
        let events = parse_events(&lines);

        assert_eq!(events.len(), 1, "only the valid event line should parse");
        assert!(events[0].is_exec());
    }

    #[test]
    fn event_type_predicates() {
        let lines = vec![EXEC_LINE.to_string(), EXIT_LINE.to_string()];
        let events = parse_events(&lines);

        assert!(events[0].is_exec());
        assert!(!events[0].is_exit());
        assert!(events[1].is_exit());
        assert!(!events[1].is_exec());
    }
}
