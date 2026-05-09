//! Session correlation: groups events into logical sessions.
//!
//! The correlator maintains a `pid → session_id` mapping updated on every
//! execve and exit event. Session assignment follows this priority:
//!
//! 1. **PTY grouping** — processes sharing a `tty_nr` share a session.
//! 2. **Ancestor inheritance** — child processes inherit their parent's session.
//! 3. **Singleton fallback** — unknown processes get a new per-PID session.
//!
//! Session IDs have the form `ox_<8 alphanumeric chars>`, e.g. `ox_k7m3qx9p`.

use std::collections::HashMap;

/// Length of the random suffix in session IDs.
pub(crate) const SESSION_ID_SUFFIX_LEN: usize = 8;

/// Prefix for all session IDs.
pub(crate) const SESSION_ID_PREFIX: &str = "ox_";

/// Information about a tracked process.
#[derive(Debug, Clone)]
struct ProcessInfo {
    session_id: String,
    #[allow(dead_code)]
    ppid: u32,
    #[allow(dead_code)]
    tty_nr: u32,
}

/// Correlates events into logical sessions.
#[derive(Debug)]
pub struct SessionCorrelator {
    /// Maps pid → process info (including session_id).
    pid_map: HashMap<u32, ProcessInfo>,
    /// Maps tty_nr → session_id for PTY-based grouping.
    tty_sessions: HashMap<u32, String>,
}

/// Minimal event info needed for session correlation.
#[derive(Debug, Clone)]
pub struct EventInfo {
    pub pid: u32,
    pub ppid: u32,
    pub tty_nr: u32,
}

impl SessionCorrelator {
    /// Create a new empty correlator.
    pub fn new() -> Self {
        Self {
            pid_map: HashMap::new(),
            tty_sessions: HashMap::new(),
        }
    }

    /// Record an execve event and return the assigned session ID.
    ///
    /// Session assignment priority:
    /// 1. If the process has a non-zero `tty_nr`, group by PTY.
    /// 2. If the parent PID is tracked, inherit the parent's session.
    /// 3. Otherwise, create a new singleton session.
    pub fn on_exec(&mut self, info: &EventInfo) -> &str {
        // If already tracked (re-exec), return existing session.
        if self.pid_map.contains_key(&info.pid) {
            return &self.pid_map[&info.pid].session_id;
        }

        let session_id = self.resolve_session(info);

        self.pid_map.insert(
            info.pid,
            ProcessInfo {
                session_id,
                ppid: info.ppid,
                tty_nr: info.tty_nr,
            },
        );

        &self.pid_map[&info.pid].session_id
    }

    /// Look up the session ID for a process without creating a new entry.
    /// Used for I/O and exit events that should be correlated to an existing
    /// session if possible.
    pub fn session_for(&mut self, info: &EventInfo) -> &str {
        if !self.pid_map.contains_key(&info.pid) {
            // Process wasn't seen via execve — try to correlate anyway.
            let session_id = self.resolve_session(info);
            self.pid_map.insert(
                info.pid,
                ProcessInfo {
                    session_id,
                    ppid: info.ppid,
                    tty_nr: info.tty_nr,
                },
            );
        }
        &self.pid_map[&info.pid].session_id
    }

    /// Record a process exit. Returns the session ID if the process was tracked.
    pub fn on_exit(&mut self, pid: u32) -> Option<String> {
        self.pid_map.remove(&pid).map(|info| info.session_id)
    }

    /// Resolve which session a process belongs to.
    fn resolve_session(&mut self, info: &EventInfo) -> String {
        // 1. PTY grouping: non-zero tty_nr → share session with same TTY.
        if info.tty_nr != 0 {
            if let Some(sid) = self.tty_sessions.get(&info.tty_nr) {
                return sid.clone();
            }
            // First process on this TTY — create a new session.
            let sid = generate_session_id();
            self.tty_sessions.insert(info.tty_nr, sid.clone());
            return sid;
        }

        // 2. Ancestor inheritance: inherit parent's session if tracked.
        if let Some(parent) = self.pid_map.get(&info.ppid) {
            return parent.session_id.clone();
        }

        // 3. Singleton fallback.
        generate_session_id()
    }

    /// Number of tracked processes (for testing/diagnostics).
    #[cfg(test)]
    fn tracked_count(&self) -> usize {
        self.pid_map.len()
    }
}

/// Generate a session ID like `ox_k7m3qx9p`.
fn generate_session_id() -> String {
    use std::io::Read;

    let mut buf = [0u8; SESSION_ID_SUFFIX_LEN];
    // getrandom via /dev/urandom — infallible on Linux in practice.
    #[allow(clippy::expect_used)]
    let mut f = std::fs::File::open("/dev/urandom").expect("failed to open /dev/urandom");
    #[allow(clippy::expect_used)]
    f.read_exact(&mut buf).expect("failed to read random bytes");

    let charset = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let suffix: String = buf
        .iter()
        .map(|b| charset[(*b as usize) % charset.len()] as char)
        .collect();

    format!("{SESSION_ID_PREFIX}{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_format() {
        let id = generate_session_id();
        assert!(id.starts_with("ox_"), "should start with ox_: {id}");
        assert_eq!(id.len(), 3 + SESSION_ID_SUFFIX_LEN);
        assert!(id[3..].chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn session_ids_are_unique() {
        let ids: Vec<_> = (0..100).map(|_| generate_session_id()).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len(), "session IDs should be unique");
    }

    #[test]
    fn pty_processes_share_session() {
        let mut c = SessionCorrelator::new();
        let s1 = c
            .on_exec(&EventInfo {
                pid: 100,
                ppid: 1,
                tty_nr: 42,
            })
            .to_string();
        let s2 = c
            .on_exec(&EventInfo {
                pid: 200,
                ppid: 1,
                tty_nr: 42,
            })
            .to_string();
        assert_eq!(s1, s2, "same tty_nr should yield same session");
    }

    #[test]
    fn different_ptys_get_different_sessions() {
        let mut c = SessionCorrelator::new();
        let s1 = c
            .on_exec(&EventInfo {
                pid: 100,
                ppid: 1,
                tty_nr: 42,
            })
            .to_string();
        let s2 = c
            .on_exec(&EventInfo {
                pid: 200,
                ppid: 1,
                tty_nr: 43,
            })
            .to_string();
        assert_ne!(s1, s2, "different tty_nr should yield different sessions");
    }

    #[test]
    fn child_inherits_parent_session() {
        let mut c = SessionCorrelator::new();
        // Parent has no PTY, gets a singleton session.
        let parent_sid = c
            .on_exec(&EventInfo {
                pid: 100,
                ppid: 1,
                tty_nr: 0,
            })
            .to_string();
        // Child references parent.
        let child_sid = c
            .on_exec(&EventInfo {
                pid: 200,
                ppid: 100,
                tty_nr: 0,
            })
            .to_string();
        assert_eq!(parent_sid, child_sid, "child should inherit parent session");
    }

    #[test]
    fn grandchild_inherits_session() {
        let mut c = SessionCorrelator::new();
        let s1 = c
            .on_exec(&EventInfo {
                pid: 100,
                ppid: 1,
                tty_nr: 0,
            })
            .to_string();
        let s2 = c
            .on_exec(&EventInfo {
                pid: 200,
                ppid: 100,
                tty_nr: 0,
            })
            .to_string();
        let s3 = c
            .on_exec(&EventInfo {
                pid: 300,
                ppid: 200,
                tty_nr: 0,
            })
            .to_string();
        assert_eq!(s1, s2);
        assert_eq!(s2, s3, "grandchild should inherit through chain");
    }

    #[test]
    fn unknown_parent_gets_singleton() {
        let mut c = SessionCorrelator::new();
        let s1 = c
            .on_exec(&EventInfo {
                pid: 100,
                ppid: 999,
                tty_nr: 0,
            })
            .to_string();
        let s2 = c
            .on_exec(&EventInfo {
                pid: 200,
                ppid: 998,
                tty_nr: 0,
            })
            .to_string();
        assert_ne!(s1, s2, "unrelated processes should get different sessions");
    }

    #[test]
    fn reexec_keeps_session() {
        let mut c = SessionCorrelator::new();
        let s1 = c
            .on_exec(&EventInfo {
                pid: 100,
                ppid: 1,
                tty_nr: 42,
            })
            .to_string();
        // Same PID re-execs (e.g. shell exec's into another program).
        let s2 = c
            .on_exec(&EventInfo {
                pid: 100,
                ppid: 1,
                tty_nr: 42,
            })
            .to_string();
        assert_eq!(s1, s2, "re-exec should keep existing session");
    }

    #[test]
    fn on_exit_removes_process() {
        let mut c = SessionCorrelator::new();
        let sid = c
            .on_exec(&EventInfo {
                pid: 100,
                ppid: 1,
                tty_nr: 0,
            })
            .to_string();
        let removed = c.on_exit(100);
        assert_eq!(removed, Some(sid));
        assert_eq!(c.tracked_count(), 0);
    }

    #[test]
    fn on_exit_unknown_pid_returns_none() {
        let mut c = SessionCorrelator::new();
        assert_eq!(c.on_exit(999), None);
    }

    #[test]
    fn session_for_untracked_process_creates_entry() {
        let mut c = SessionCorrelator::new();
        let sid = c
            .session_for(&EventInfo {
                pid: 100,
                ppid: 1,
                tty_nr: 0,
            })
            .to_string();
        assert!(sid.starts_with("ox_"));
        assert_eq!(c.tracked_count(), 1);
    }

    #[test]
    fn session_for_tracked_process_returns_existing() {
        let mut c = SessionCorrelator::new();
        let s1 = c
            .on_exec(&EventInfo {
                pid: 100,
                ppid: 1,
                tty_nr: 42,
            })
            .to_string();
        let s2 = c
            .session_for(&EventInfo {
                pid: 100,
                ppid: 1,
                tty_nr: 42,
            })
            .to_string();
        assert_eq!(s1, s2);
    }

    #[test]
    fn io_event_on_pty_process_inherits_session() {
        let mut c = SessionCorrelator::new();
        // Shell starts on a PTY.
        let shell_sid = c
            .on_exec(&EventInfo {
                pid: 100,
                ppid: 1,
                tty_nr: 42,
            })
            .to_string();
        // A child writes to stdout — might not have been seen via execve yet,
        // but shares the same TTY.
        let io_sid = c
            .session_for(&EventInfo {
                pid: 200,
                ppid: 100,
                tty_nr: 42,
            })
            .to_string();
        assert_eq!(shell_sid, io_sid);
    }
}
