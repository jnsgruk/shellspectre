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

use shspectr_common::SessionId;

/// Length of the random suffix in session IDs.
pub(crate) const SESSION_ID_SUFFIX_LEN: usize = SessionId::SUFFIX_LEN;

/// Prefix for all session IDs.
pub(crate) const SESSION_ID_PREFIX: &str = SessionId::PREFIX;

/// Information about a tracked process.
#[derive(Debug, Clone)]
struct ProcessInfo {
    session_id: SessionId,
    ppid: u32,
    tty_nr: u32,
    comm: String,
    execution_id: u64,
}

/// Per-TTY session entry used to keep session identity stable across
/// short gaps between observed child processes on the same terminal.
#[derive(Debug)]
struct TtySession {
    session_id: SessionId,
}

/// Result of removing a tracked process on exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitInfo {
    pub session_id: SessionId,
    pub session_complete: bool,
}

/// Correlates events into logical sessions.
#[derive(Debug, Default)]
pub struct SessionCorrelator {
    /// Maps pid → process info (including session_id).
    pid_map: HashMap<u32, ProcessInfo>,
    /// Maps tty_nr → session entry for PTY-based grouping.
    tty_sessions: HashMap<u32, TtySession>,
}

/// Minimal event info needed for session correlation.
#[derive(Debug, Clone)]
pub struct EventInfo {
    pub pid: u32,
    pub ppid: u32,
    pub tty_nr: u32,
    pub comm: String,
    pub execution_id: u64,
}

impl SessionCorrelator {
    /// Record an execve event and return the assigned session ID.
    ///
    /// Session assignment priority:
    /// 1. If the process has a non-zero `tty_nr`, group by PTY.
    /// 2. If the parent PID is tracked, inherit the parent's session.
    /// 3. Otherwise, create a new singleton session.
    pub fn on_exec(&mut self, info: &EventInfo) -> &SessionId {
        // Re-exec stays in the same session but must refresh process metadata.
        if let Some(existing) = self.pid_map.get_mut(&info.pid) {
            existing.ppid = info.ppid;
            existing.tty_nr = info.tty_nr;
            existing.comm.clone_from(&info.comm);
            existing.execution_id = info.execution_id;
            return &self.pid_map[&info.pid].session_id;
        }

        let session_id = self.resolve_session(info);

        self.pid_map.insert(
            info.pid,
            ProcessInfo {
                session_id,
                ppid: info.ppid,
                tty_nr: info.tty_nr,
                comm: info.comm.clone(),
                execution_id: info.execution_id,
            },
        );

        &self.pid_map[&info.pid].session_id
    }

    /// Look up the session ID for a process without creating a new entry.
    /// Used for I/O and exit events that should be correlated to an existing
    /// session if possible.
    pub fn session_for(&mut self, info: &EventInfo) -> &SessionId {
        if !self.pid_map.contains_key(&info.pid) {
            // Process wasn't seen via execve — try to correlate anyway.
            let session_id = self.resolve_session(info);
            self.pid_map.insert(
                info.pid,
                ProcessInfo {
                    session_id,
                    ppid: info.ppid,
                    tty_nr: info.tty_nr,
                    comm: info.comm.clone(),
                    execution_id: info.execution_id,
                },
            );
        }
        &self.pid_map[&info.pid].session_id
    }

    /// Record a process exit. Returns session details if the process was tracked.
    pub fn on_exit(&mut self, pid: u32) -> Option<ExitInfo> {
        let info = self.pid_map.remove(&pid)?;

        let session_complete = info.tty_nr == 0
            && !self
                .pid_map
                .values()
                .any(|tracked| tracked.session_id == info.session_id);

        Some(ExitInfo {
            session_id: info.session_id,
            session_complete,
        })
    }

    /// Walk the ppid chain and return the comm of each known ancestor.
    pub fn ancestor_comms(&self, pid: u32) -> Vec<String> {
        let mut comms = Vec::new();
        let mut current = pid;
        // Walk up to 32 levels to avoid infinite loops from stale data.
        for _ in 0..32 {
            let Some(info) = self.pid_map.get(&current) else {
                break;
            };
            if info.ppid == current {
                break; // pid 1 is its own parent
            }
            current = info.ppid;
            if let Some(parent) = self.pid_map.get(&current) {
                comms.push(parent.comm.clone());
            } else {
                break;
            }
        }
        comms
    }

    /// Resolve which session a process belongs to.
    fn resolve_session(&mut self, info: &EventInfo) -> SessionId {
        // 1. PTY grouping: non-zero tty_nr → share session with same TTY.
        if info.tty_nr != 0 {
            if let Some(tty) = self.tty_sessions.get_mut(&info.tty_nr) {
                return tty.session_id.clone();
            }
            // First process on this TTY — create a new session.
            let sid = generate_session_id();
            self.tty_sessions.insert(
                info.tty_nr,
                TtySession {
                    session_id: sid.clone(),
                },
            );
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

    /// Number of active TTY session entries (for testing/diagnostics).
    #[cfg(test)]
    fn tty_session_count(&self) -> usize {
        self.tty_sessions.len()
    }
}

/// Generate a session ID like `ox_k7m3qx9p`.
fn generate_session_id() -> SessionId {
    let mut buf = [0u8; SESSION_ID_SUFFIX_LEN];
    // Panicking is appropriate: failure indicates a catastrophic environment (e.g. seccomp blocking getrandom(2)).
    #[allow(clippy::expect_used)]
    getrandom::fill(&mut buf)
        .expect("getrandom failed — is this process in a seccomp sandbox blocking getrandom(2)?");

    let charset = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let suffix: String = buf
        .iter()
        .map(|b| charset[(*b as usize) % charset.len()] as char)
        .collect();

    SessionId::from(format!("{SESSION_ID_PREFIX}{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create EventInfo with a default comm.
    fn ei(pid: u32, ppid: u32, tty_nr: u32) -> EventInfo {
        ei_comm(pid, ppid, tty_nr, "test")
    }

    fn ei_comm(pid: u32, ppid: u32, tty_nr: u32, comm: &str) -> EventInfo {
        EventInfo {
            pid,
            ppid,
            tty_nr,
            comm: comm.into(),
            execution_id: u64::from(pid),
        }
    }

    #[test]
    fn session_id_format() {
        let id = generate_session_id();
        let s = id.as_ref();
        assert!(s.starts_with("ox_"), "should start with ox_: {id}");
        assert_eq!(s.len(), 3 + SESSION_ID_SUFFIX_LEN);
        assert!(s[3..].chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn session_ids_are_unique() {
        let ids: Vec<_> = (0..100).map(|_| generate_session_id()).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len(), "session IDs should be unique");
    }

    #[test]
    fn pty_processes_share_session() {
        let mut c = SessionCorrelator::default();
        let s1 = c.on_exec(&ei(100, 1, 42)).clone();
        let s2 = c.on_exec(&ei(200, 1, 42)).clone();
        assert_eq!(s1, s2, "same tty_nr should yield same session");
    }

    #[test]
    fn different_ptys_get_different_sessions() {
        let mut c = SessionCorrelator::default();
        let s1 = c.on_exec(&ei(100, 1, 42)).clone();
        let s2 = c.on_exec(&ei(200, 1, 43)).clone();
        assert_ne!(s1, s2, "different tty_nr should yield different sessions");
    }

    #[test]
    fn child_inherits_parent_session() {
        let mut c = SessionCorrelator::default();
        let parent_sid = c.on_exec(&ei(100, 1, 0)).clone();
        let child_sid = c.on_exec(&ei(200, 100, 0)).clone();
        assert_eq!(parent_sid, child_sid, "child should inherit parent session");
    }

    #[test]
    fn grandchild_inherits_session() {
        let mut c = SessionCorrelator::default();
        let s1 = c.on_exec(&ei(100, 1, 0)).clone();
        let s2 = c.on_exec(&ei(200, 100, 0)).clone();
        let s3 = c.on_exec(&ei(300, 200, 0)).clone();
        assert_eq!(s1, s2);
        assert_eq!(s2, s3, "grandchild should inherit through chain");
    }

    #[test]
    fn unknown_parent_gets_singleton() {
        let mut c = SessionCorrelator::default();
        let s1 = c.on_exec(&ei(100, 999, 0)).clone();
        let s2 = c.on_exec(&ei(200, 998, 0)).clone();
        assert_ne!(s1, s2, "unrelated processes should get different sessions");
    }

    #[test]
    fn reexec_keeps_session() {
        let mut c = SessionCorrelator::default();
        let s1 = c.on_exec(&ei(100, 1, 42)).clone();
        let s2 = c.on_exec(&ei(100, 1, 42)).clone();
        assert_eq!(s1, s2, "re-exec should keep existing session");
    }

    #[test]
    fn reexec_refreshes_process_metadata_and_execution_id() {
        let mut c = SessionCorrelator::default();
        c.on_exec(&ei_comm(100, 1, 42, "bash"));
        c.on_exec(&EventInfo {
            pid: 100,
            ppid: 55,
            tty_nr: 99,
            comm: "python".into(),
            execution_id: 1234,
        });

        assert_eq!(
            c.pid_map.get(&100).map(|info| info.execution_id),
            Some(1234)
        );
        assert_eq!(c.pid_map[&100].ppid, 55);
        assert_eq!(c.pid_map[&100].tty_nr, 99);
        assert_eq!(c.pid_map[&100].comm, "python");
    }

    #[test]
    fn on_exit_removes_process() {
        let mut c = SessionCorrelator::default();
        let sid = c.on_exec(&ei(100, 1, 0)).clone();
        let removed = c.on_exit(100);
        assert_eq!(
            removed,
            Some(ExitInfo {
                session_id: sid,
                session_complete: true,
            })
        );
        assert_eq!(c.tracked_count(), 0);
    }

    #[test]
    fn on_exit_unknown_pid_returns_none() {
        let mut c = SessionCorrelator::default();
        assert_eq!(c.on_exit(999), None);
    }

    #[test]
    fn session_for_untracked_process_creates_entry() {
        let mut c = SessionCorrelator::default();
        let sid = c.session_for(&ei(100, 1, 0)).clone();
        assert!(sid.as_ref().starts_with("ox_"));
        assert_eq!(c.tracked_count(), 1);
    }

    #[test]
    fn session_for_tracked_process_returns_existing() {
        let mut c = SessionCorrelator::default();
        let s1 = c.on_exec(&ei(100, 1, 42)).clone();
        let s2 = c.session_for(&ei(100, 1, 42)).clone();
        assert_eq!(s1, s2);
    }

    #[test]
    fn io_event_on_pty_process_inherits_session() {
        let mut c = SessionCorrelator::default();
        let shell_sid = c.on_exec(&ei(100, 1, 42)).clone();
        let io_sid = c.session_for(&ei(200, 100, 42)).clone();
        assert_eq!(shell_sid, io_sid);
    }

    #[test]
    fn ancestor_comms_walks_chain() {
        let mut c = SessionCorrelator::default();
        c.on_exec(&ei_comm(1, 0, 0, "systemd"));
        c.on_exec(&ei_comm(100, 1, 0, "sshd"));
        c.on_exec(&ei_comm(200, 100, 0, "bash"));
        c.on_exec(&ei_comm(300, 200, 0, "ls"));

        let comms = c.ancestor_comms(300);
        assert_eq!(comms, vec!["bash", "sshd", "systemd"]);
    }

    #[test]
    fn ancestor_comms_empty_for_unknown() {
        let c = SessionCorrelator::default();
        assert!(c.ancestor_comms(999).is_empty());
    }

    #[test]
    fn tty_session_entry_persists_after_last_process_exits() {
        let mut c = SessionCorrelator::default();
        c.on_exec(&ei(100, 1, 5));
        assert_eq!(c.tty_session_count(), 1);
        let exit = c.on_exit(100).expect("tracked process should exit");
        assert!(
            !exit.session_complete,
            "PTY sessions should stay open across command gaps"
        );
        assert_eq!(
            c.tty_session_count(),
            1,
            "TTY session should remain so later commands on the same terminal reuse it"
        );
    }

    #[test]
    fn tty_session_entry_retained_while_processes_remain() {
        let mut c = SessionCorrelator::default();
        c.on_exec(&ei(100, 1, 5));
        c.on_exec(&ei(101, 1, 5));
        assert_eq!(c.tty_session_count(), 1);
        c.on_exit(100);
        assert_eq!(
            c.tty_session_count(),
            1,
            "entry must remain while a process is still on the TTY"
        );
        let exit = c.on_exit(101).expect("tracked process should exit");
        assert!(!exit.session_complete);
        assert_eq!(c.tty_session_count(), 1);
    }

    #[test]
    fn tty_session_count_zero_for_tty_nr_zero() {
        let mut c = SessionCorrelator::default();
        c.on_exec(&ei(100, 1, 0));
        assert_eq!(
            c.tty_session_count(),
            0,
            "tty_nr=0 must not create a tty_sessions entry"
        );
        c.on_exit(100);
        assert_eq!(c.tty_session_count(), 0);
    }

    #[test]
    fn pty_session_survives_gap_between_commands() {
        let mut c = SessionCorrelator::default();
        let first = c.on_exec(&ei_comm(100, 1, 9, "ls")).clone();
        let exit = c.on_exit(100).expect("tracked process should exit");
        assert_eq!(exit.session_id, first);
        assert!(!exit.session_complete);

        let second = c.on_exec(&ei_comm(200, 1, 9, "whoami")).clone();
        assert_eq!(
            second, first,
            "same tty_nr should keep one session across command gaps"
        );
    }

    #[test]
    fn non_pty_session_only_completes_when_last_process_exits() {
        let mut c = SessionCorrelator::default();
        let session_id = c.on_exec(&ei(100, 1, 0)).clone();
        let child_session = c.on_exec(&ei(200, 100, 0)).clone();
        assert_eq!(child_session, session_id);

        let parent_exit = c.on_exit(100).expect("parent should be tracked");
        assert_eq!(parent_exit.session_id, session_id);
        assert!(
            !parent_exit.session_complete,
            "session must remain open while child is tracked"
        );

        let child_exit = c.on_exit(200).expect("child should be tracked");
        assert_eq!(child_exit.session_id, session_id);
        assert!(
            child_exit.session_complete,
            "last non-PTY process should complete the session"
        );
    }
}
