//! Filter engine: composable event filters with OR semantics.
//!
//! When no filters are active, all events pass. When one or more filters are
//! active, an event passes if it matches **any** active filter.

/// Configuration for the filter engine, derived from CLI flags.
#[derive(Debug, Clone, Default)]
pub struct FilterConfig {
    /// Only pass events from processes attached to a PTY (tty_nr != 0).
    pub filter_pty: bool,
    /// Only pass events from descendants of these process names.
    pub filter_ancestors: Vec<String>,
}

impl FilterConfig {
    /// Returns true if no filters are active (pass-all mode).
    pub fn is_empty(&self) -> bool {
        !self.filter_pty && self.filter_ancestors.is_empty()
    }
}

/// Information about an event needed for filtering decisions.
#[derive(Debug, Clone)]
pub struct FilterInput {
    pub tty_nr: u32,
    pub comm: String,
    /// The comm values of all known ancestors, from parent to root.
    /// Populated by walking the session correlator's pid map.
    pub ancestor_comms: Vec<String>,
}

/// Evaluate whether an event should be emitted based on active filters.
///
/// Returns `true` if the event passes the filter (should be emitted).
pub fn passes_filter(config: &FilterConfig, input: &FilterInput) -> bool {
    // No filters = pass everything.
    if config.is_empty() {
        return true;
    }

    // OR composition: pass if any filter matches.
    if config.filter_pty && input.tty_nr != 0 {
        return true;
    }

    if !config.filter_ancestors.is_empty() {
        // Check if any ancestor's comm matches a configured name.
        for ancestor_comm in &input.ancestor_comms {
            if config
                .filter_ancestors
                .iter()
                .any(|name| name == ancestor_comm)
            {
                return true;
            }
        }
        // Also check the process's own comm.
        if config
            .filter_ancestors
            .iter()
            .any(|name| name == &input.comm)
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_filters_passes_everything() {
        let config = FilterConfig::default();
        let input = FilterInput {
            tty_nr: 0,
            comm: "cat".into(),
            ancestor_comms: vec![],
        };
        assert!(passes_filter(&config, &input));
    }

    #[test]
    fn pty_filter_passes_pty_process() {
        let config = FilterConfig {
            filter_pty: true,
            ..Default::default()
        };
        let input = FilterInput {
            tty_nr: 42,
            comm: "bash".into(),
            ancestor_comms: vec![],
        };
        assert!(passes_filter(&config, &input));
    }

    #[test]
    fn pty_filter_rejects_non_pty_process() {
        let config = FilterConfig {
            filter_pty: true,
            ..Default::default()
        };
        let input = FilterInput {
            tty_nr: 0,
            comm: "cron".into(),
            ancestor_comms: vec![],
        };
        assert!(!passes_filter(&config, &input));
    }

    #[test]
    fn ancestor_filter_passes_matching_ancestor() {
        let config = FilterConfig {
            filter_ancestors: vec!["sshd".into()],
            ..Default::default()
        };
        let input = FilterInput {
            tty_nr: 0,
            comm: "ls".into(),
            ancestor_comms: vec!["bash".into(), "sshd".into()],
        };
        assert!(passes_filter(&config, &input));
    }

    #[test]
    fn ancestor_filter_passes_matching_self_comm() {
        let config = FilterConfig {
            filter_ancestors: vec!["sshd".into()],
            ..Default::default()
        };
        let input = FilterInput {
            tty_nr: 0,
            comm: "sshd".into(),
            ancestor_comms: vec![],
        };
        assert!(passes_filter(&config, &input));
    }

    #[test]
    fn ancestor_filter_rejects_no_match() {
        let config = FilterConfig {
            filter_ancestors: vec!["sshd".into()],
            ..Default::default()
        };
        let input = FilterInput {
            tty_nr: 0,
            comm: "cron".into(),
            ancestor_comms: vec!["crond".into(), "systemd".into()],
        };
        assert!(!passes_filter(&config, &input));
    }

    #[test]
    fn or_composition_pty_matches() {
        let config = FilterConfig {
            filter_pty: true,
            filter_ancestors: vec!["sshd".into()],
        };
        // Has PTY but no matching ancestor — should still pass.
        let input = FilterInput {
            tty_nr: 42,
            comm: "vim".into(),
            ancestor_comms: vec!["bash".into()],
        };
        assert!(passes_filter(&config, &input));
    }

    #[test]
    fn or_composition_ancestor_matches() {
        let config = FilterConfig {
            filter_pty: true,
            filter_ancestors: vec!["sshd".into()],
        };
        // No PTY but has matching ancestor — should still pass.
        let input = FilterInput {
            tty_nr: 0,
            comm: "rsync".into(),
            ancestor_comms: vec!["sshd".into()],
        };
        assert!(passes_filter(&config, &input));
    }

    #[test]
    fn or_composition_neither_matches() {
        let config = FilterConfig {
            filter_pty: true,
            filter_ancestors: vec!["sshd".into()],
        };
        let input = FilterInput {
            tty_nr: 0,
            comm: "cron".into(),
            ancestor_comms: vec!["crond".into()],
        };
        assert!(!passes_filter(&config, &input));
    }

    #[test]
    fn multiple_ancestor_names() {
        let config = FilterConfig {
            filter_ancestors: vec!["sshd".into(), "my-agent".into()],
            ..Default::default()
        };
        let input = FilterInput {
            tty_nr: 0,
            comm: "python".into(),
            ancestor_comms: vec!["my-agent".into()],
        };
        assert!(passes_filter(&config, &input));
    }

    #[test]
    fn filter_config_is_empty() {
        assert!(FilterConfig::default().is_empty());
        assert!(
            !FilterConfig {
                filter_pty: true,
                ..Default::default()
            }
            .is_empty()
        );
        assert!(
            !FilterConfig {
                filter_ancestors: vec!["sshd".into()],
                ..Default::default()
            }
            .is_empty()
        );
    }
}
