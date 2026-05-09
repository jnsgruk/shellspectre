//! Stdout sink: emits events as structured JSON via the tracing subscriber.

use shspectr_common::EventType;
use tracing::info;

use crate::event::{ParsedExecEvent, ParsedExitEvent, ParsedIoEvent};
use crate::sink::{SessionInfo, Sink};

/// Emits events as structured JSON to stdout via tracing.
pub(crate) struct StdoutSink;

impl Sink for StdoutSink {
    fn on_exec(&self, session: &SessionInfo<'_>, event: &ParsedExecEvent) {
        info!(
            event = "exec",
            session_id = %session.session_id,
            pid = event.pid,
            ppid = event.ppid,
            uid = event.uid,
            gid = event.gid,
            euid = event.euid,
            comm = %event.comm,
            tty_nr = event.tty_nr,
            cgroup_id = event.cgroup_id,
            filename = %event.filename,
            argv = ?event.argv,
            retval = event.retval,
        );
    }

    fn on_exit(&self, session: &SessionInfo<'_>, event: &ParsedExitEvent, _session_complete: bool) {
        info!(
            event = "exit",
            session_id = %session.session_id,
            pid = event.pid,
            ppid = event.ppid,
            uid = event.uid,
            gid = event.gid,
            euid = event.euid,
            comm = %event.comm,
            tty_nr = event.tty_nr,
            cgroup_id = event.cgroup_id,
            exit_code = event.exit_code,
        );
    }

    fn on_io(&self, session: &SessionInfo<'_>, event: &ParsedIoEvent, event_type: EventType) {
        let data_str = String::from_utf8_lossy(&event.data);
        info!(
            event = event_type.as_str(),
            session_id = %session.session_id,
            pid = event.pid,
            ppid = event.ppid,
            uid = event.uid,
            gid = event.gid,
            euid = event.euid,
            comm = %event.comm,
            tty_nr = event.tty_nr,
            cgroup_id = event.cgroup_id,
            fd = event.fd,
            data_len = event.data.len(),
            count = event.count,
            data = %data_str,
        );
    }
}
