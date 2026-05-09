//! Event sink trait: abstracts where session events are sent.

use shspectr_common::{EventType, SessionId};

use crate::event::{ParsedExecEvent, ParsedExitEvent, ParsedIoEvent};

/// Info needed by sinks when handling a new session.
pub(crate) struct SessionInfo<'a> {
    pub session_id: &'a SessionId,
    pub pid: u32,
    pub comm: &'a str,
    pub uid: u32,
    pub euid: u32,
    pub tty_nr: u32,
    pub cgroup_id: u64,
}

/// Abstracts where captured session events are delivered.
pub(crate) trait Sink {
    /// Called on exec events. The sink should ensure the session exists.
    fn on_exec(&self, session: &SessionInfo<'_>, event: &ParsedExecEvent);
    /// Called on exit events.
    fn on_exit(&self, session: &SessionInfo<'_>, event: &ParsedExitEvent, session_complete: bool);
    /// Called on I/O events.
    fn on_io(&self, session: &SessionInfo<'_>, event: &ParsedIoEvent, event_type: EventType);
}
