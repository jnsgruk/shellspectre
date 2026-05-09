use shspectr_common::{EventHeader, EventType};

use crate::event::{ParsedExecEvent, ParsedExitEvent, ParsedIoEvent};
use crate::filter;
use crate::session;
use crate::sink::{SessionInfo, Sink};

pub(crate) fn handle_event(
    data: &[u8],
    correlator: &mut session::SessionCorrelator,
    filter_config: &filter::FilterConfig,
    sink: &dyn Sink,
) {
    let header = match EventHeader::try_from(data) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(len = data.len(), %e, "invalid or truncated event, skipping");
            return;
        }
    };

    let Some(event_type) = header.decoded_event_type() else {
        tracing::warn!(
            raw_event_type = header.event_type,
            wire_version = header.wire_version,
            "invalid event header, skipping"
        );
        return;
    };

    match event_type {
        EventType::Exec => handle_exec_event(data, correlator, filter_config, sink),
        EventType::Exit => handle_exit_event(data, correlator, filter_config, sink),
        EventType::Read | EventType::Write => {
            handle_io_event(data, correlator, filter_config, sink, event_type);
        }
    }
}

fn handle_exec_event(
    data: &[u8],
    correlator: &mut session::SessionCorrelator,
    filter_config: &filter::FilterConfig,
    sink: &dyn Sink,
) {
    let Ok(exec) = ParsedExecEvent::try_from(data) else {
        tracing::warn!("exec event too short");
        return;
    };
    let event_info = session::EventInfo {
        pid: exec.pid,
        ppid: exec.ppid,
        tty_nr: exec.tty_nr,
        comm: exec.comm.clone(),
        execution_id: exec.execution_id,
    };
    let session_id = correlator.on_exec(&event_info).clone();

    if !filter_config.is_empty() {
        let ancestor_comms = correlator.ancestor_comms(exec.pid);
        let fi = filter::FilterInput {
            tty_nr: exec.tty_nr,
            comm: exec.comm.clone(),
            ancestor_comms,
        };
        if !filter::passes_filter(filter_config, &fi) {
            return;
        }
    }

    let si = SessionInfo {
        session_id: &session_id,
        pid: exec.pid,
        comm: &exec.comm,
        uid: exec.uid,
        euid: exec.euid,
        tty_nr: exec.tty_nr,
        cgroup_id: exec.cgroup_id,
    };
    sink.on_exec(&si, &exec);
}

fn handle_exit_event(
    data: &[u8],
    correlator: &mut session::SessionCorrelator,
    filter_config: &filter::FilterConfig,
    sink: &dyn Sink,
) {
    let Ok(exit) = ParsedExitEvent::try_from(data) else {
        tracing::warn!("exit event too short");
        return;
    };
    let event_info = session::EventInfo {
        pid: exit.pid,
        ppid: exit.ppid,
        tty_nr: exit.tty_nr,
        comm: exit.comm.clone(),
        execution_id: exit.execution_id,
    };
    let session_id = correlator.session_for(&event_info).clone();

    if !filter_config.is_empty() {
        let ancestor_comms = correlator.ancestor_comms(exit.pid);
        let fi = filter::FilterInput {
            tty_nr: exit.tty_nr,
            comm: exit.comm.clone(),
            ancestor_comms,
        };
        if !filter::passes_filter(filter_config, &fi) {
            correlator.on_exit(exit.pid);
            return;
        }
    }

    let session_complete = correlator
        .on_exit(exit.pid)
        .is_some_and(|info| info.session_complete);

    let si = SessionInfo {
        session_id: &session_id,
        pid: exit.pid,
        comm: &exit.comm,
        uid: exit.uid,
        euid: exit.euid,
        tty_nr: exit.tty_nr,
        cgroup_id: exit.cgroup_id,
    };
    sink.on_exit(&si, &exit, session_complete);
}

fn handle_io_event(
    data: &[u8],
    correlator: &mut session::SessionCorrelator,
    filter_config: &filter::FilterConfig,
    sink: &dyn Sink,
    event_type: EventType,
) {
    let Ok(io) = ParsedIoEvent::try_from(data) else {
        tracing::warn!("io event too short");
        return;
    };
    let event_info = session::EventInfo {
        pid: io.pid,
        ppid: io.ppid,
        tty_nr: io.tty_nr,
        comm: io.comm.clone(),
        execution_id: io.execution_id,
    };
    let session_id = correlator.session_for(&event_info).clone();

    if !filter_config.is_empty() {
        let ancestor_comms = correlator.ancestor_comms(io.pid);
        let fi = filter::FilterInput {
            tty_nr: io.tty_nr,
            comm: io.comm.clone(),
            ancestor_comms,
        };
        if !filter::passes_filter(filter_config, &fi) {
            return;
        }
    }

    let si = SessionInfo {
        session_id: &session_id,
        pid: io.pid,
        comm: &io.comm,
        uid: io.uid,
        euid: io.euid,
        tty_nr: io.tty_nr,
        cgroup_id: io.cgroup_id,
    };
    sink.on_io(&si, &io, event_type);
}
