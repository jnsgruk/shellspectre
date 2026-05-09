#![no_std]

/// Maximum number of arguments captured per execve call.
pub const MAX_ARGV_COUNT: usize = 20;

/// Maximum byte length of a single argument.
pub const MAX_ARG_LEN: usize = 256;

/// Maximum byte length of I/O data captured per event.
pub const MAX_DATA_LEN: usize = 4096;

/// Maximum byte length of an executable filename path.
pub const MAX_FILENAME_LEN: usize = 256;

/// Kernel task comm field length.
pub const COMM_LEN: usize = 16;

/// Discriminant for the type of event captured.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum EventType {
    Exec = 0,
    ExecResult = 1,
    Read = 2,
    Write = 3,
    Exit = 4,
}

/// Common header shared by all events sent through the ring buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct EventHeader {
    pub event_type: EventType,
    _pad0: u32,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub ppid: u32,
    pub tgid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub comm: [u8; COMM_LEN],
    pub tty_nr: u32,
    _pad1: u32,
    pub cgroup_id: u64,
}

impl EventHeader {
    /// Create a new event header. Padding fields are zeroed automatically.
    #[allow(clippy::too_many_arguments, clippy::similar_names)]
    pub const fn new(
        event_type: EventType,
        timestamp_ns: u64,
        pid: u32,
        ppid: u32,
        tgid: u32,
        tid: u32,
        uid: u32,
        gid: u32,
        euid: u32,
        comm: [u8; COMM_LEN],
        tty_nr: u32,
        cgroup_id: u64,
    ) -> Self {
        Self {
            event_type,
            _pad0: 0,
            timestamp_ns,
            pid,
            ppid,
            tgid,
            tid,
            uid,
            gid,
            euid,
            comm,
            tty_nr,
            _pad1: 0,
            cgroup_id,
        }
    }
}

/// Exec event payload — captures execve filename and arguments.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecEvent {
    pub header: EventHeader,
    pub filename: [u8; MAX_FILENAME_LEN],
    pub argv: [[u8; MAX_ARG_LEN]; MAX_ARGV_COUNT],
    pub argc: u32,
}

/// Exec result event payload — captures execve return value.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct ExecResultEvent {
    pub header: EventHeader,
    pub retval: i64,
}

/// I/O event payload — captures read/write data on stdin/stdout/stderr.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IoEvent {
    pub header: EventHeader,
    pub fd: u32,
    pub data_len: u32,
    pub count: u64,
    pub data: [u8; MAX_DATA_LEN],
}

/// Exit event payload — captures process exit code.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct ExitEvent {
    pub header: EventHeader,
    pub exit_code: i32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn event_header_offsets() {
        assert_eq!(mem::offset_of!(EventHeader, event_type), 0, "event_type");
        assert_eq!(
            mem::offset_of!(EventHeader, timestamp_ns),
            8,
            "timestamp_ns"
        );
        assert_eq!(mem::offset_of!(EventHeader, pid), 16, "pid");
        assert_eq!(mem::offset_of!(EventHeader, ppid), 20, "ppid");
        assert_eq!(mem::offset_of!(EventHeader, tgid), 24, "tgid");
        assert_eq!(mem::offset_of!(EventHeader, tid), 28, "tid");
        assert_eq!(mem::offset_of!(EventHeader, uid), 32, "uid");
        assert_eq!(mem::offset_of!(EventHeader, gid), 36, "gid");
        assert_eq!(mem::offset_of!(EventHeader, euid), 40, "euid");
        assert_eq!(mem::offset_of!(EventHeader, comm), 44, "comm");
        assert_eq!(mem::offset_of!(EventHeader, tty_nr), 60, "tty_nr");
        assert_eq!(mem::offset_of!(EventHeader, cgroup_id), 72, "cgroup_id");
    }

    #[test]
    fn event_header_size() {
        assert_eq!(mem::size_of::<EventHeader>(), 80, "EventHeader size");
    }

    #[test]
    fn exec_event_offsets() {
        assert_eq!(mem::offset_of!(ExecEvent, header), 0, "header");
        assert_eq!(mem::offset_of!(ExecEvent, filename), 80, "filename");
        assert_eq!(
            mem::offset_of!(ExecEvent, argv),
            80 + MAX_FILENAME_LEN,
            "argv"
        );
        assert_eq!(
            mem::offset_of!(ExecEvent, argc),
            80 + MAX_FILENAME_LEN + MAX_ARGV_COUNT * MAX_ARG_LEN,
            "argc"
        );
    }

    #[test]
    fn io_event_size() {
        assert_eq!(mem::size_of::<IoEvent>(), 96 + MAX_DATA_LEN, "IoEvent size");
    }

    #[test]
    fn small_events_fit_bpf_stack() {
        let bpf_stack: usize = 512;
        assert!(
            mem::size_of::<ExecResultEvent>() <= bpf_stack,
            "ExecResultEvent exceeds BPF stack"
        );
        assert!(
            mem::size_of::<ExitEvent>() <= bpf_stack,
            "ExitEvent exceeds BPF stack"
        );
        assert!(
            mem::size_of::<EventHeader>() <= bpf_stack,
            "EventHeader exceeds BPF stack"
        );
    }
}
