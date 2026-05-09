use core::fmt;

use crate::EventType;

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

/// Current version of the ring-buffer wire contract.
pub const WIRE_VERSION: u32 = 1;

/// Error returned when parsing a raw event from a byte buffer fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The byte buffer is shorter than the required size.
    BufferTooShort {
        /// Minimum number of bytes needed.
        need: usize,
        /// Actual number of bytes provided.
        got: usize,
    },
    /// The wire version in the header does not match [`WIRE_VERSION`].
    InvalidWireVersion(u32),
    /// The event type discriminant is not a known [`EventType`] variant.
    InvalidEventType(u32),
    /// The event type in the header does not match the expected type for
    /// the target struct (e.g. an `Exit` header in an `ExecEvent` buffer).
    UnexpectedEventType {
        /// The event type that was expected.
        expected: &'static str,
        /// The event type discriminant found in the header.
        got: u32,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort { need, got } => {
                write!(f, "buffer too short: need {need} bytes, got {got}")
            }
            Self::InvalidWireVersion(v) => {
                write!(f, "unsupported wire version {v} (expected {WIRE_VERSION})")
            }
            Self::InvalidEventType(t) => write!(f, "invalid event type discriminant {t}"),
            Self::UnexpectedEventType { expected, got } => {
                write!(f, "expected {expected} event type, got discriminant {got}")
            }
        }
    }
}

/// Common header shared by all events sent through the ring buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct EventHeader {
    pub event_type: u32,
    pub wire_version: u32,
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
    pub execution_id: u64,
    pub cgroup_id: u64,
}

impl EventHeader {
    /// Decode and validate the event type stored in the header.
    pub const fn decoded_event_type(&self) -> Option<EventType> {
        if self.wire_version != WIRE_VERSION {
            return None;
        }
        EventType::from_wire(self.event_type)
    }

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
        execution_id: u64,
        cgroup_id: u64,
    ) -> Self {
        Self {
            event_type: event_type.as_wire(),
            wire_version: WIRE_VERSION,
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
            execution_id,
            cgroup_id,
        }
    }
}

impl TryFrom<&[u8]> for EventHeader {
    type Error = ParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let need = core::mem::size_of::<Self>();
        if data.len() < need {
            return Err(ParseError::BufferTooShort {
                need,
                got: data.len(),
            });
        }

        // SAFETY: EventHeader is repr(C), we verified the length, and use
        // read_unaligned because ring buffer data may not be aligned.
        let header = unsafe { core::ptr::read_unaligned(data.as_ptr().cast::<Self>()) };

        if header.wire_version != WIRE_VERSION {
            return Err(ParseError::InvalidWireVersion(header.wire_version));
        }
        if EventType::from_wire(header.event_type).is_none() {
            return Err(ParseError::InvalidEventType(header.event_type));
        }

        Ok(header)
    }
}

/// Exec event payload — captures execve filename, arguments, and result.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecEvent {
    pub header: EventHeader,
    pub filename: [u8; MAX_FILENAME_LEN],
    pub argv: [[u8; MAX_ARG_LEN]; MAX_ARGV_COUNT],
    pub argc: u32,
    _pad: u32,
    pub retval: i64,
}

impl ExecEvent {
    /// Create a zeroed exec event. Useful for test construction and
    /// scratch buffer initialization.
    pub const fn zeroed(header: EventHeader) -> Self {
        Self {
            header,
            filename: [0u8; MAX_FILENAME_LEN],
            argv: [[0u8; MAX_ARG_LEN]; MAX_ARGV_COUNT],
            argc: 0,
            _pad: 0,
            retval: 0,
        }
    }
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

impl IoEvent {
    /// Create a zeroed I/O event. Useful for test construction and
    /// scratch buffer initialization.
    pub const fn zeroed(header: EventHeader) -> Self {
        Self {
            header,
            fd: 0,
            data_len: 0,
            count: 0,
            data: [0u8; MAX_DATA_LEN],
        }
    }
}

/// Exit event payload — captures process exit code.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub struct ExitEvent {
    pub header: EventHeader,
    pub exit_code: i32,
    _pad: u32,
}

impl ExitEvent {
    /// Create an exit event with padding zeroed.
    pub const fn new(header: EventHeader, exit_code: i32) -> Self {
        Self {
            header,
            exit_code,
            _pad: 0,
        }
    }
}

// Compile-time size assertions for critical structs.
const _: () = assert!(
    core::mem::size_of::<EventHeader>() == 80,
    "EventHeader size changed — update eBPF offsets"
);
const _: () = assert!(
    core::mem::size_of::<ExecEvent>() == 80 + MAX_FILENAME_LEN + MAX_ARGV_COUNT * MAX_ARG_LEN + 16,
    "ExecEvent size changed — update eBPF offsets"
);
const _: () = assert!(
    core::mem::size_of::<IoEvent>() == 80 + 16 + MAX_DATA_LEN,
    "IoEvent size changed — update eBPF offsets"
);
const _: () = assert!(
    core::mem::size_of::<ExitEvent>() == 88,
    "ExitEvent size changed — update eBPF offsets"
);

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
        assert_eq!(
            mem::offset_of!(EventHeader, execution_id),
            64,
            "execution_id"
        );
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
        assert_eq!(
            mem::offset_of!(ExecEvent, retval),
            80 + MAX_FILENAME_LEN + MAX_ARGV_COUNT * MAX_ARG_LEN + 8,
            "retval"
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
            mem::size_of::<ExitEvent>() <= bpf_stack,
            "ExitEvent exceeds BPF stack"
        );
        assert!(
            mem::size_of::<EventHeader>() <= bpf_stack,
            "EventHeader exceeds BPF stack"
        );
    }

    #[test]
    fn event_header_validates_wire_version_and_type() {
        let mut header = EventHeader::new(
            EventType::Exec,
            0,
            1,
            0,
            1,
            1,
            1000,
            1000,
            1000,
            [0u8; COMM_LEN],
            0,
            7,
            9,
        );

        assert_eq!(header.decoded_event_type(), Some(EventType::Exec));

        header.wire_version = WIRE_VERSION + 1;
        assert_eq!(header.decoded_event_type(), None);

        header.wire_version = WIRE_VERSION;
        header.event_type = 99;
        assert_eq!(header.decoded_event_type(), None);
    }

    #[test]
    fn exec_event_size() {
        assert_eq!(
            mem::size_of::<ExecEvent>(),
            80 + MAX_FILENAME_LEN + MAX_ARGV_COUNT * MAX_ARG_LEN + 16,
        );
    }

    #[test]
    fn exit_event_offsets() {
        assert_eq!(mem::offset_of!(ExitEvent, exit_code), 80, "exit_code");
        assert_eq!(mem::size_of::<ExitEvent>(), 88, "ExitEvent size");
    }

    #[test]
    fn io_event_offsets() {
        assert_eq!(mem::offset_of!(IoEvent, fd), 80, "fd");
        assert_eq!(mem::offset_of!(IoEvent, data_len), 84, "data_len");
        assert_eq!(mem::offset_of!(IoEvent, count), 88, "count");
        assert_eq!(mem::offset_of!(IoEvent, data), 96, "data");
    }

    #[test]
    fn exec_event_zeroed_fields() {
        let header = EventHeader::new(
            EventType::Exec,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            [0u8; COMM_LEN],
            0,
            0,
            0,
        );
        let evt = ExecEvent::zeroed(header);
        assert_eq!(evt.argc, 0);
        assert_eq!(evt.retval, 0);
        assert_eq!(evt.filename, [0u8; MAX_FILENAME_LEN]);
    }

    #[test]
    fn io_event_zeroed_fields() {
        let header = EventHeader::new(
            EventType::Read,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            [0u8; COMM_LEN],
            0,
            0,
            0,
        );
        let evt = IoEvent::zeroed(header);
        assert_eq!(evt.fd, 0);
        assert_eq!(evt.data_len, 0);
        assert_eq!(evt.count, 0);
        assert_eq!(evt.data, [0u8; MAX_DATA_LEN]);
    }
}
