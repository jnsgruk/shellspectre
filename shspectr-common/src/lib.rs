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

/// Byte offsets resolved from kernel BTF at runtime, shared with eBPF
/// via an array map. These allow reading `ppid`, `euid`, and `tty_nr`
/// from `task_struct` without hardcoding kernel-version-specific offsets.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TaskFieldOffsets {
    /// Offset of `real_parent` (ptr) in `task_struct`.
    pub task_real_parent: u64,
    /// Offset of `tgid` (pid_t) in `task_struct`.
    pub task_tgid: u64,
    /// Offset of `cred` (ptr) in `task_struct`.
    pub task_cred: u64,
    /// Offset of `euid` (kuid_t) in `cred`.
    pub cred_euid: u64,
    /// Offset of `signal` (ptr) in `task_struct`.
    pub task_signal: u64,
    /// Offset of `tty` (ptr) in `signal_struct`.
    pub signal_tty: u64,
    /// Offset of `index` (int) in `tty_struct`.
    pub tty_index: u64,
}

impl TaskFieldOffsets {
    /// Return all offsets as an array indexed by [`offset_idx`] constants.
    ///
    /// This is the single source of truth for the mapping between struct
    /// fields and BPF array map indices.
    pub const fn as_array(&self) -> [u64; offset_idx::COUNT as usize] {
        [
            self.task_real_parent,
            self.task_tgid,
            self.task_cred,
            self.cred_euid,
            self.task_signal,
            self.signal_tty,
            self.tty_index,
        ]
    }
}

/// Array map indices for [`TaskFieldOffsets`] fields, used with a
/// `BPF_MAP_TYPE_ARRAY` of `u64` values.
pub mod offset_idx {
    pub const TASK_REAL_PARENT: u32 = 0;
    pub const TASK_TGID: u32 = 1;
    pub const TASK_CRED: u32 = 2;
    pub const CRED_EUID: u32 = 3;
    pub const TASK_SIGNAL: u32 = 4;
    pub const SIGNAL_TTY: u32 = 5;
    pub const TTY_INDEX: u32 = 6;
    pub const COUNT: u32 = 7;
}

/// Discriminant for the type of event captured.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum EventType {
    Exec = 0,
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
    fn task_field_offsets_array_length_matches_count() {
        let offsets = TaskFieldOffsets {
            task_real_parent: 10,
            task_tgid: 20,
            task_cred: 30,
            cred_euid: 40,
            task_signal: 50,
            signal_tty: 60,
            tty_index: 70,
        };
        let arr = offsets.as_array();
        assert_eq!(arr.len(), offset_idx::COUNT as usize);
        assert_eq!(arr[offset_idx::TASK_REAL_PARENT as usize], 10);
        assert_eq!(arr[offset_idx::TASK_TGID as usize], 20);
        assert_eq!(arr[offset_idx::TASK_CRED as usize], 30);
        assert_eq!(arr[offset_idx::CRED_EUID as usize], 40);
        assert_eq!(arr[offset_idx::TASK_SIGNAL as usize], 50);
        assert_eq!(arr[offset_idx::SIGNAL_TTY as usize], 60);
        assert_eq!(arr[offset_idx::TTY_INDEX as usize], 70);
    }
}

/// Metadata for a filter keyword, used for autocompletion and help.
#[derive(Debug, Clone, Copy)]
pub struct FilterKeywordMeta {
    /// The keyword name (e.g. "pid", "ppid").
    pub keyword: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Expected value type: "number", "text", or "glob".
    pub value_type: &'static str,
    /// Example usage.
    pub example: &'static str,
    /// Whether this keyword supports `!` negation.
    pub supports_negation: bool,
}

/// All supported filter keywords.
pub const FILTER_KEYWORDS: &[FilterKeywordMeta] = &[
    FilterKeywordMeta {
        keyword: "pid",
        description: "Process ID",
        value_type: "number",
        example: "pid:1234",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "ppid",
        description: "Parent process ID",
        value_type: "number",
        example: "ppid:1",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "user",
        description: "Username or UID",
        value_type: "text",
        example: "user:root",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "comm",
        description: "Kernel task name (supports * and ? globs)",
        value_type: "glob",
        example: "comm:bash",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "cmd",
        description: "Command name from path (supports * and ? globs)",
        value_type: "glob",
        example: "cmd:git",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "exit",
        description: "Exit code",
        value_type: "number",
        example: "exit:0",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "session",
        description: "Session ID (prefix match)",
        value_type: "text",
        example: "session:ox_abc",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "gid",
        description: "Group ID",
        value_type: "number",
        example: "gid:1000",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "euid",
        description: "Effective user ID",
        value_type: "number",
        example: "euid:0",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "tty",
        description: "TTY number (0 = no PTY)",
        value_type: "number",
        example: "tty:34816",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "file",
        description: "Executable path (supports * and ? globs)",
        value_type: "glob",
        example: "file:/usr/bin/*",
        supports_negation: true,
    },
];
