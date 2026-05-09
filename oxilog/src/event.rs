//! Event parsing: converts raw ring buffer bytes into structured Rust types.
//!
//! All functions in this module are pure — they take byte slices and return
//! structured data, with no I/O side effects. This makes them straightforward
//! to unit test with synthetic data.

use oxilog_common::{EventHeader, ExecEvent, ExitEvent, IoEvent, MAX_ARGV_COUNT};

/// A parsed exec event with owned string fields, ready for logging or
/// serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub comm: String,
    pub tty_nr: u32,
    pub cgroup_id: u64,
    pub filename: String,
    pub argv: Vec<String>,
    pub retval: i64,
}

/// Parse a raw exec event from ring buffer bytes.
///
/// Returns `None` if the buffer is too short.
pub fn parse_exec_event(data: &[u8]) -> Option<ParsedExecEvent> {
    if data.len() < core::mem::size_of::<ExecEvent>() {
        return None;
    }

    // SAFETY: ExecEvent is repr(C), we verified the length, and use
    // read_unaligned because ring buffer data may not be aligned.
    let event = unsafe { core::ptr::read_unaligned(data.as_ptr().cast::<ExecEvent>()) };
    let header = &event.header;

    let arg_count = event.argc as usize;
    let argv = (0..arg_count.min(MAX_ARGV_COUNT))
        .map(|i| cstr_from_bytes(&event.argv[i]))
        .collect();

    Some(ParsedExecEvent {
        pid: header.pid,
        ppid: header.ppid,
        uid: header.uid,
        gid: header.gid,
        euid: header.euid,
        comm: cstr_from_bytes(&header.comm),
        tty_nr: header.tty_nr,
        cgroup_id: header.cgroup_id,
        filename: cstr_from_bytes(&event.filename),
        argv,
        retval: event.retval,
    })
}

/// Parse the event header from raw ring buffer bytes.
///
/// Returns `None` if the buffer is too short.
pub fn parse_header(data: &[u8]) -> Option<EventHeader> {
    if data.len() < core::mem::size_of::<EventHeader>() {
        return None;
    }

    // SAFETY: EventHeader is repr(C), we verified the length.
    Some(unsafe { core::ptr::read_unaligned(data.as_ptr().cast::<EventHeader>()) })
}

/// A parsed exit event with fields ready for logging or serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedExitEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub comm: String,
    pub tty_nr: u32,
    pub cgroup_id: u64,
    pub exit_code: i32,
}

/// Parse a raw exit event from ring buffer bytes.
///
/// Returns `None` if the buffer is too short.
pub fn parse_exit_event(data: &[u8]) -> Option<ParsedExitEvent> {
    if data.len() < core::mem::size_of::<ExitEvent>() {
        return None;
    }

    // SAFETY: ExitEvent is repr(C), we verified the length, and use
    // read_unaligned because ring buffer data may not be aligned.
    let event = unsafe { core::ptr::read_unaligned(data.as_ptr().cast::<ExitEvent>()) };
    let header = &event.header;

    Some(ParsedExitEvent {
        pid: header.pid,
        ppid: header.ppid,
        uid: header.uid,
        gid: header.gid,
        euid: header.euid,
        comm: cstr_from_bytes(&header.comm),
        tty_nr: header.tty_nr,
        cgroup_id: header.cgroup_id,
        exit_code: event.exit_code,
    })
}

/// A parsed I/O event with fields ready for logging or serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedIoEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub comm: String,
    pub tty_nr: u32,
    pub cgroup_id: u64,
    pub fd: u32,
    pub data: Vec<u8>,
    pub count: u64,
}

/// Parse a raw I/O event from ring buffer bytes.
///
/// Returns `None` if the buffer is too short.
pub fn parse_io_event(data: &[u8]) -> Option<ParsedIoEvent> {
    if data.len() < core::mem::size_of::<IoEvent>() {
        return None;
    }

    // SAFETY: IoEvent is repr(C), we verified the length, and use
    // read_unaligned because ring buffer data may not be aligned.
    let event = unsafe { core::ptr::read_unaligned(data.as_ptr().cast::<IoEvent>()) };
    let header = &event.header;

    let data_len = (event.data_len as usize).min(oxilog_common::MAX_DATA_LEN);

    Some(ParsedIoEvent {
        pid: header.pid,
        ppid: header.ppid,
        uid: header.uid,
        gid: header.gid,
        euid: header.euid,
        comm: cstr_from_bytes(&header.comm),
        tty_nr: header.tty_nr,
        cgroup_id: header.cgroup_id,
        fd: event.fd,
        data: event.data[..data_len].to_vec(),
        count: event.count,
    })
}

/// Extract a UTF-8 string from a null-terminated byte buffer.
///
/// Stops at the first null byte. Invalid UTF-8 sequences are replaced
/// with the Unicode replacement character (U+FFFD).
pub fn cstr_from_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxilog_common::EventType;

    #[test]
    fn cstr_from_bytes_normal_string() {
        let buf = b"hello\0world";
        assert_eq!(cstr_from_bytes(buf), "hello");
    }

    #[test]
    fn cstr_from_bytes_no_null() {
        let buf = b"hello";
        assert_eq!(cstr_from_bytes(buf), "hello");
    }

    #[test]
    fn cstr_from_bytes_empty() {
        assert_eq!(cstr_from_bytes(b""), "");
    }

    #[test]
    fn cstr_from_bytes_leading_null() {
        assert_eq!(cstr_from_bytes(b"\0abc"), "");
    }

    #[test]
    fn cstr_from_bytes_invalid_utf8() {
        let buf = [0xff, 0xfe, 0x00];
        assert_eq!(cstr_from_bytes(&buf), "\u{FFFD}\u{FFFD}");
    }

    /// Build a minimal ExecEvent byte buffer for testing.
    fn make_exec_event(filename: &str, argv: &[&str], retval: i64) -> Vec<u8> {
        let header = EventHeader::new(
            EventType::Exec,
            12345,
            100,
            1,
            100,
            100,
            1000,
            1000,
            1000,
            *b"test\0\0\0\0\0\0\0\0\0\0\0\0",
            7,
            42,
        );
        let mut event = ExecEvent::zeroed(header);
        event.retval = retval;
        event.argc = argv.len() as u32;

        // Write filename
        let fname = filename.as_bytes();
        event.filename[..fname.len()].copy_from_slice(fname);

        // Write argv
        for (i, arg) in argv.iter().enumerate() {
            let bytes = arg.as_bytes();
            event.argv[i][..bytes.len()].copy_from_slice(bytes);
        }

        // SAFETY: ExecEvent is repr(C), converting to bytes is safe.
        let ptr = &event as *const ExecEvent as *const u8;
        unsafe { core::slice::from_raw_parts(ptr, core::mem::size_of::<ExecEvent>()) }.to_vec()
    }

    #[test]
    fn parse_exec_event_roundtrip() {
        let data = make_exec_event("/usr/bin/ls", &["ls", "-la", "/tmp"], 0);
        let parsed = parse_exec_event(&data).expect("should parse");

        assert_eq!(parsed.filename, "/usr/bin/ls");
        assert_eq!(parsed.argv, vec!["ls", "-la", "/tmp"]);
        assert_eq!(parsed.retval, 0);
        assert_eq!(parsed.pid, 100);
        assert_eq!(parsed.ppid, 1);
        assert_eq!(parsed.uid, 1000);
        assert_eq!(parsed.gid, 1000);
        assert_eq!(parsed.euid, 1000);
        assert_eq!(parsed.comm, "test");
        assert_eq!(parsed.tty_nr, 7);
        assert_eq!(parsed.cgroup_id, 42);
    }

    #[test]
    fn parse_exec_event_failed_exec() {
        let data = make_exec_event("/usr/bin/nonexistent", &["nonexistent"], -2);
        let parsed = parse_exec_event(&data).expect("should parse");
        assert_eq!(parsed.retval, -2);
    }

    #[test]
    fn parse_exec_event_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_exec_event(&data).is_none());
    }

    #[test]
    fn parse_header_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_header(&data).is_none());
    }

    #[test]
    fn parse_exec_event_no_args() {
        let data = make_exec_event("/bin/true", &[], 0);
        let parsed = parse_exec_event(&data).expect("should parse");
        assert!(parsed.argv.is_empty());
    }

    fn make_exit_event(exit_code: i32) -> Vec<u8> {
        let header = EventHeader::new(
            EventType::Exit,
            99999,
            200,
            1,
            200,
            200,
            1000,
            1000,
            0,
            *b"bash\0\0\0\0\0\0\0\0\0\0\0\0",
            7,
            42,
        );
        let event = oxilog_common::ExitEvent { header, exit_code };

        let ptr = &event as *const oxilog_common::ExitEvent as *const u8;
        unsafe {
            core::slice::from_raw_parts(ptr, core::mem::size_of::<oxilog_common::ExitEvent>())
        }
        .to_vec()
    }

    #[test]
    fn parse_exit_event_success() {
        let data = make_exit_event(0);
        let parsed = parse_exit_event(&data).expect("should parse");

        assert_eq!(parsed.pid, 200);
        assert_eq!(parsed.ppid, 1);
        assert_eq!(parsed.exit_code, 0);
        assert_eq!(parsed.comm, "bash");
        assert_eq!(parsed.tty_nr, 7);
        assert_eq!(parsed.cgroup_id, 42);
    }

    #[test]
    fn parse_exit_event_nonzero_code() {
        let data = make_exit_event(1);
        let parsed = parse_exit_event(&data).expect("should parse");
        assert_eq!(parsed.exit_code, 1);
    }

    #[test]
    fn parse_exit_event_signal_death() {
        // Process killed by signal 9 → exit code 137 (128 + 9)
        let data = make_exit_event(137);
        let parsed = parse_exit_event(&data).expect("should parse");
        assert_eq!(parsed.exit_code, 137);
    }

    #[test]
    fn parse_exit_event_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_exit_event(&data).is_none());
    }

    fn make_io_event(fd: u32, payload: &[u8], count: u64) -> Vec<u8> {
        let header = EventHeader::new(
            if fd == 0 {
                EventType::Read
            } else {
                EventType::Write
            },
            55555,
            300,
            1,
            300,
            300,
            1000,
            1000,
            0,
            *b"cat\0\0\0\0\0\0\0\0\0\0\0\0\0",
            7,
            42,
        );
        let mut event = oxilog_common::IoEvent {
            header,
            fd,
            data_len: payload.len() as u32,
            count,
            data: [0u8; oxilog_common::MAX_DATA_LEN],
        };
        event.data[..payload.len()].copy_from_slice(payload);

        let ptr = &event as *const oxilog_common::IoEvent as *const u8;
        unsafe { core::slice::from_raw_parts(ptr, core::mem::size_of::<oxilog_common::IoEvent>()) }
            .to_vec()
    }

    #[test]
    fn parse_io_event_write_stdout() {
        let data = make_io_event(1, b"hello world\n", 12);
        let parsed = parse_io_event(&data).expect("should parse");

        assert_eq!(parsed.pid, 300);
        assert_eq!(parsed.fd, 1);
        assert_eq!(parsed.data, b"hello world\n");
        assert_eq!(parsed.count, 12);
        assert_eq!(parsed.comm, "cat");
    }

    #[test]
    fn parse_io_event_read_stdin() {
        let data = make_io_event(0, b"input\n", 6);
        let parsed = parse_io_event(&data).expect("should parse");

        assert_eq!(parsed.fd, 0);
        assert_eq!(parsed.data, b"input\n");
        assert_eq!(parsed.count, 6);
    }

    #[test]
    fn parse_io_event_empty_data() {
        let data = make_io_event(2, b"", 0);
        let parsed = parse_io_event(&data).expect("should parse");

        assert_eq!(parsed.fd, 2);
        assert!(parsed.data.is_empty());
    }

    #[test]
    fn parse_io_event_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_io_event(&data).is_none());
    }
}
