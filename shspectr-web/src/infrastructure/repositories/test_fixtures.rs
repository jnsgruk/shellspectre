//! Test fixture builders for repository integration tests.

use rusqlite::params;

#[allow(dead_code)]
pub(super) struct SessionRow<'a> {
    pub id: &'a str,
    pub root_pid: u32,
    pub uid: u32,
    pub euid: u32,
}

#[rustfmt::skip]
impl<'a> SessionRow<'a> {
    pub fn new(id: &'a str) -> Self { Self { id, root_pid: 100, uid: 1000, euid: 1000 } }
    #[allow(dead_code)] pub fn root_pid(mut self, v: u32) -> Self { self.root_pid = v; self }
    #[allow(dead_code)] pub fn uid(mut self, v: u32) -> Self { self.uid = v; self }
    #[allow(dead_code)] pub fn euid(mut self, v: u32) -> Self { self.euid = v; self }
    pub fn insert(self, conn: &rusqlite::Connection) {
        conn.execute(
            "INSERT INTO sessions (id, started_at, root_pid, uid, euid) \
             VALUES (?1, datetime('now'), ?2, ?3, ?4)",
            params![self.id, self.root_pid, self.uid, self.euid],
        )
        .expect("insert test session");
    }
}

pub(super) struct ExecEventRow<'a> {
    pub session_id: &'a str,
    pub execution_id: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub tty_nr: Option<u32>,
    pub comm: &'a str,
    pub filename: &'a str,
    pub argv: &'a str,
    pub exit_code: Option<i32>,
}

#[rustfmt::skip]
impl<'a> ExecEventRow<'a> {
    pub fn new(session_id: &'a str) -> Self {
        Self {
            session_id, execution_id: 100, pid: 100, ppid: 1, uid: 1000, gid: 1000, euid: 1000,
            tty_nr: None, comm: "cmd", filename: "/usr/bin/cmd", argv: "[]", exit_code: Some(0),
        }
    }
    pub fn execution_id(mut self, v: u64) -> Self { self.execution_id = v; self }
    pub fn pid(mut self, v: u32) -> Self { self.pid = v; self }
    pub fn ppid(mut self, v: u32) -> Self { self.ppid = v; self }
    pub fn uid(mut self, v: u32) -> Self { self.uid = v; self }
    pub fn gid(mut self, v: u32) -> Self { self.gid = v; self }
    pub fn euid(mut self, v: u32) -> Self { self.euid = v; self }
    pub fn tty_nr(mut self, v: u32) -> Self { self.tty_nr = Some(v); self }
    pub fn comm(mut self, v: &'a str) -> Self { self.comm = v; self }
    pub fn filename(mut self, v: &'a str) -> Self { self.filename = v; self }
    pub fn argv(mut self, v: &'a str) -> Self { self.argv = v; self }
    pub fn exit_code(mut self, v: i32) -> Self { self.exit_code = Some(v); self }
    #[allow(dead_code)] pub fn no_exit_code(mut self) -> Self { self.exit_code = None; self }
    pub fn insert(self, conn: &rusqlite::Connection) {
        conn.execute(
            "INSERT INTO events \
             (session_id, event_type, timestamp, execution_id, pid, ppid, uid, gid, euid, tty_nr, comm, filename, argv, exit_code) \
             VALUES (?1, 'exec', datetime('now'), ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                self.session_id, self.execution_id, self.pid, self.ppid, self.uid, self.gid, self.euid,
                self.tty_nr, self.comm, self.filename, self.argv, self.exit_code,
            ],
        )
        .expect("insert test exec event");
    }
}

pub(super) struct IoEventRow<'a> {
    pub session_id: &'a str,
    pub execution_id: u64,
    pub pid: u32,
    pub event_type: &'a str,
    pub fd: u32,
    pub data: &'a str,
}

#[rustfmt::skip]
impl<'a> IoEventRow<'a> {
    pub fn new(session_id: &'a str) -> Self {
        Self { session_id, execution_id: 100, pid: 100, event_type: "write", fd: 1, data: "" }
    }
    pub fn execution_id(mut self, v: u64) -> Self { self.execution_id = v; self }
    pub fn pid(mut self, v: u32) -> Self { self.pid = v; self }
    pub fn event_type(mut self, v: &'a str) -> Self { self.event_type = v; self }
    pub fn fd(mut self, v: u32) -> Self { self.fd = v; self }
    pub fn data(mut self, v: &'a str) -> Self { self.data = v; self }
    pub fn insert(self, conn: &rusqlite::Connection) {
        conn.execute(
            "INSERT INTO events \
             (session_id, event_type, timestamp, execution_id, pid, ppid, uid, gid, euid, fd, data, data_len, byte_count) \
             VALUES (?1, ?2, datetime('now'), ?3, ?4, 1, 1000, 1000, 1000, ?5, ?6, ?7, ?8)",
            params![
                self.session_id, self.event_type, self.execution_id, self.pid, self.fd,
                self.data, self.data.len(), self.data.len(),
            ],
        )
        .expect("insert test io event");
    }
}
