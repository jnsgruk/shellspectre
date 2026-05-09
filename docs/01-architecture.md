# ShellSpectre Architecture

> Part of the [ShellSpectre docs](00-overview.md).

## System Overview

```
┌─────────────────────────────────────────────┐
│  Kernel                                     │
│                                             │
│  ┌───────────────────────────────────────┐  │
│  │  eBPF Tracepoints (shspectr-ebpf)    │  │
│  │                                       │  │
│  │  sys_enter_execve   sys_exit_execve   │  │
│  │  sys_enter_write    sys_enter_read    │  │
│  │  sys_exit_read      sys_exit_exit_group│ │
│  └──────────────┬────────────────────────┘  │
│                 │ RingBuf (256KB)            │
├─────────────────┼───────────────────────────┤
│  Userspace      │                           │
│                 ▼                            │
│  ┌──────────────────────────────────────┐   │
│  │  shspectr CLI                        │   │
│  │                                      │   │
│  │  Event Parser (event.rs)             │   │
│  │    -> Session Correlator (session.rs)│   │
│  │    -> Filter Engine (filter.rs)      │   │
│  │    -> SQLite Sink (sqlite_sink.rs)   │   │
│  └──────────────────────────────────────┘   │
│                 │                            │
│                 ▼                            │
│  ┌──────────────────────────────────────┐   │
│  │  shspectr-web                        │   │
│  │  axum server + Datastar SSE frontend │   │
│  └──────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

## Crate Roles and Boundaries

### shspectr-common — Shared Types

Role: defines all event structs and enums shared between kernel-space eBPF probes and the userspace consumer.

- `#![no_std]`, all types `#[repr(C)]`
- Contains: `ExecEvent`, `IoEvent`, `ExitEvent`, `TaskFieldOffsets`, `EventType` enum
- Source files: `lib.rs`, `event.rs`, `event_type.rs`, `offsets.rs`, plus `filter.rs`, `schema.rs`, `session.rs` (gated behind `std` feature)
- A `"std"` feature flag gates `serde` derives for userspace deserialization

Belongs here: wire-format event definitions, shared constants, field offset structs.
Does not belong here: parsing logic, filtering, any heap allocation, anything that pulls in `std` unconditionally.

Constraints: must compile under both `bpf-linker` (nightly, `--target bpfel-unknown-none`) and stable Rust. No generics that monomorphize differently across targets.

### shspectr-ebpf — eBPF Probes

Role: kernel-side syscall tracepoint programs that capture exec, I/O, and exit events.

- `#![no_std]`, `#[no_main]`, Rust nightly, compiled with `bpf-linker`
- Single `main.rs` containing all tracepoint programs

BPF maps:

| Map | Type | Purpose |
|-----|------|---------|
| `EVENTS` | RingBuf (256KB) | Event output to userspace |
| `PENDING_EXEC` | HashMap | Correlate `sys_enter_execve` with `sys_exit_execve` (key: `tgid<<32 \| pid`) |
| `PENDING_READ` | HashMap | Correlate `sys_enter_read` (captures buf pointer) with `sys_exit_read` (reads data) |
| `EXEC_SCRATCH` | PerCpuArray | Scratch space for `ExecEvent` (~5.5KB, exceeds 512B stack limit) |
| `IO_SCRATCH` | PerCpuArray | Scratch space for `IoEvent` (~4KB) |
| `EXEC_PIDS` | HashMap | Set of PIDs seen via execve; I/O capture restricted to these |
| `SELF_TGID` | Array | Own TGID for self-filtering |
| `OFFSETS` | Array | BTF-resolved `task_struct` field offsets |

BPF-side filtering:
- Skip events from own process (`SELF_TGID`)
- Only capture read/write for PIDs in `EXEC_PIDS` (processes seen via execve)
- FD filter: file descriptors 0, 1, 2 (stdin/stdout/stderr) plus any fd backed by a PTY device (detected via `is_pty_fd()` which walks `task->files->fdt->fd[n]->f_inode->i_rdev`)

Constraints: no heap, 512B stack limit per function, no loops without bounded iteration. Cannot be unit tested -- all testing goes through system tests.

### shspectr — Userspace CLI

Role: loads eBPF programs, consumes events from the ring buffer, correlates sessions, applies filters, writes to sinks.

- Rust stable, `clap` CLI, `tokio` async runtime
- Optionally includes `shspectr-web` for the `web` subcommand

Key modules:

| Module | Responsibility |
|--------|---------------|
| `main.rs` | CLI entry point: argument parsing, tracing setup, delegates to `ebpf::run()` |
| `btf.rs` | Parses kernel BTF to resolve `task_struct` field offsets at runtime |
| `event.rs` | Deserializes raw byte slices from ring buffer into typed events |
| `filter.rs` | Composable filter predicates (PTY, ancestor) with OR semantics |
| `session.rs` | `SessionCorrelator`: maintains `pid -> session_id` map using PTY grouping, ancestor inheritance, singleton fallback |
| `sqlite_sink.rs` | WAL-mode SQLite writer for `sessions` and `events` tables |

Belongs here: eBPF lifecycle management, event consumption, session logic, sink implementations, CLI definition.
Does not belong here: `#[repr(C)]` event definitions (those go in `shspectr-common`), web UI code.

### shspectr-web — Web UI

Role: read-only web interface for browsing and searching recorded sessions.

- `axum` HTTP server, `askama` templates, Tailwind CSS, Datastar (hypermedia/SSE)
- Reads directly from the SQLite database written by `shspectr`

Architecture layers:

```
presentation/   view models, ANSI-to-HTML conversion
application/    axum routes, shared state
domain/         types, EventRepository trait
infrastructure/ SQLite repository implementations
```

`EventRepository` trait decouples route handlers from storage. SSE live tail polls the DB every 500ms.

Search DSL supports field filters: `user:root comm:bash* !exit:0 pid:123`

### tests/system — System Tests

Role: end-to-end validation with real eBPF in LXD VMs.

- SSH-driven command execution against a VM running `shspectr`
- Parses JSON log output to assert on captured events
- Covers: exec/exit/IO events, PTY and ancestor filters, session correlation, SQLite sink correctness

Black-box: no library dependencies on any crate. Runs the compiled `shspectr` binary.

## Dependency DAG

```
shspectr ──> shspectr-common (std feature)
         ──> shspectr-web (optional, "web" feature)

shspectr-ebpf ──> shspectr-common (no_std, default features)

shspectr-web ──> (standalone; reads shspectr's SQLite DB directly)

tests/system ──> (black-box; runs shspectr binary in VM)
```

## Event Pipeline Detail

1. **Tracepoint fire.** eBPF programs attached to syscall tracepoints (`sys_enter_execve`, `sys_exit_execve`, `sys_enter_write`, `sys_enter_read`, `sys_exit_read`, `sys_exit_exit_group`) execute on each matching syscall. Programs read pid/tgid from `bpf_get_current_pid_tgid()` and comm from `bpf_get_current_comm()`. Fields requiring BTF-resolved offsets (ppid, euid, tty_nr, and PTY device detection fields) are read from `task_struct` via the `OFFSETS` map.

2. **Scratch arrays.** `ExecEvent` (~5.5KB) and `IoEvent` (~4KB) exceed the 512B BPF stack limit. Programs use `PerCpuArray` maps (`EXEC_SCRATCH`, `IO_SCRATCH`) as scratch space to build events.

3. **Enter/exit correlation (execve).** `sys_enter_execve` captures the filename and argv, stores a partial event in `PENDING_EXEC` keyed by `tgid<<32 | pid`. `sys_exit_execve` retrieves it, adds the return code, and emits the complete event.

4. **Enter/exit correlation (read).** `sys_enter_read` saves the userspace buffer pointer in `PENDING_READ`. `sys_exit_read` retrieves the pointer, reads the data (up to 4KB) via `bpf_probe_read_user`, and emits the event with the captured bytes.

5. **Ring buffer emission.** Completed events are reserved and submitted to the `EVENTS` ring buffer (256KB).

6. **Userspace consumption.** A tokio async loop reads events from the ring buffer. The parser (`event.rs`) extracts typed events from raw byte slices by inspecting the `EventType` discriminant.

7. **Session correlation.** `SessionCorrelator` assigns a `session_id` to each event (see below).

8. **Filtering.** The filter engine evaluates OR-composed predicates. An event passes if any filter matches (e.g., has a PTY, or is a descendant of a configured ancestor process).

9. **Sink.** The SQLite sink writes to two tables (`sessions`, `events`) in WAL mode for concurrent read access by `shspectr-web`.

## Session Correlation

`SessionCorrelator` uses a 3-tier strategy to assign `session_id` values:

1. **PTY grouping.** If a process has a non-zero `tty_nr`, all processes sharing that `tty_nr` belong to the same session. This naturally groups everything within an SSH session or local terminal.

2. **Ancestor inheritance.** On execve, the process inherits its parent's `session_id` from the correlator's `pid -> session_id` map. If the parent PID is tracked, the child joins the same session.

3. **Singleton fallback.** If a process has no PTY and no known ancestor in the map, it gets a session keyed by its own PID. This handles daemon-spawned or cron processes that still trigger execve.

The correlator updates its map on every execve (insert/update) and exit (cleanup) event.

## Security Properties

- **Passive observation.** Read-only attachment to syscall tracepoints. No `ptrace`, no process injection, no signal delivery, no memory modification.
- **Privilege requirements.** Requires `root` or `CAP_BPF` + `CAP_PERFMON` capabilities.
- **Kernel version.** Requires Linux 5.8+ for `BPF_MAP_TYPE_RINGBUF` support.
- **Self-exclusion.** The eBPF programs filter out events from their own TGID to avoid feedback loops.
