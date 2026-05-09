# Technology Stack and Performance

> Part of the [ShellSpectre docs](00-overview.md).

## Technology Stack

| Layer | Technology | Notes |
|---|---|---|
| eBPF framework | aya-rs (aya-ebpf + aya) | Rust-native, no libbpf/C dependency |
| Kernel interface | Tracepoints (syscalls) | sys_enter/exit_execve, sys_enter_write, sys_enter/exit_read, sys_exit_exit_group |
| Transport | BPF RingBuf (256KB) | Lock-free kernel-to-userspace, requires kernel 5.8+ |
| CLI | clap | Derive-based argument parsing |
| Async runtime | tokio | Ring buffer consumption + web server |
| Logging | tracing + tracing-subscriber | Structured JSON output |
| Storage | SQLite (rusqlite, bundled) | WAL mode, sessions + events tables |
| OTel export | OTLP/HTTP (reqwest) | `--output otel --otel-endpoint URL`; logs format, no traces dependency |
| Web framework | axum | Async HTTP with tower middleware |
| Templates | askama | Compile-time checked HTML templates |
| Frontend | Datastar v1 + Tailwind CSS v4 | Hypermedia/SSE, no JS framework |
| CSS build | Tailwind CLI (downloaded at build time) | Embedded in binary via include_str! |
| Serialization | serde + serde_json | Event serialization, conditional via feature flag in common crate |
| BTF parsing | Custom (btf.rs) | Resolves task_struct field offsets at runtime |
| Linker | mold (via clang) | Fast linking for dev iterations |
| Linting | clippy (pedantic + cherry-picked restriction) | See clippy.toml for thresholds |
| Pre-commit | prek | Rust rewrite of pre-commit; runs fmt, clippy |
| Task runner | mise | Build orchestration, tool management |
| System tests | LXD VMs + openssh crate | Real eBPF loading in isolated VMs |

## System Requirements

| Requirement | Minimum |
|---|---|
| Linux kernel | 5.8+ (BPF_MAP_TYPE_RINGBUF) |
| Kernel config | CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y, CONFIG_BPF_EVENTS=y |
| BTF support | CONFIG_DEBUG_INFO_BTF=y (recommended for portable tracepoint access) |
| Permissions | Root or CAP_BPF + CAP_PERFMON |
| Build deps | clang, mold, pkg-config (apt) |
| Rust | Stable (userspace) + Nightly (eBPF crate) |

## Performance Characteristics

### eBPF Side

- Zero-copy ring buffer: events written directly to shared memory.
- Per-CPU scratch arrays avoid contention (no locks).
- BPF-side filtering drops irrelevant events before they reach userspace: SELF_TGID check, EXEC_PIDS gate for I/O, FD filter (0/1/2 only).
- Enter-to-exit correlation via BPF HashMaps (kernel-managed, O(1) lookup).

### Userspace Side

- Async ring buffer consumption via tokio (non-blocking).
- Session correlator: O(1) HashMap lookups for pid-to-session mapping.
- SQLite WAL mode: concurrent reads (web UI) don't block writes (event ingestion).
- Tailwind CSS compiled at build time, served as embedded static asset.

### Known Limits

- Argv: 20 args x 256 bytes each (BPF instruction budget).
- I/O data: 4KB per event (configurable).
- OTel sink: I/O event data is truncated to 4 KiB and base64-encoded, so binary payloads survive transport but large outputs are lossy.
- Ring buffer: 256KB — high event volume can cause drops (kernel increments lost count).
- File length: 1000 lines max (guidance).
