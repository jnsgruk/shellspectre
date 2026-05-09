# AGENTS.md

## Project Overview

ShellSpectre is a passive Linux session recorder built with Rust and eBPF (via aya-rs). It hooks syscall tracepoints to capture command executions, I/O, and process lifecycle events for SSH sessions, local interactive shells, and agent-spawned processes.

See `docs/01-spec.md` for the full specification.

## Workflow

- Always use Test-Driven Development: write failing tests before implementation. Limit each iteration to at most 3 failing tests to keep work incremental.
- Prefer testing external behaviour (interfaces, CLIs, APIs) over internal implementation details.
- Use `prek` (Rust rewrite of pre-commit) for pre-commit hooks.
- Use `mise` to author formatting, linting, and testing tasks that are run with `prek`.
- Always use conventional commits.
- Always break work down into small, logical commits.
- Never add the `Co-authored-by:` trailer for the agent.
- When working autonomously, use `--no-gpg-sign` to commit without the user's presence.

## Plans

When the user asks for a new plan, always create a markdown file in the `plans/` directory (git-ignored). Files must be numbered with two-digit prefixes, e.g.:

```
plans/
├── 01-initial-scaffold.md
├── 02-bootstrap-cli.md
├── 03-ebpf-tracepoints.md
└── ...
```

Check existing files in `plans/` to determine the next number. Plans should include clear steps, acceptance criteria, and any open questions.

## Workspace Layout

```
shspectr/
├── shspectr/              # Userspace CLI crate (Rust stable)
├── shspectr-ebpf/         # eBPF probe crate (Rust nightly, #![no_std])
├── shspectr-common/       # Shared event types (both kernel and userspace, #![no_std])
├── docs/                  # Specifications and design documents
├── mise.toml              # Toolchain and task definitions
├── Cargo.toml             # Workspace root
└── AGENTS.md
```

## Build

System dependencies must be installed via apt:

```sh
sudo apt install clang mold pkg-config
```

All tooling is managed by mise. Run `mise install` to set up the toolchain.

```sh
mise run build          # Build everything (eBPF + userspace)
mise run build-ebpf     # Build eBPF crate only (nightly)
mise run test           # Run userspace tests
mise run clippy         # Lint
mise run fmt            # Format
```

The eBPF crate must be built before the userspace crate. The `build` task handles ordering.

Running requires root or `CAP_BPF` + `CAP_PERFMON`:

```sh
sudo mise run run -- --filter-pty
```

## Code Conventions

- **Rust edition**: 2024
- **eBPF crate**: `#![no_std]`, `#[no_main]`. No heap allocations. All data structures must fit on the BPF stack or use BPF maps.
- **Shared types**: All types in `shspectr-common` must be `#[repr(C)]` and `#![no_std]` compatible. These are used directly in both BPF ring buffer events and userspace deserialization.
- **Userspace crate**: Standard Rust. Uses `clap` for CLI, `tracing` + `tracing-subscriber` for structured logging and output, `aya` for BPF program management, `serde` for serialization.
- **Error handling**: Use `anyhow` in the userspace crate. BPF programs return `Result<(), i64>`.
- **Formatting**: `cargo fmt` (rustfmt defaults). Run before committing.
- **Linting**: `cargo clippy` must pass with no warnings.

## Key Dependencies

| Crate | Used in | Purpose |
|-------|---------|---------|
| `aya` | shspectr | Load/manage BPF programs, read ring buffer |
| `aya-ebpf` | shspectr-ebpf | BPF program macros and helpers |
| `aya-log` / `aya-log-ebpf` | both | BPF-side logging to userspace |
| `clap` | shspectr | CLI argument parsing |
| `tracing` | shspectr | Structured event output |
| `tracing-subscriber` | shspectr | JSON formatting, log layers |
| `rusqlite` | shspectr | SQLite sink storage |
| `serde` / `serde_json` | shspectr, shspectr-common | Event serialization |
| `anyhow` | shspectr | Error handling |
| `tokio` | shspectr | Async runtime for ring buffer consumption |

## Testing

- **Unit tests**: `cargo test -p shspectr`. Cover event parsing, session correlation logic, filter matching, and sink formatting.
- **Integration tests**: Require root or elevated capabilities. Run in a VM or with `sudo`. These load actual BPF programs and verify end-to-end event capture.
- **No BPF unit tests**: The `shspectr-ebpf` crate cannot be tested with `cargo test` (no_std, BPF target). Test BPF logic through integration tests.

## Architecture Notes

- Events flow: BPF tracepoint → ring buffer → userspace consumer → session correlator → filter engine → sink
- Session correlation (ancestor tracking) is done entirely in userspace by maintaining a `pid → session_id` map updated on execve/exit events.
- BPF-side filtering is limited to PTY checks (`tty_nr`) and cgroup ID map lookups to keep probe complexity low.
- I/O data is captured at full fidelity up to a configurable per-event limit (default 4KB in BPF). Userspace can reassemble across multiple events if needed.
