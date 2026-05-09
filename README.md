# ShellSpectre

Passive Linux session recorder built with Rust and eBPF. Captures command executions, I/O, and process lifecycle events at the syscall level. Records SSH sessions, local terminals, and agent-spawned processes without modifying monitored sessions.

The binary and crate names use the abbreviation `shspectr`.

## Quick Start

```sh
# Install system dependencies
sudo apt install clang mold pkg-config

# Install toolchain
mise install

# Build everything (eBPF + userspace)
mise run build

# Build and run with SQLite + web UI (requires root or CAP_BPF + CAP_PERFMON)
sudo mise run dev
# Open http://localhost:3000
```

## Web UI

```sh
# Browse recorded sessions standalone (reads SQLite DB at ./shspectr.db)
mise run dev-web
# Open http://localhost:3000
```

## Filtering

Composable filters narrow which processes are recorded. Pass extra args after `mise run dev --`:

```sh
# PTY sessions (SSH, local terminals, tmux/screen)
sudo mise run dev -- --filter-pty

# Descendants of specific processes
sudo mise run dev -- --filter-ancestor sshd,ansible

# Combine filters (OR logic)
sudo mise run dev -- --filter-pty --filter-ancestor my-agent

# Custom DB path
sudo mise run dev -- --db-path /var/lib/shspectr/shspectr.db
```

## Development

```sh
mise run test          # Unit tests
mise run test-system   # End-to-end tests (requires LXD)
mise run fmt           # Format
mise run clippy        # Lint
prek run -av           # All pre-commit checks
```

## Documentation

See [docs/00-overview.md](docs/00-overview.md) for architecture, technology stack, code structure, and decision log.

## Requirements

- Linux kernel 5.8+ with BPF support
- Root or CAP_BPF + CAP_PERFMON capabilities
- Rust stable + nightly (managed by mise)
