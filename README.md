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

# Check kernel and BPF capability status
sudo mise run run -- check

# Run (requires root or CAP_BPF + CAP_PERFMON)
sudo mise run run -- run --filter-pty    # PTY sessions only
sudo mise run run -- run                 # All processes
```

## Web UI

```sh
# Browse recorded sessions (reads SQLite DB at ./shspectr.db)
mise run run-web-dev
# Open http://localhost:3000
```

## Filtering

Composable filters narrow which processes are recorded. No filters = capture everything.

```sh
# PTY sessions (SSH, local terminals, tmux/screen)
sudo mise run run -- run --filter-pty

# Descendants of specific processes
sudo mise run run -- run --filter-ancestor sshd,ansible

# Combine filters (OR logic)
sudo mise run run -- run --filter-pty --filter-ancestor my-agent

# Output to SQLite instead of stdout
sudo mise run run -- run --output sqlite --db-path /var/lib/shspectr/shspectr.db
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
