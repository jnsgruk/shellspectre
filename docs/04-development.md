# Development Workflow

> Part of the [ShellSpectre docs](00-overview.md).

## Prerequisites

```sh
# System dependencies
sudo apt install clang mold pkg-config

# Toolchain management
mise install          # sets up Rust stable, prek, Go, spread (nightly via cargo +nightly)
```

## Building

```sh
mise run build-ebpf   # eBPF crate only (nightly, bpf target)
mise run build        # Everything: eBPF first, then userspace (stable)
mise run build-web    # Web crate only (downloads Tailwind on first run)
```

The eBPF crate must be built before the userspace crate (the binary embeds the compiled BPF object). The `build` task handles this ordering via `depends = ["build-ebpf"]`.

## Running

```sh
# Requires root or CAP_BPF + CAP_PERFMON
sudo mise run run -- run --filter-pty              # Record PTY sessions only
sudo mise run run -- run --filter-ancestor sshd    # Record sshd descendants
sudo mise run run -- run                           # Record all processes (stdout sink)
sudo mise run run -- run --output sqlite           # Record to SQLite database

# Web UI (standalone, no eBPF needed — reads existing SQLite DB)
mise run run-web-dev                           # Dev mode (port 3000, ./shspectr.db)
mise run run-web                               # Via main binary (builds eBPF first)

# Check kernel and BPF capability status
sudo mise run run -- check
```

## Testing

### Unit Tests

```sh
mise run test         # Runs: cargo test -p shspectr -p shspectr-common -p shspectr-web
```

Tests are inline `#[cfg(test)] mod tests` at the bottom of each source file. Cover parsing, filtering, session correlation, SQLite operations, repository queries, view model formatting.

### Web Integration Tests

Located in `shspectr-web/tests/`. HTTP-level tests using reqwest against a real axum server with in-memory SQLite. Cover:

- Smoke tests (server starts, serves pages)
- Event listing (pagination, filtering, sorting)
- Event detail rendering
- Live tail SSE streaming

### System Tests (End-to-End)

```sh
mise run test-system  # Requires LXD; runs with --test-threads=1
```

Provisions LXD VMs, builds and deploys shspectr, runs commands via SSH, verifies JSON log output and SQLite contents. Covers exec/exit/IO events, filters, session correlation.

The eBPF crate cannot be unit tested (`#![no_std]`, BPF target). All BPF logic is tested through system tests.

## Code Quality

### Pre-commit Hooks (prek)

```sh
prek run -av          # Run all hooks manually
```

Hooks:

- `trailing-whitespace` — strip trailing spaces
- `end-of-file-fixer` — ensure newline at EOF
- `check-added-large-files` — prevent large binaries
- `cargo fmt --check` — formatting
- `cargo clippy` — linting (pedantic, zero warnings)
- `check-file-length` — max 750 lines per .rs file

### Formatting and Linting

```sh
mise run fmt          # Format all Rust code (stable + nightly for eBPF)
mise run clippy       # Lint all crates (workspace + eBPF)
```

## Workflow

1. Write failing tests first (TDD). Max 3 failing tests per iteration.
2. Implement until tests pass.
3. Run `prek run -av` before committing.
4. Use conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`).
5. Break work into small, logical commits.
6. If the change affects architecture, update the relevant `docs/` file.
7. If it's a significant decision, add a dated entry to `docs/05-decision-log.md`.

### Commit Conventions

- Conventional Commits format
- When committing autonomously (as an AI agent): use `--no-gpg-sign`
- Never add `Co-authored-by:` trailer for the agent

## Test Placement

Tests are colocated with source. No separate test directories (except integration/system tests).

```rust
// At the bottom of any source file
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exec_event() {
        // ...
    }
}
```
