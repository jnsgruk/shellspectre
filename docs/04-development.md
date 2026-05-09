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
```

The eBPF crate must be built before running the userspace collector because `shspectr` loads the compiled eBPF artifact from disk at startup. The `build` task handles this ordering via `depends = ["build-ebpf"]`. If the artifact is missing, `shspectr` fails with an explicit error telling you to run `mise run build-ebpf` or `mise run build`.

## Running

```sh
# Build and run with SQLite + web UI (requires root or CAP_BPF + CAP_PERFMON)
sudo mise run dev

# Web UI (standalone, no eBPF needed — reads an existing collector-created SQLite DB)
mise run dev-web                               # Dev mode (port 3000, ./shspectr.db)
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
mise run test-system  # Requires LXD + spread; builds first, then runs spread -v
```

System tests use [spread](https://github.com/canonical/spread) — a full-system test runner that provisions LXD VMs, syncs project artifacts, and runs shell-script tests.

**How it works:**

1. `spread.yaml` defines an `adhoc` LXD backend that launches an Ubuntu 26.04 VM
2. The global `prepare` installs the pre-built `shspectr` binary and eBPF artifact, starts a systemd service (`shspectr-test.service`), and waits for the web UI on port 3000
3. Each test is a `task.yaml` file containing shell commands that run in the VM and assert against the SQLite database using `sqlite3` queries and spread's `MATCH`/`NOMATCH`

**Test structure:**

```
spread.yaml
tests/
  lib/
    shspectr-test.service     # systemd unit installed in VM
    assert_db.py              # SQLite assertion helper (stdlib only)
    cloud-config.yaml             # Cloud-init config for LXD VMs
  exec-event/task.yaml
  exit-event/task.yaml
  io-write-event/task.yaml
  io-read-event/task.yaml
  filter-pty/task.yaml
  session-correlation/task.yaml
  sqlite-sink/task.yaml
```

**Running and debugging:**

- `spread -v` — run all tests with verbose output
- `spread -reuse` — keep VMs alive across runs for fast iteration
- `spread -debug` — drop into a shell at the failure point
- `spread tests/exec-event` — run a single test

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
