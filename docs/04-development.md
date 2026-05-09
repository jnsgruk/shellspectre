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
mise run test-system  # Requires LXD; runs with --test-threads=1
```

Provisions a single LXD VM shared across all tests via `LazyLock`, installs `shspectr` once, then runs each test against the same VM. Tests use `TestHarness` for the common start/exercise/stop/collect workflow and typed `Event` structs for assertions.

**Architecture:**

- **Shared VM fixture** (`fixture.rs`): A `LazyLock<Mutex<SharedState>>` provisions one VM on first access and installs artifacts once. All tests reuse it.
- **Systemd drop-in** (`vm.rs`): The `shspectr-test.service` unit is baked into the base VM image. Tests write a drop-in env file (`/etc/shspectr-test.env`) with extra args — no heredoc or `daemon-reload` at runtime.
- **In-VM readiness polling** (`shspectr.rs`): A single SSH command runs a polling loop inside the VM, replacing per-iteration SSH round-trips.
- **Test harness** (`harness.rs`): `TestHarness::capture()` encapsulates start/exercise/stop/collect into one call. Returns typed `Event` structs.
- **Typed events** (`event.rs`): `Event` struct deserialises the tracing JSON format (fields nested under `"fields"`). Replaces brittle `line.contains()` matching.

SSH helpers use isolated `known_hosts` state so tests do not depend on or modify the user's real SSH configuration. Test VMs are cleaned up via RAII and stale `shspectr-test-*` instances are deleted opportunistically before provisioning. The smoke test provisions its own VM independently to validate the provisioning code path.

The standalone web server does not create the database. Start the collector with `--output sqlite` first so the DB schema exists before running `shspectr-web`.

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
