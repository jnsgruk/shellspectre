# AGENTS.md

## Project Overview

ShellSpectre is a passive Linux session recorder built with Rust and eBPF (via aya-rs). It hooks syscall tracepoints to capture command executions, I/O, and process lifecycle events for SSH sessions, local interactive shells, and agent-spawned processes.

See [docs/00-overview.md](docs/00-overview.md) for the full knowledge base.

## Workflow

- Always use Test-Driven Development: write failing tests before implementation. Limit each iteration to at most 3 failing tests to keep work incremental.
- Prefer testing external behaviour (interfaces, CLIs, APIs) over internal implementation details.
- Use `prek` (Rust rewrite of pre-commit) for pre-commit hooks.
- Use `mise` to author formatting, linting, and testing tasks that are run with `prek`.
- Always use conventional commits.
- Always break work down into small, logical commits.
- Never add the `Co-authored-by:` trailer for the agent.
- When working autonomously, use `--no-gpg-sign` to commit without the user's presence.
- If the change affects architecture or conventions, update the relevant `docs/` file.
- If the change represents a significant decision, add a dated entry to `docs/05-decision-log.md`.

## Plans

When the user asks for a new plan, always create a markdown file in the `plans/` directory (git-ignored). Files must be numbered with two-digit prefixes. Check existing files to determine the next number. Plans should include clear steps, acceptance criteria, and any open questions.

## Quick Reference

```sh
sudo apt install clang mold pkg-config   # System deps
mise install                              # Toolchain setup
mise run build                            # Build everything (eBPF + userspace)
mise run test                             # Unit tests
mise run test-system                      # System tests (requires LXD)
mise run fmt                              # Format
mise run clippy                           # Lint
prek run -av                              # All pre-commit hooks
sudo mise run dev                         # Build and run with SQLite + web UI
```

## Code Conventions

- **Rust edition**: 2024
- **File length**: 1000 lines max (guidance, not enforced). Consider splitting at ~500.
- **eBPF crate**: `#![no_std]`, `#[no_main]`. No heap. BPF stack or BPF maps only.
- **Shared types**: `#[repr(C)]`, `#![no_std]` in `shspectr-common`.
- **Error handling**: `anyhow` (CLI), `Result<(), i64>` (eBPF), typed enums (web domain).
- **Linting**: `clippy::pedantic` + restriction lints. Zero warnings. See `clippy.toml`.
- **Naming**: snake_case files. Module path provides context — no redundant prefixes.
- **No junk drawers**: No `utils/` or `helpers/` directories.
- **Tests**: Inline `#[cfg(test)] mod tests` at file bottom. Colocated, not in separate directories.

See [docs/03-code-structure.md](docs/03-code-structure.md) for full conventions and [docs/04-development.md](docs/04-development.md) for development workflow.
