# ShellSpectre Overview

ShellSpectre is a passive Linux session recorder built with Rust and eBPF (via aya-rs). It hooks syscall tracepoints to capture command executions, I/O, and process lifecycle events for SSH sessions, local interactive shells, and agent-spawned processes. Monitored sessions are never modified.

## How to Read These Docs

| Document | Scope |
|---|---|
| `00-overview.md` | What ShellSpectre is, doc index, codebase map |
| `01-architecture.md` | System design, event pipeline, crate roles |
| `02-technology.md` | Technology stack, performance characteristics |
| `03-code-structure.md` | Code organisation principles, naming conventions, module structure |
| `04-development.md` | Building, testing, workflow, pre-commit hooks |
| `05-decision-log.md` | Dated log of significant architectural decisions |
| `01-spec.md` | Original specification (reference) |
| `AGENTS.md` | AI agent instructions with summarised build and convention reference |
| `README.md` | Quickstart |

## Codebase Map

```
shspectr/                  # Workspace root
├── shspectr/              #   Userspace CLI binary (Rust stable)
├── shspectr-ebpf/         #   eBPF probe programs (Rust nightly, #![no_std])
├── shspectr-common/       #   Shared event types (kernel + userspace, #![no_std], #[repr(C)])
├── shspectr-web/          #   Web UI for session browsing (axum + askama + Tailwind + Datastar)
├── otel-demo/             #   Docker Compose stack for local OTel visualization (Loki + Grafana)
├── tests/                 #   End-to-end tests via spread + LXD
├── docs/                  #   Architecture and decision documentation
├── plans/                 #   Implementation plans (git-ignored)
├── mise.toml              #   Task runner definitions
├── prek.toml              #   Pre-commit hook configuration
├── spread.yaml             #   System test configuration
├── clippy.toml            #   Strict clippy thresholds
└── Cargo.toml             #   Workspace root
```

---

> The docs describe how things are now and why — not a historical log. When making significant changes, update the relevant doc and add a decision log entry.
