# Code Structure and Conventions

> Part of the [ShellSpectre docs](00-overview.md).

## Workspace Layout

```
shspectr/
├── shspectr-common/       # Shared event types (#![no_std], #[repr(C)])
├── shspectr-ebpf/         # eBPF tracepoint programs (nightly, #![no_std])
├── shspectr/              # CLI: eBPF loader, event consumer, sinks
└── shspectr-web/          # Web UI: session viewer, event browser
```

## Current Organisation

### shspectr-common/ — Shared Types

Source files: `lib.rs` (re-exports), `event.rs` (`#[repr(C)]` event structs, `EventHeader`), `event_type.rs` (`EventType` enum), `offsets.rs` (`TaskFieldOffsets`). The `std` feature enables three additional modules: `filter.rs` (search keyword metadata), `schema.rs` (SQLite DDL), `session.rs` (`SessionId` newtype). Must stay `#![no_std]` at baseline.

### shspectr-ebpf/ — Single File

`main.rs`: All BPF tracepoint programs and map definitions. Cannot be split further due to eBPF toolchain constraints.

### shspectr/ — Flat Module Structure

```
shspectr/src/
├── main.rs           # CLI parsing, tracing setup, delegates to ebpf.rs
├── btf.rs            # Kernel BTF parsing for task_struct offsets
├── event.rs          # Raw [u8] → parsed event types
├── filter.rs         # Composable PTY/ancestor filters
├── session.rs        # Session correlator (pid → session_id)
└── sqlite_sink.rs    # SQLite writer (WAL mode)
```

Each file owns a single concern. At current size this is at the Tier 1–2 boundary (see [When to Add Structure](#when-to-add-structure)).

### shspectr-web/ — Layered Architecture

```
shspectr-web/src/
├── lib.rs            # ServerConfig, start_server
├── domain/           # Pure types and traits
│   ├── event.rs      #   EventSummary, EventDetail, EventFilter parser
│   ├── listing.rs    #   Page<T>, ListRequest, SortDirection
│   ├── filter.rs     #   Search DSL keywords, filter parsing
│   └── repositories.rs  # EventRepository trait
├── infrastructure/   # External system implementations
│   ├── database.rs   #   r2d2 SQLite pool
│   └── repositories/
│       └── event.rs  #   SqlEventRepository
├── application/      # HTTP handlers and routing
│   ├── state.rs      #   AppState with Arc<dyn EventRepository>
│   └── routes/
│       ├── api.rs    #   REST + SSE endpoints
│       ├── app.rs    #   Page routes
│       ├── middleware.rs  # CSP headers
│       ├── static_assets.rs
│       └── support.rs
└── presentation/     # View models and formatting
    └── web/
        ├── event.rs  #   EventSummaryView, ANSI→HTML
        ├── listing.rs #  Paginated, ListNavigator
        └── username.rs # UID→username resolution
```

Follows hexagonal architecture: domain defines traits, infrastructure implements them, application wires everything, presentation handles display formatting.

## Naming Conventions

| Element | Convention | Example |
|---|---|---|
| Files/modules | snake_case | `sqlite_sink.rs` |
| Structs/enums | PascalCase | `SessionCorrelator`, `EventType` |
| Functions | snake_case | `parse_exec_event()` |
| Constants | SCREAMING_SNAKE_CASE | `EVENTS`, `SELF_TGID` |
| Doc comments | `//!` at module top | `//! Session correlation logic` |

Use the module path as context. Don't prefix filenames with the parent module name:

```
domain/event.rs           ← good
domain/domain_event.rs    ← redundant, avoid
```

## Structural Rules

### File Length

- **Guideline: 1000 lines** max per `.rs` file
- Guideline: consider splitting at ~500 lines

### Clippy Thresholds

Defined in `clippy.toml`:

| Rule | Limit |
|---|---|
| Function body | 75 lines |
| Cognitive complexity | 20 |
| Function params | 6 |
| Pass-by-value size | 128 bytes |
| Error variant size | 128 bytes |
| Async future size | 8192 bytes |

### Lint Configuration

Workspace-level in `Cargo.toml`. `clippy::pedantic` and `clippy::cargo` groups enabled as warnings. Cherry-picked restriction lints include `undocumented_unsafe_blocks`, `dbg_macro`, `print_stdout`, `print_stderr`, `unwrap_used`, `expect_used`, `wildcard_enum_match_arm`, `rest_pat_in_fully_bound_structs`, `missing_assert_message`. See `Cargo.toml` `[workspace.lints.clippy]` for the full list.

Tests allow `unwrap`/`expect`/`dbg` via `clippy.toml`.

### Error Handling

| Context | Approach |
|---|---|
| CLI (shspectr) | `anyhow::Result` |
| eBPF (shspectr-ebpf) | `Result<(), i64>` (kernel convention) |
| Web domain | Typed error enums |
| Web application | Domain errors mapped to HTTP status codes |

### No Junk Drawers

No `utils/` or `helpers/` directories. Every piece of code belongs in a module that describes its purpose.

## When to Add Structure

Follow the module size tier model:

| Tier | Size | Structure |
|---|---|---|
| 1 | < 150 LOC | Single file |
| 2 | 150–500 LOC | `mod.rs` as pure re-export, logic in named siblings |
| 3 | 500+ LOC | Nested subdirectories for distinct concerns |

Example — if `filter.rs` grows to support redaction rules and OTel attribute matching:

```
# Before (Tier 1)
shspectr/src/filter.rs

# After (Tier 2)
shspectr/src/filter/
├── mod.rs            # pub use pty::PtyFilter; pub use ancestor::AncestorFilter;
├── pty.rs            # PTY-based filtering
└── ancestor.rs       # Process tree ancestor matching
```

The `mod.rs` file re-exports only — no logic:

```rust
//! Composable event filters.

mod ancestor;
mod pty;

pub use ancestor::AncestorFilter;
pub use pty::PtyFilter;
```

### Choosing Between Flat and Layered

The CLI crate uses flat modules because its concerns are linear: load eBPF → consume events → filter → write to sink. No dependency inversion needed.

The web crate uses layered architecture because it benefits from separating the repository trait (domain) from its SQLite implementation (infrastructure), enabling testing with in-memory databases and keeping HTTP handlers independent of storage details.

Use layered architecture when you need trait-based abstraction boundaries. Use flat modules when the data flows in one direction without polymorphism.

### Test Fixture Extraction

When a `#[cfg(test)]` block grows large enough that it would push a file toward the 1000-line limit, extract fixtures (builders, helpers, shared setup) into a sibling `_fixtures.rs` file. Wire it in with `#[path]`:

```rust
#[cfg(test)]
#[allow(clippy::expect_used)]
#[path = "test_fixtures.rs"]
mod test_fixtures;

#[cfg(test)]
#[allow(clippy::expect_used)]
#[path = "event_tests.rs"]
mod tests;
```

The fixture file uses `pub(super)` visibility — it is not part of the public API. This keeps the main implementation file readable while respecting the line limit. See `shspectr-web/src/infrastructure/repositories/` for a worked example.

Builder structs in fixture files use the consuming-setter pattern (`fn field(mut self, v: T) -> Self`) with a terminal `insert(self, conn: &Connection)` method. All fields have sensible defaults so call sites only override what they care about.
