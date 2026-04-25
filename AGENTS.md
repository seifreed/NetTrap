# Repository Guidelines

## Project Structure & Module Organization
This repository is a Rust workspace. Code lives in `crates/`, with subsystem crates such as `nettrap-core`, `nettrap-interceptor`, protocol crates like `nettrap-proto-dns`, and entry points in `nettrap-cli`, `nettrap-tui`, and `nettrap-api`. Each crate keeps code under `src/` and may include crate-local tests under `tests/`. Top-level integration helpers live in `tests/`, CI in `.github/workflows/`, Windows driver assets in `windivert/`, and build outputs in `target/`.

## Clean Architecture

This project follows Clean Architecture principles:

### Layer Organization

```
┌─────────────────────────────────────────────────────────────────┐
│                    Drivers / Entry Points                       │
│  nettrap-cli (CLI), nettrap-api (REST), nettrap-tui (Terminal)  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Use Cases / Business Logic                   │
│                      nettrap-engine                              │
│  - Engine trait (abstraction)                                    │
│  - StartupContext, ShutdownContext (entities)                   │
│  - ListenerSpawner, InterceptorSpawner (interfaces)             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Infrastructure                              │
│  nettrap-proxy, nettrap-pcap, nettrap-interceptor               │
│  nettrap-attribution, nettrap-tls-mitm, nettrap-protocols      │
└─────────────────────────────────────────────────────────────────┘
```

### Key Crates

| Crate | Layer | Purpose |
|-------|-------|---------|
| `nettrap-engine` | Use Case | Business logic, traits for DI, entities |
| `nettrap-cli` | Driver | CLI parsing, commands, adapters |
| `nettrap-core` | Core | Shared types, error types, prelude |
| `nettrap-*` | Infrastructure | Protocol handlers, interceptors, PCAP |

### Dependency Rule

- **Inner layers** (engine, core) **depend outward** (infrastructure)
- **Outer layers** (CLI) depend on inner layers
- **Dependencies point inward** through traits/interfaces

### Clean Code & Architecture Discipline

- Preserve Clean Architecture boundaries when adding or changing behavior. Keep policy and orchestration in the appropriate use-case layer, keep adapters and protocol/infrastructure details at the edges, and introduce traits/interfaces when crossing layer boundaries.
- Follow Clean Code practices: small cohesive functions, clear names, explicit error handling, minimal shared mutable state, and no unrelated refactors in feature or bug-fix changes.
- Prefer existing local abstractions and patterns over new framework-style abstractions. Add new abstractions only when they reduce real duplication or clarify a stable boundary.
- Do not hide design problems with broad `allow` attributes, dead-code workarounds, or bypasses around quality gates. Fix the underlying issue or document a narrow, justified exception.

### Testing Strategy

Components can be tested with mock implementations:

```rust
// Production
let engine = RealEngine::new(config, real_listener_spawner);

// Testing
let engine = TestEngine::new(test_config, mock_listener_spawner);
```

## Build, Test, and Development Commands

Use the workspace root for all commands.

### Build Commands

- `cargo build --release`: build the full workspace with optimizations
- `cargo build`: build in debug mode (faster compile, slower runtime)

### Test Commands

- `cargo test --all`: run all unit and integration tests across all crates
- `cargo test --package <crate-name>`: run tests for a specific crate
  - Example: `cargo test --package nettrap-proto-dns`
  - Example: `cargo test --package nettrap-proto-smtp`
- `cargo test --package <crate> --test <test-name>`: run a specific integration test file
  - Example: `cargo test --package nettrap-proto-dns --test cross_platform_tests`
- `cargo test <test-name>`: run tests matching a name pattern across all crates
  - Example: `cargo test dns_handler` runs all tests with "dns_handler" in the name
- `cargo test -- --nocapture`: run tests and show stdout/stderr output
- `cargo test -- --test-threads=1`: run tests single-threaded (for debugging race conditions)

### Lint & Format Commands

- `cargo fmt --all`: apply standard Rust formatting
- `cargo fmt --all -- --check`: verify formatting without modifying files
- `cargo clippy --all-targets --all-features -- -D warnings`: lint with clippy (CI enforced)
- `cargo clippy --fix`: auto-fix clippy warnings where possible

### Integration Tests

- `bash tests/verify_platform.sh`: verify build, tests, and interceptor availability on current platform
- `docker build -t nettrap:test .` then `docker run --rm nettrap:test /app/integration_test.sh`: run containerized integration suite

### Rust Version

- Minimum Rust version: **1.85** (specified in `Cargo.toml` `rust-version`)
- CI uses Rust **1.88** for stable builds
- Edition: **2024**

## Code Style & Naming Conventions

### Formatting

- Follow Rust 2024 edition defaults
- Use 4-space indentation
- Keep files `cargo fmt` clean
- Maximum line width: 100 characters (default)
- Treat `clippy` warnings as errors unless there's a narrow, documented `#[allow(...)]`

### Naming Conventions

- **Modules & files**: `snake_case` (e.g., `listener_config.rs`, `proto_dns`)
- **Types & traits**: `PascalCase` (e.g., `DnsHandler`, `Engine`, `ListenerSpawner`)
- **Functions & methods**: `snake_case` (e.g., `handle_query`, `spawn_tcp`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `MAX_CONNECTIONS`)
- **Crate names**: `nettrap-<subsystem>` pattern (e.g., `nettrap-proto-dns`)

### Imports

Organize imports in this order with blank lines between groups:

```rust
// 1. Standard library
use std::path::PathBuf;
use std::sync::Arc;

// 2. External crates
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

// 3. Internal crates (from workspace)
use nettrap_core::prelude::*;
use nettrap_protocols::tcp::*;

// 4. Current crate modules
use crate::handler::DnsHandler;
use crate::response::ResponseBuilder;
```

### Prelude Pattern

Most crates expose a `prelude` module for convenient imports:

```rust
// In crates/nettrap-*/src/lib.rs
pub mod prelude {
    pub use nettrap_core::prelude::*;
    pub use crate::error::{Error, Result};
    pub use crate::handler::*;
}
```

Usage:

```rust
use crate::prelude::*;
// Instead of:
// use nettrap_core::prelude::*;
// use crate::error::{Error, Result};
```

### Error Handling

Use `thiserror::Error` for error types:

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Config error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, Error>;
```

Error variants use `#[from]` for automatic conversions from `std::io::Error` and other common errors.

### Derive Macros

Order for struct/enum derives:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FiveTuple {
    // fields...
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}
```

Order: Debug → Clone → Copy (if applicable) → PartialEq → Eq → Hash → Serialize/Deserialize

### Async Traits

Use `async_trait` crate for async traits:

```rust
#[async_trait]
pub trait ListenerSpawner: Send + Sync {
    async fn spawn_tcp(&self, config: Arc<dyn ListenerConfigTrait>) -> Result<()>;
}
```

### Testing Patterns

Unit tests go in the same file under `#[cfg(test)]` module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_handler_query() {
        let handler = DnsHandler::new();
        let result = handler.handle_query(&query, addr).await;
        assert!(result.is_ok());
    }
}
```

Integration tests go in `tests/` directory within each crate:

```
crates/nettrap-proto-dns/
├── src/
│   ├── lib.rs
│   └── handler.rs
└── tests/
    └── cross_platform_tests.rs
```

### Regression Contracts

- New features must include regression contracts that lock the expected behavior at the protocol, API, CLI, or integration boundary they change. A contract can be a focused unit test, integration test, fixture/corpus case, property-style negative case, or documented quality-gate check.
- Regression contracts must cover success behavior and the most important failure or malformed-input paths, especially for protocol parsers, network framing, file-serving paths, redirection/routing, authentication flows, and async backpressure/timeouts.
- When fixing a bug, add or update a regression contract that would have failed before the fix. Do this before or alongside the implementation so future changes cannot reintroduce the bug silently.
- If a behavior cannot be tested directly, add the nearest executable contract and document the remaining manual or platform-specific verification in the change notes.

## Security & Platform Notes

### Platform-Specific Dependencies

- **Linux**: `libpcap` (required), `libnetfilter_queue` (optional for NFQUEUE)
- **macOS**: `libpcap` via Homebrew: `brew install libpcap`
- **Windows**: 
  - x86/x64: WinDivert (included in `windivert/` directory)
  - ARM64: Npcap (install separately from https://nmap.org/npcap/)

### Git Commit Guidelines

Use short, imperative subjects:

- ✅ `Add WinDivert support for Windows packet interception`
- ✅ `Fix DNS NXDomain cycling logic`
- ✅ `Implement FTP PASV mode handling`
- ❌ `Fixed the bug` (not imperative)
- ❌ `Adding support` (not present tense)

### What NOT to Commit

- Local driver binaries (`windivert/*.dll`, `windivert/*.sys`)
- Generated archives (`*.tar.gz`, `*.zip`)
- Temporary test configs (`/tmp/*.toml`)
- IDE files (`.idea/`, `.vscode/`, `*.swp`)
- Cargo lock file conflict markers

## Architecture Patterns

### Trait-Based Dependency Injection

The engine uses traits for testability:

```rust
// In nettrap-engine/src/lib.rs
pub trait ListenerSpawner: Send + Sync {
    async fn spawn_tcp(&self, config: Arc<dyn ListenerConfigTrait>) -> Result<()>;
}

// Production implementation
pub struct RealListenerSpawner;
impl ListenerSpawner for RealListenerSpawner { ... }

// Test implementation
pub struct MockListenerSpawner;
impl ListenerSpawner for MockListenerSpawner { ... }
```

### Builder Pattern

Many handlers use the builder pattern:

```rust
let handler = DnsHandler::new()
    .with_wildcard(true)
    .with_nxdomains(3)
    .with_default_response_ip("192.168.1.1");
```

### Result Type Alias

Each crate defines its own `Result<T>` alias:

```rust
pub type Result<T> = std::result::Result<T, Error>;
```
