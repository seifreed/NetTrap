# Repository Guidelines

## Project Structure & Module Organization
This repository is a Rust workspace. Code lives in `crates/`, with subsystem crates such as `nettrap-core`, `nettrap-interceptor`, protocol crates like `nettrap-proto-dns`, and entry points in `nettrap-cli`, `nettrap-tui`, and `nettrap-api`. Each crate keeps code under `src/` and may include crate-local tests under `tests/`. Top-level integration helpers live in `tests/`, CI in `.github/workflows/`, Windows driver assets in `windivert/`, and build outputs in `target/`.

## Build, Test, and Development Commands
Use the workspace root for all commands.

- `cargo build --release`: build the full workspace.
- `cargo test --all`: run unit and integration tests across crates.
- `cargo test --package nettrap-proto-dns`: run a focused crate test pass while developing.
- `cargo fmt --all`: apply standard Rust formatting.
- `cargo clippy --all-targets --all-features -- -D warnings`: enforce the same lint bar used in CI.
- `bash tests/verify_platform.sh`: verify build, tests, and interceptor availability on the current platform.
- `docker build -t nettrap:test .` then `docker run --rm nettrap:test /app/integration_test.sh`: run the containerized integration suite.

## Coding Style & Naming Conventions
Follow Rust 2024 edition defaults and format with `rustfmt`; use 4-space indentation and keep files `cargo fmt` clean. Prefer snake_case for modules, files, functions, and test names, and PascalCase for types and traits. Keep new crates under the `nettrap-*` pattern. Treat `clippy` warnings as errors unless there is a narrow, documented `#[allow(...)]`.

## Testing Guidelines
Put unit tests next to the code they cover or in crate-level `tests/` directories. Name test files by behavior, for example `platform_tests.rs`, `smtp_tests.rs`, or `cross_platform_tests.rs`. Use `#[tokio::test]` for async paths. Before opening a PR, run `cargo test --all`, the relevant package-specific tests, and the platform or Docker script when changing interceptors, protocol handlers, or startup flows.

## Commit & Pull Request Guidelines
Recent commits use short, imperative subjects such as `Add WinDivert support for Windows packet interception`. Keep that style: start with a verb, describe the user-visible change, and keep the subject focused. PRs should include a concise summary, affected platforms or crates, linked issues, and validation notes listing the commands you ran. Include screenshots only when CLI or TUI behavior changes.

## Security & Configuration Notes
Platform-specific packet capture dependencies matter: Linux uses `libpcap` and optionally NFQUEUE, macOS uses `libpcap`, and Windows uses WinDivert for x86/x64 or Npcap on ARM64. Do not commit local driver binaries, generated archives, or temporary test configs.
