#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/quality-gates.sh [quick|full]

Modes:
  quick  Run PR-blocking gates: fmt, clippy, tests, audit, deny, lockfile, check, diff.
  full   Run quick gates plus udeps, tarpaulin, fuzz smoke, benchmarks, and outdated.
EOF
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

mode="${1:-quick}"

run() {
    printf '\n==> %s\n' "$*"
    "$@"
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'missing required command: %s\n' "$1" >&2
        exit 127
    fi
}

ensure_lockfile_clean() {
    if ! git diff --quiet -- Cargo.lock; then
        printf 'Cargo.lock changed during quality gates. Commit the lockfile update.\n' >&2
        git diff -- Cargo.lock >&2
        exit 1
    fi
}

validate_lockfile_resolution() {
    printf '\n==> cargo metadata --locked --format-version 1\n'
    cargo metadata --locked --format-version 1 >/dev/null
}

run_quick() {
    require_command cargo-audit
    require_command cargo-deny

    run cargo fmt --all -- --check
    run cargo clippy --all-targets --all-features -- -D warnings
    run cargo test
    run cargo audit
    run cargo deny check
    validate_lockfile_resolution
    run cargo check --all-targets --all-features
    run git diff --check
    ensure_lockfile_clean
}

run_full() {
    require_command cargo-udeps
    require_command cargo-tarpaulin
    require_command cargo-fuzz
    require_command cargo-outdated

    run_quick
    run cargo +nightly udeps --all-targets --all-features
    run cargo tarpaulin --out Xml --out Html
    run cargo +nightly fuzz build
    run cargo +nightly fuzz run http_request_parse -- -max_total_time=10
    run cargo bench --no-fail-fast
    run cargo outdated
}

case "$mode" in
    quick)
        run_quick
        ;;
    full)
        run_full
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
