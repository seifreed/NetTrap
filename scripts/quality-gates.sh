#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/quality-gates.sh [quick|full]

Modes:
  quick  Run PR-blocking gates: fmt, clippy, tests, audit, deny, lockfile, check, diff.
  full   Run quick gates plus udeps, coverage, semver, fuzzing, benchmarks, and outdated.
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

require_nightly_toolchain() {
    require_command rustup
    rustup which rustc --toolchain nightly >/dev/null
}

run_nightly() {
    local nightly_bin
    nightly_bin="$(dirname "$(rustup which rustc --toolchain nightly)")"
    PATH="$nightly_bin:$PATH" "$nightly_bin/cargo" "$@"
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
    run cargo test -- --test-threads=1
    run cargo audit
    run cargo deny check
    run scripts/check-architecture.sh
    run scripts/check-deployment.sh
    validate_lockfile_resolution
    run cargo check --all-targets --all-features
    run git diff --check
    ensure_lockfile_clean
}

run_coverage() {
    local coverage_dir="target/quality-gates/coverage"
    mkdir -p "$coverage_dir"
    rm -f cobertura.xml tarpaulin-report.html
    run cargo tarpaulin --fail-under 70 --out Xml --out Html --output-dir "$coverage_dir"
}

run_semver_check() {
    local baseline
    baseline="$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || printf 'HEAD^')"
    run run_nightly semver-checks --workspace --baseline-rev "$baseline"
}

run_fuzz_smoke() {
    local target
    for target in $(run_nightly fuzz list); do
        run run_nightly fuzz run "$target" -- -max_total_time=10
    done
}

run_full() {
    require_command cargo-udeps
    require_command cargo-tarpaulin
    require_command cargo-fuzz
    require_command cargo-semver-checks
    require_command cargo-outdated
    require_nightly_toolchain

    run_quick
    run run_nightly udeps --all-targets --all-features
    run_coverage
    run_semver_check
    run run_nightly fuzz build
    run_fuzz_smoke
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
