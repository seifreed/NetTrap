#!/usr/bin/env bash

set -euo pipefail

repo="${GITHUB_REPOSITORY:-seifreed/NetTrap}"
output_dir="${1:-target/security-audit}"
mkdir -p "$output_dir"

command -v cargo-audit >/dev/null 2>&1 || {
    echo "cargo-audit is required; install it with: cargo install cargo-audit --locked" >&2
    exit 1
}
command -v cargo-deny >/dev/null 2>&1 || {
    echo "cargo-deny is required; install it with: cargo install cargo-deny --locked" >&2
    exit 1
}
command -v gh >/dev/null 2>&1 || {
    echo "gh is required to collect repository security controls" >&2
    exit 1
}
command -v jq >/dev/null 2>&1 || {
    echo "jq is required to validate repository security controls" >&2
    exit 1
}

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$output_dir/generated-at.txt"
git rev-parse HEAD >"$output_dir/commit.txt"
git diff --check >"$output_dir/diff-check.txt"
cargo audit --version >"$output_dir/tool-versions.txt"
cargo deny --version >>"$output_dir/tool-versions.txt"
gh --version | head -n 1 >>"$output_dir/tool-versions.txt"
cargo audit --json >"$output_dir/cargo-audit.json"
cargo deny check >"$output_dir/cargo-deny.txt" 2>&1
gh api "repos/$repo/branches/main/protection" >"$output_dir/branch-protection.json"
gh api "repos/$repo/code-scanning/alerts" --paginate >"$output_dir/code-scanning-alerts.json"

if rg -n --glob '*.yml' --glob '*.yaml' \
    'uses:\s*[^#[:space:]]+@(v[0-9]|stable|nightly|main|master)(\s|$)' \
    .github; then
    echo "Unpinned GitHub Actions references found" >&2
    exit 1
fi

jq -e '
    (.required_pull_request_reviews.required_approving_review_count >= 1)
    and (.required_pull_request_reviews.require_code_owner_reviews == true)
    and (.required_pull_request_reviews.require_last_push_approval == true)
    and (.enforce_admins.enabled == true)
    and (.required_status_checks.strict == true)
    and (([
        "Build & Test (Linux x86_64-unknown-linux-gnu)",
        "Build & Test (Linux aarch64-unknown-linux-gnu)",
        "Build & Test (Windows x86_64-pc-windows-msvc)",
        "Build & Test (Windows aarch64-pc-windows-msvc)",
        "Verify Linux/Windows protocol parity",
        "Hostile E2E Smoke",
        "Rust Quality",
        "Lockfile and Diff Hygiene",
        "Security Audit",
        "Dependency Security Audit",
        "CodeQL Rust Analysis"
    ] - (.required_status_checks.contexts // [])) | length == 0)
    and (.allow_force_pushes.enabled == false)
    and (.allow_deletions.enabled == false)
' "$output_dir/branch-protection.json" >/dev/null

jq '{open_alerts: ([.[] | select(.state == "open")] | length),
     open_high_or_critical: ([.[] | select(.state == "open" and
       (.rule.security_severity_level == "high" or
        .rule.security_severity_level == "critical"))] | length)}' \
    "$output_dir/code-scanning-alerts.json" \
    | tee "$output_dir/summary.json"

echo "Security evidence written to $output_dir"
