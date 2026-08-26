#!/usr/bin/env bash

set -euo pipefail

script="$(dirname -- "${BASH_SOURCE[0]}")/../scripts/verify-external-audit.sh"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

cat >"$workdir/valid.md" <<'EOF'
# Independent Third-Party Security Audit
Auditor: Example Security Ltd.
Report date: 2026-08-26

## Scope
Network parsing and release controls.

## Findings
Severity rank: None.
Reproduction: each finding includes reproduction steps.
Retest statement: all findings were retested after remediation.
EOF

bash "$script" "$workdir/valid.md"

sed '/Retest statement/d' "$workdir/valid.md" >"$workdir/invalid.md"
if bash "$script" "$workdir/invalid.md" >/dev/null 2>&1; then
    echo "incomplete external audit report was accepted" >&2
    exit 1
fi

echo "PASS: external audit gate rejects incomplete evidence"
