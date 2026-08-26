#!/usr/bin/env bash

set -euo pipefail

report=${1:-${NETTRAP_EXTERNAL_AUDIT_REPORT:-SECURITY_AUDIT_REPORT.md}}

if [[ ! -s "$report" ]]; then
    echo "independent security audit report is missing or empty: $report" >&2
    exit 1
fi

require_marker() {
    local pattern=$1
    if ! grep -Eiq "$pattern" "$report"; then
        echo "external security audit report is missing required evidence: $pattern" >&2
        exit 1
    fi
}

require_marker '^#.*(independent|third.party).*security audit'
require_marker '(^|[^[:alpha:]])auditor([^[:alpha:]]|:)'
require_marker '(report date|audit date):[[:space:]]*20[0-9]{2}-[0-9]{2}-[0-9]{2}'
require_marker '^##?[[:space:]]+scope'
require_marker '^##?[[:space:]]+(findings|results)'
require_marker '(severity|risk)[[:space:]]*(rank|level|classification)'
require_marker '(reproduction|reproduce|proof.of.concept)'
require_marker '(retest|verification|remediation)[[:space:]]*(statement|result|status)?'

if grep -Eiq '^[[:space:]]*(TODO|TBD|INCOMPLETE|PLACEHOLDER)([[:space:]:]|$)|\[[[:space:]]*(TODO|TBD|INCOMPLETE|PLACEHOLDER)[[:space:]]*\]' "$report"; then
    echo "external security audit report contains unresolved placeholders" >&2
    exit 1
fi

echo "PASS: external security audit evidence is complete enough for release admission"
