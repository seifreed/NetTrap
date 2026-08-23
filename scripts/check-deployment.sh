#!/usr/bin/env bash
set -euo pipefail

manifest="deploy/kubernetes/deployment.yaml"

grep -Eq '^        image: .+@sha256:[0-9a-f]{64}$' "$manifest"
grep -Fq '      automountServiceAccountToken: false' "$manifest"
grep -Fq '          type: RuntimeDefault' "$manifest"
grep -Fq '          allowPrivilegeEscalation: false' "$manifest"
grep -Fq '          readOnlyRootFilesystem: true' "$manifest"
grep -Fq '            - ALL' "$manifest"

if grep -Fq ':latest' "$manifest"; then
    echo "Kubernetes deployment must not use a mutable latest tag" >&2
    exit 1
fi
