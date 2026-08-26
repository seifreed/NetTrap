#!/usr/bin/env bash

set -euo pipefail

command -v cosign >/dev/null || {
    echo "cosign is required for release signature smoke" >&2
    exit 1
}

workflow="$(dirname -- "${BASH_SOURCE[0]}")/../.github/workflows/release.yml"
for marker in \
    "cosign sign-blob --yes" \
    'cosign sign --yes "$image_ref"' \
    'cosign verify "$image_ref"' \
    "scripts/verify-release-signatures.sh releases" \
    "Verify release Linux/Windows protocol parity" \
    "tests/compare_protocol_matrix_reports.py" \
    "Block release on open high or critical alerts" \
    "bash scripts/security-evidence.sh target/security-audit" \
    "Upload release security evidence" \
    "Require independent audit report" \
    "scripts/verify-external-audit.sh" \
    "Run macOS listener E2E smoke" \
    "Sign Windows MSI (Authenticode)" \
    "Get-AuthenticodeSignature -LiteralPath \"nettrap-\${{ matrix.name }}.msi\"" \
    "Packaged executable Authenticode verification failed" \
    "codesign --verify --strict \"\$clean_dir/nettrap\"" \
    "sha256_file()" \
    "shasum -a 256 \"\$1\""; do
    if ! grep -Fq "$marker" "$workflow"; then
        echo "release signing contract is missing: $marker" >&2
        exit 1
    fi
done

bash "$(dirname -- "${BASH_SOURCE[0]}")/external_audit_gate_smoke.sh"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

artifact="$workdir/artifact"
bundle="$artifact.sigstore.json"
printf 'nettrap release signature smoke\n' >"$artifact"

export COSIGN_PASSWORD="$(openssl rand -hex 16)"
cosign generate-key-pair --output-key-prefix "$workdir/key" >/dev/null
cosign sign-blob --key "$workdir/key.key" --bundle "$bundle" "$artifact" >/dev/null
cosign verify-blob --key "$workdir/key.pub" --bundle "$bundle" "$artifact" >/dev/null

printf 'tampered\n' >>"$artifact"
if cosign verify-blob --key "$workdir/key.pub" --bundle "$bundle" "$artifact" >/dev/null 2>&1; then
    echo "tampered release artifact was accepted" >&2
    exit 1
fi

echo "PASS: release signature verification rejects tampering"
