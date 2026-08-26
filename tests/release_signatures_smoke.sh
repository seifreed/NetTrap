#!/usr/bin/env bash

set -euo pipefail

command -v cosign >/dev/null || {
    echo "cosign is required for release signature smoke" >&2
    exit 1
}

workflow="$(dirname -- "${BASH_SOURCE[0]}")/../.github/workflows/release.yml"
for marker in \
    "cosign sign-blob --yes" \
    "scripts/verify-release-signatures.sh releases" \
    "Sign Windows MSI (Authenticode)" \
    "Get-AuthenticodeSignature -LiteralPath \"nettrap-\${{ matrix.name }}.msi\""; do
    if ! grep -Fq "$marker" "$workflow"; then
        echo "release signing contract is missing: $marker" >&2
        exit 1
    fi
done

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
