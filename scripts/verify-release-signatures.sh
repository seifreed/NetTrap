#!/usr/bin/env bash
set -euo pipefail

release_dir=${1:-.}
identity=${COSIGN_CERTIFICATE_IDENTITY:?COSIGN_CERTIFICATE_IDENTITY is required}
issuer=${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}

command -v cosign >/dev/null || {
  echo "cosign is required to verify release signatures" >&2
  exit 1
}

shopt -s nullglob
artifacts=(
  "$release_dir"/nettrap-*.tar.gz "$release_dir"/nettrap-*.zip
  "$release_dir"/nettrap-*.binary "$release_dir"/nettrap-*.msi
  "$release_dir"/nettrap-*.deb "$release_dir"/nettrap-*.rpm
  "$release_dir"/nettrap.rb "$release_dir"/SHA256SUMS
  "$release_dir"/nettrap.spdx.json
  "$release_dir"/nettrap-oci-image.txt
  "$release_dir"/nettrap-kubernetes-deployment.yaml
)

if ((${#artifacts[@]} == 0)); then
  echo "no release artifacts found in $release_dir" >&2
  exit 1
fi

for artifact in "${artifacts[@]}"; do
  bundle="${artifact}.sigstore.json"
  [[ -s "$bundle" ]] || {
    echo "missing Sigstore bundle: $bundle" >&2
    exit 1
  }
  cosign verify-blob \
    --bundle "$bundle" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer "$issuer" \
    "$artifact"
done

echo "PASS: verified ${#artifacts[@]} release artifact signatures"
