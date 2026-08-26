#!/usr/bin/env bash
set -euo pipefail

: "${NETTRAP_MACOS_P12_BASE64:?NETTRAP_MACOS_P12_BASE64 is required for native macOS signing}"
: "${NETTRAP_MACOS_P12_PASSWORD:?NETTRAP_MACOS_P12_PASSWORD is required for native macOS signing}"
: "${NETTRAP_MACOS_SIGNING_IDENTITY:?NETTRAP_MACOS_SIGNING_IDENTITY is required for native macOS signing}"
if (($# == 0)); then
    echo "usage: $0 <binary> [<binary> ...]" >&2
    exit 2
fi

workdir="$(mktemp -d)"
keychain="$workdir/nettrap-signing.keychain-db"
p12="$workdir/signing.p12"
keychain_password="$(uuidgen)"
cleanup() {
    security delete-keychain "$keychain" >/dev/null 2>&1 || true
    rm -rf "$workdir"
}
trap cleanup EXIT

printf '%s' "$NETTRAP_MACOS_P12_BASE64" | base64 -D >"$p12"
security create-keychain -p "$keychain_password" "$keychain" >/dev/null
security set-keychain-settings -lut 900 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security import "$p12" -k "$keychain" -P "$NETTRAP_MACOS_P12_PASSWORD" -T /usr/bin/codesign >/dev/null
security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_password" "$keychain" >/dev/null
security list-keychains -d user -s "$keychain"

for path in "$@"; do
    [[ -f "$path" ]] || { echo "macOS signing input is missing: $path" >&2; exit 1; }
    codesign --force --options runtime --timestamp --sign "$NETTRAP_MACOS_SIGNING_IDENTITY" "$path"
    codesign --verify --strict "$path"
done
