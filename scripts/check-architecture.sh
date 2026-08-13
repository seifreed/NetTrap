#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

direct_workspace_dependencies() {
    cargo tree -p "$1" --edges normal --depth 1 --prefix none \
        | sed -n '2,$s/^\(nettrap-[^ ]*\) .*/\1/p' \
        | sort -u
}

check_dependencies() {
    local package="$1"
    local expected="$2"
    local actual
    actual="$(direct_workspace_dependencies "$package")"
    if [[ "$actual" != "$expected" ]]; then
        printf '%s has unexpected direct workspace dependencies; expected:\n%s\nfound:\n%s\n' \
            "$package" "$expected" "$actual" >&2
        exit 1
    fi
}

check_dependencies nettrap-core ""
check_dependencies nettrap-engine "nettrap-core"
check_dependencies nettrap-api $'nettrap-core\nnettrap-engine\nnettrap-flow'
check_dependencies nettrap-distributed "nettrap-core"

printf 'Architecture dependency direction: OK\n'
