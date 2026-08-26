#!/usr/bin/env bash

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "SKIP: network namespace E2E requires Linux"
    exit 0
fi

if [[ "${NETTRAP_NAMESPACE_E2E:-0}" != "1" ]]; then
    echo "SKIP: set NETTRAP_NAMESPACE_E2E=1 to run the privileged test"
    exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "FAIL: network namespace E2E requires root" >&2
    exit 1
fi

for command in ip curl nft iptables ip6tables; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "FAIL: missing required command: $command" >&2
        exit 1
    }
done

NETTRAP_BIN="${NETTRAP_BIN:-./target/release/nettrap}"
if [[ ! -x "$NETTRAP_BIN" ]]; then
    echo "FAIL: NetTrap binary is not executable: $NETTRAP_BIN" >&2
    exit 1
fi

namespace="nettrap-e2e-$$"
host_veth="ntvh-$$"
peer_veth="ntvp-$$"
config_file="$(mktemp)"
log_file="$(mktemp)"
body_file="$(mktemp)"
nettrap_pid=""

cleanup() {
    if [[ -n "$nettrap_pid" ]] && kill -0 "$nettrap_pid" 2>/dev/null; then
        kill -TERM "$nettrap_pid" 2>/dev/null || true
        wait "$nettrap_pid" 2>/dev/null || true
    fi
    ip netns del "$namespace" 2>/dev/null || true
    rm -f "$config_file" "$log_file" "$body_file"
}

trap cleanup EXIT

cat >"$config_file" <<'EOF'
attribution_enabled = false
network_mode = "multihost"
redirect_all_traffic = true
default_decision = "emulate"
default_tcp_listener = "http"
pcap_enabled = false
output_format = "jsonl"

[[listeners]]
name = "http"
protocol = "tcp"
port = 18080
bind_address = "0.0.0.0"
enabled = true
emulate_response = true
EOF

ip netns add "$namespace"
ip link add "$host_veth" type veth peer name "$peer_veth"
ip link set "$peer_veth" netns "$namespace"
ip addr add 198.18.0.1/24 dev "$host_veth"
ip link set "$host_veth" up
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" ip addr add 198.18.0.2/24 dev "$peer_veth"
ip netns exec "$namespace" ip link set "$peer_veth" up
ip netns exec "$namespace" ip route add default via 198.18.0.1

start_nettrap() {
    "$NETTRAP_BIN" run --intercept -c "$config_file" >"$log_file" 2>&1 &
    nettrap_pid=$!

    for _ in $(seq 1 40); do
        if (echo >/dev/tcp/127.0.0.1/18080) >/dev/null 2>&1; then
            return 0
        fi
        if ! kill -0 "$nettrap_pid" 2>/dev/null; then
            break
        fi
        sleep 0.25
    done

    echo "FAIL: NetTrap HTTP listener did not become ready" >&2
    cat "$log_file" >&2
    return 1
}

assert_redirected_request() {
    local status
    status="$(ip netns exec "$namespace" curl --noproxy '*' --silent --show-error \
        --max-time 10 --output "$body_file" --write-out '%{http_code}' \
        http://198.18.0.1:18081/)"
    if [[ "$status" != "200" ]] || ! grep -Fq "It Works!" "$body_file"; then
        echo "FAIL: namespace traffic was not redirected to the HTTP listener (status=$status)" >&2
        cat "$log_file" >&2
        return 1
    fi
}

start_nettrap
assert_redirected_request

kill -KILL "$nettrap_pid"
wait "$nettrap_pid" 2>/dev/null || true
nettrap_pid=""

start_nettrap
assert_redirected_request

kill -TERM "$nettrap_pid"
wait "$nettrap_pid"
nettrap_pid=""

for family in ip ip6; do
    if nft list tables "$family" 2>/dev/null | grep -Eq "^table ${family} nettrap_[0-9]+$"; then
        echo "FAIL: NetTrap nftables table survived graceful shutdown (${family})" >&2
        exit 1
    fi
done
if iptables -t nat -S NETTRAP_PREROUTING >/dev/null 2>&1 \
    || ip6tables -t nat -S NETTRAP_PREROUTING >/dev/null 2>&1; then
    echo "FAIL: NetTrap iptables chain survived graceful shutdown" >&2
    exit 1
fi

echo "PASS: namespace traffic was redirected, crash-recovered, emulated, and cleaned up"
