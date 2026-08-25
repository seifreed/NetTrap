#!/usr/bin/env bash

set -euo pipefail

duration="${NETTRAP_SOAK_SECONDS:-60}"
concurrency="${NETTRAP_SOAK_CONCURRENCY:-8}"
connection_churn="${NETTRAP_SOAK_CONNECTION_CHURN:-64}"
binary="${NETTRAP_BIN:-./target/release/nettrap}"
workdir="$(mktemp -d)"
config="$workdir/config.toml"
log="$workdir/nettrap.log"
nettrap_pid=""

cleanup() {
    if [[ -n "$nettrap_pid" ]] && kill -0 "$nettrap_pid" 2>/dev/null; then
        kill -TERM "$nettrap_pid" 2>/dev/null || true
        wait "$nettrap_pid" 2>/dev/null || true
    fi
    rm -rf "$workdir"
}

trap cleanup EXIT

if [[ ! "$duration" =~ ^[1-9][0-9]*$ ]]; then
    echo "NETTRAP_SOAK_SECONDS must be a positive integer" >&2
    exit 1
fi
if [[ ! "$concurrency" =~ ^[1-9][0-9]*$ ]] || (( concurrency > 64 )); then
    echo "NETTRAP_SOAK_CONCURRENCY must be between 1 and 64" >&2
    exit 1
fi
if [[ ! "$connection_churn" =~ ^[1-9][0-9]*$ ]] || (( connection_churn > 256 )); then
    echo "NETTRAP_SOAK_CONNECTION_CHURN must be between 1 and 256" >&2
    exit 1
fi
if [[ ! -x "$binary" ]]; then
    echo "NetTrap binary is not executable: $binary" >&2
    exit 1
fi

cat >"$config" <<'EOF'
attribution_enabled = false
default_decision = "emulate"
pcap_enabled = false
output_format = "jsonl"

[[listeners]]
name = "soak-http"
protocol = "tcp"
port = 18080
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "soak-dns"
protocol = "udp"
port = 18053
bind_address = "127.0.0.1"
enabled = true
emulate_response = true
EOF

"$binary" run -c "$config" >"$log" 2>&1 &
nettrap_pid=$!

for _ in $(seq 1 40); do
    if curl --noproxy '*' --silent --fail --max-time 1 \
        -H 'Host: soak.example.test' http://127.0.0.1:18080/ >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$nettrap_pid" 2>/dev/null; then
        cat "$log" >&2
        exit 1
    fi
    sleep 0.25
done

if ! curl --noproxy '*' --silent --fail --max-time 1 \
    -H 'Host: soak.example.test' http://127.0.0.1:18080/ >/dev/null 2>&1; then
    cat "$log" >&2
    exit 1
fi

deadline=$((SECONDS + duration))
http_requests=0
dns_requests=0
while (( SECONDS < deadline )); do
    pids=()
    for _ in $(seq 1 "$concurrency"); do
        (
            curl --noproxy '*' --silent --fail --max-time 2 \
                --no-keepalive -H 'Host: soak.example.test' \
                http://127.0.0.1:18080/ >/dev/null
            dig @127.0.0.1 -p 18053 soak.example.test A +short \
                | grep -Eq '^[0-9]+(\.[0-9]+){3}$'
        ) &
        pids+=("$!")
    done
    for pid in "${pids[@]}"; do
        wait "$pid"
    done

    churn_pids=()
    for _ in $(seq 1 "$connection_churn"); do
        (
            exec 3<>/dev/tcp/127.0.0.1/18080
            sleep 0.2
            exec 3>&-
        ) &
        churn_pids+=("$!")
    done
    sleep 0.1
    curl --noproxy '*' --silent --fail --max-time 2 \
        -H 'Host: soak.example.test' http://127.0.0.1:18080/ >/dev/null
    for pid in "${churn_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    http_requests=$((http_requests + concurrency + 1))
    dns_requests=$((dns_requests + concurrency))
done

if ! kill -0 "$nettrap_pid" 2>/dev/null; then
    cat "$log" >&2
    exit 1
fi

echo "PASS: ${duration}s concurrent soak completed (${http_requests} HTTP, ${dns_requests} DNS requests, ${connection_churn}-connection churn)"
