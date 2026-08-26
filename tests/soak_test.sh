#!/usr/bin/env bash

set -euo pipefail

duration="${NETTRAP_SOAK_SECONDS:-60}"
concurrency="${NETTRAP_SOAK_CONCURRENCY:-8}"
connection_churn="${NETTRAP_SOAK_CONNECTION_CHURN:-64}"
max_rss_growth_kb="${NETTRAP_SOAK_MAX_RSS_GROWTH_KB:-131072}"
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
if [[ ! "$max_rss_growth_kb" =~ ^[1-9][0-9]*$ ]]; then
    echo "NETTRAP_SOAK_MAX_RSS_GROWTH_KB must be a positive integer" >&2
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

[[listeners]]
name = "dns-tcp"
protocol = "tcp"
port = 18054
bind_address = "127.0.0.1"
enabled = true
emulate_response = true
EOF

malformed_http="$workdir/malformed-http.request"
{
    printf 'GET /'
    head -c 4096 /dev/zero | tr '\0' 'A'
    printf ' HTTP/1.1\r\nHost: soak.example.test\r\n\r\n'
} >"$malformed_http"
printf '\xff\xff' >"$workdir/malformed-dns-tcp.request"

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
if ! dig +tcp @127.0.0.1 -p 18054 soak.example.test A +short \
    | grep -Eq '^[0-9]+(\.[0-9]+){3}$'; then
    cat "$log" >&2
    exit 1
fi

fd_baseline=""
rss_baseline_kb=""
if [[ -d "/proc/$nettrap_pid/fd" ]]; then
    fd_baseline="$(find "/proc/$nettrap_pid/fd" -mindepth 1 -maxdepth 1 -type l | wc -l | tr -d ' ')"
    rss_baseline_kb="$(awk '/^VmRSS:/ {print $2; exit}' "/proc/$nettrap_pid/status")"
fi

assert_resource_bounds() {
    local fd_count rss_kb
    if [[ -n "$fd_baseline" ]]; then
        fd_count="$(find "/proc/$nettrap_pid/fd" -mindepth 1 -maxdepth 1 -type l | wc -l | tr -d ' ')"
        if (( fd_count > fd_baseline + connection_churn + concurrency + 32 )); then
            echo "FAIL: file descriptors grew beyond the soak bound ($fd_count, baseline $fd_baseline)" >&2
            cat "$log" >&2
            exit 1
        fi
    fi
    if [[ -n "$rss_baseline_kb" ]]; then
        rss_kb="$(awk '/^VmRSS:/ {print $2; exit}' "/proc/$nettrap_pid/status")"
        if [[ -n "$rss_kb" ]] && (( rss_kb > rss_baseline_kb + max_rss_growth_kb )); then
            echo "FAIL: resident memory grew beyond the soak bound (${rss_kb}KB, baseline ${rss_baseline_kb}KB)" >&2
            cat "$log" >&2
            exit 1
        fi
    fi
}

run_malformed_burst() {
    local -a hostile_pids=()
    for _ in $(seq 1 "$concurrency"); do
        (
            timeout 2 nc 127.0.0.1 18080 <"$malformed_http" >/dev/null 2>&1 || true
            printf '\xff\x00\xff\x00' | timeout 2 nc -u -w 1 127.0.0.1 18053 >/dev/null 2>&1 || true
            timeout 2 nc 127.0.0.1 18054 <"$workdir/malformed-dns-tcp.request" >/dev/null 2>&1 || true
        ) &
        hostile_pids+=("$!")
    done
    for pid in "${hostile_pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
}

deadline=$((SECONDS + duration))
http_requests=0
dns_requests=0
dns_tcp_requests=0
malformed_requests=0
while (( SECONDS < deadline )); do
    pids=()
    for _ in $(seq 1 "$concurrency"); do
        (
            curl --noproxy '*' --silent --fail --max-time 2 \
                --no-keepalive -H 'Host: soak.example.test' \
                http://127.0.0.1:18080/ >/dev/null
            dig @127.0.0.1 -p 18053 soak.example.test A +short \
                | grep -Eq '^[0-9]+(\.[0-9]+){3}$'
            dig +tcp @127.0.0.1 -p 18054 soak.example.test A +short \
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

    run_malformed_burst
    assert_resource_bounds

    http_requests=$((http_requests + concurrency + 1))
    dns_requests=$((dns_requests + concurrency))
    dns_tcp_requests=$((dns_tcp_requests + concurrency))
    malformed_requests=$((malformed_requests + concurrency * 3))
done

if ! kill -0 "$nettrap_pid" 2>/dev/null; then
    cat "$log" >&2
    exit 1
fi
assert_resource_bounds

echo "PASS: ${duration}s hostile soak completed (${http_requests} HTTP, ${dns_requests} DNS UDP, ${dns_tcp_requests} DNS TCP, ${malformed_requests} malformed requests, ${connection_churn}-connection churn)"
