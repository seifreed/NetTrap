#!/usr/bin/env bash

set -euo pipefail

binary="${NETTRAP_BIN:-nettrap}"
workdir="$(mktemp -d)"
config="$workdir/config.toml"
log="$workdir/nettrap.log"
nettrap_pid=""

tcp_names=(
    dns http smtp ftp pop3 imap irc telnet finger ident daytime time chargen
    quotd syslogrecv dummy ssh smb rdp redis mysql ldap socks memcached mqtt tls
    upnp nkn postgres raw
)
udp_names=(dns tftp snmp sip upnp ntp coap quic daytime time chargen quotd syslogrecv raw)

cleanup() {
    if [[ -n "$nettrap_pid" ]] && kill -0 "$nettrap_pid" 2>/dev/null; then
        kill -TERM "$nettrap_pid" 2>/dev/null || true
        wait "$nettrap_pid" 2>/dev/null || true
    fi
    rm -rf "$workdir"
}

trap cleanup EXIT

cat >"$config" <<'EOF'
attribution_enabled = false
default_decision = "emulate"
pcap_enabled = false
output_format = "jsonl"
EOF

tcp_ports=()
port=19000
for name in "${tcp_names[@]}"; do
    cat >>"$config" <<EOF

[[listeners]]
name = "$name"
protocol = "tcp"
port = $port
bind_address = "127.0.0.1"
enabled = true
emulate_response = true
EOF
    tcp_ports+=("$port")
    port=$((port + 1))
done

udp_ports=()
for name in "${udp_names[@]}"; do
    cat >>"$config" <<EOF

[[listeners]]
name = "$name-udp"
protocol = "udp"
port = $port
bind_address = "127.0.0.1"
enabled = true
emulate_response = true
EOF
    udp_ports+=("$port")
    port=$((port + 1))
done

"$binary" run -c "$config" >"$log" 2>&1 &
nettrap_pid=$!

for tcp_port in "${tcp_ports[@]}"; do
    ready=false
    for _ in $(seq 1 40); do
        if nc -z 127.0.0.1 "$tcp_port" 2>/dev/null; then
            ready=true
            break
        fi
        if ! kill -0 "$nettrap_pid" 2>/dev/null; then
            cat "$log" >&2
            exit 1
        fi
        sleep 0.25
    done
    if [[ "$ready" != true ]]; then
        cat "$log" >&2
        echo "TCP handler did not become ready on port $tcp_port" >&2
        exit 1
    fi
done

for index in "${!tcp_ports[@]}"; do
    printf 'probe\r\n' | timeout 2 nc 127.0.0.1 "${tcp_ports[$index]}" >/dev/null 2>&1 || true
done

for udp_port in "${udp_ports[@]}"; do
    printf 'probe\n' | nc -u -w 1 127.0.0.1 "$udp_port" >/dev/null 2>&1 || true
done

if ! kill -0 "$nettrap_pid" 2>/dev/null; then
    cat "$log" >&2
    exit 1
fi

echo "PASS: protocol matrix smoke exercised ${#tcp_names[@]} TCP and ${#udp_names[@]} UDP handlers"
