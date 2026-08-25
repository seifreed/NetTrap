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

write_tcp_probe() {
    local name=$1
    local path=$2
    case "$name" in
        dns) printf '%b' '\x00\x1d\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' >"$path" ;;
        http) printf 'GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n' >"$path" ;;
        smtp) printf 'EHLO matrix.test\r\nQUIT\r\n' >"$path" ;;
        ftp) printf 'SYST\r\nQUIT\r\n' >"$path" ;;
        pop3) printf 'CAPA\r\nQUIT\r\n' >"$path" ;;
        imap) printf 'a001 CAPABILITY\r\na002 LOGOUT\r\n' >"$path" ;;
        irc) printf 'NICK matrix\r\nUSER matrix 0 * :matrix\r\n' >"$path" ;;
        telnet) printf '%b' '\xff\xfb\x01\xff\xfb\x03' >"$path" ;;
        finger) printf '\r\n' >"$path" ;;
        ident) printf '40000 , 80\r\n' >"$path" ;;
        daytime|time|chargen|quotd) printf '\r\n' >"$path" ;;
        syslogrecv) printf '<34>1 2026-01-01T00:00:00Z host app 1 ID47 - smoke\n' >"$path" ;;
        dummy|smb|raw) printf 'probe\r\n' >"$path" ;;
        ssh|mysql) : >"$path" ;;
        rdp) printf '%b' '\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00' >"$path" ;;
        redis) printf '*1\r\n$4\r\nPING\r\n' >"$path" ;;
        ldap) printf '%b' '\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00' >"$path" ;;
        socks) printf '%b' '\x05\x01\x00' >"$path" ;;
        memcached) printf 'version\r\n' >"$path" ;;
        mqtt) printf '%b' '\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00' >"$path" ;;
        tls) printf '%b' '\x16\x03\x01\x00\x00' >"$path" ;;
        upnp) printf 'GET /desc.xml HTTP/1.1\r\nHost: matrix.test\r\nConnection: close\r\n\r\n' >"$path" ;;
        nkn) printf '{}\n' >"$path" ;;
        postgres) printf '%b' '\x00\x00\x00\x08\x00\x03\x00\x00' >"$path" ;;
        *) printf 'probe\r\n' >"$path" ;;
    esac
}

tcp_responses=0
udp_responses=0
for index in "${!tcp_ports[@]}"; do
    name=${tcp_names[$index]}
    request="$workdir/tcp-$name.request"
    response="$workdir/tcp-$name.response"
    write_tcp_probe "$name" "$request"
    timeout 2 nc 127.0.0.1 "${tcp_ports[$index]}" <"$request" >"$response" 2>/dev/null || true
    if ! kill -0 "$nettrap_pid" 2>/dev/null; then
        cat "$log" >&2
        echo "TCP handler crashed after $name probe" >&2
        exit 1
    fi
    case "$name" in
        dns|http|smtp|ftp|pop3|imap|ssh|redis|mysql|ldap|socks|memcached|mqtt|postgres)
            if [[ ! -s "$response" ]]; then
                echo "TCP handler returned no response for $name" >&2
                exit 1
            fi
            tcp_responses=$((tcp_responses + 1))
            ;;
    esac
done

for index in "${!udp_ports[@]}"; do
    name=${udp_names[$index]}
    request="$workdir/udp-$name.request"
    case "$name" in
        dns) printf '%b' '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' >"$request" ;;
        tftp) printf '%b' '\x00\x01smoke.txt\x00octet\x00' >"$request" ;;
        snmp) printf '%b' '\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00' >"$request" ;;
        sip) printf 'OPTIONS sip:matrix.test SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1\r\n\r\n' >"$request" ;;
        ntp) { printf '%b' '\x1b'; head -c 47 /dev/zero; } >"$request" ;;
        coap|quic|raw) printf 'probe\n' >"$request" ;;
        upnp) printf 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n' >"$request" ;;
        daytime|time|chargen|quotd|syslogrecv) printf '\n' >"$request" ;;
        *) printf 'probe\n' >"$request" ;;
    esac
    response="$workdir/udp-$name.response"
    nc -u -w 1 127.0.0.1 "${udp_ports[$index]}" <"$request" >"$response" 2>/dev/null || true
    case "$name" in
        dns|tftp|ntp)
            if [[ ! -s "$response" ]]; then
                echo "UDP handler returned no response for $name" >&2
                exit 1
            fi
            udp_responses=$((udp_responses + 1))
            ;;
    esac
done

if ! kill -0 "$nettrap_pid" 2>/dev/null; then
    cat "$log" >&2
    exit 1
fi

echo "PASS: protocol matrix smoke exercised ${#tcp_names[@]} TCP and ${#udp_names[@]} UDP handlers (${tcp_responses} TCP, ${udp_responses} UDP responses)"
