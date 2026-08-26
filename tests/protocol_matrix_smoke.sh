#!/usr/bin/env bash

set -euo pipefail

binary="${NETTRAP_BIN:-nettrap}"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
manifest="$script_dir/protocol_matrix_manifest.txt"
workdir="$(mktemp -d)"
config="$workdir/config.toml"
log="$workdir/nettrap.log"
nettrap_pid=""
repeat="${NETTRAP_MATRIX_REPEAT:-1}"
duration="${NETTRAP_MATRIX_DURATION_SECONDS:-0}"
tcp_probe_timeout_seconds=5

if [[ ! -r "$manifest" ]]; then
    echo "protocol matrix manifest is missing: $manifest" >&2
    exit 1
fi
tcp_names=()
udp_names=()
tcp_capture_only=()
udp_capture_only=()
while IFS= read -r name; do
    [[ -n "$name" ]] && tcp_names+=("$name")
done < <(awk '$1 == "tcp" {print $2}' "$manifest")
while IFS= read -r name; do
    [[ -n "$name" ]] && udp_names+=("$name")
done < <(awk '$1 == "udp" {print $2}' "$manifest")
while IFS= read -r name; do
    [[ -n "$name" ]] && tcp_capture_only+=("$name")
done < <(awk '$1 == "tcp" && $3 == "capture" {print $2}' "$manifest")
while IFS= read -r name; do
    [[ -n "$name" ]] && udp_capture_only+=("$name")
done < <(awk '$1 == "udp" && $3 == "capture" {print $2}' "$manifest")
if (( ${#tcp_names[@]} != 30 || ${#udp_names[@]} != 14 )); then
    echo "protocol matrix manifest must define 30 TCP and 14 UDP handlers" >&2
    exit 1
fi

if [[ ! "$repeat" =~ ^[1-9][0-9]*$ ]] || (( repeat > 32 )); then
    echo "NETTRAP_MATRIX_REPEAT must be between 1 and 32" >&2
    exit 1
fi
if [[ ! "$duration" =~ ^[0-9]+$ ]] || (( duration > 1800 )); then
    echo "NETTRAP_MATRIX_DURATION_SECONDS must be between 0 and 1800" >&2
    exit 1
fi

contains_name() {
    local needle=$1
    shift
    local candidate
    for candidate in "$@"; do
        [[ "$candidate" == "$needle" ]] && return 0
    done
    return 1
}

cleanup() {
    if [[ -n "$nettrap_pid" ]] && kill -0 "$nettrap_pid" 2>/dev/null; then
        kill -TERM "$nettrap_pid" 2>/dev/null || true
        wait "$nettrap_pid" 2>/dev/null || true
    fi
    rm -rf "$workdir"
}

trap cleanup EXIT

cat >"$config" <<EOF
attribution_enabled = false
default_decision = "emulate"
pcap_enabled = false
output_format = "jsonl"
output_path = "$workdir/events.jsonl"
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
        telnet) printf '%b' '\xff\xfb\x01\xff\xfb\x03root\r\n' >"$path" ;;
        finger) printf 'root\r\n' >"$path" ;;
        ident) printf '40000 , 80\r\n' >"$path" ;;
        daytime) printf 'daytime\r\n' >"$path" ;;
        time) printf 'time\r\n' >"$path" ;;
        chargen) printf 'chargen\r\n' >"$path" ;;
        quotd) printf 'quote\r\n' >"$path" ;;
        syslogrecv) printf '<34>1 2026-01-01T00:00:00Z host app 1 ID47 - smoke\n' >"$path" ;;
        dummy|raw) printf 'probe\r\n' >"$path" ;;
        ssh) printf 'SSH-2.0-NetTrapMatrix_1.0\r\n' >"$path" ;;
        mysql) printf '%b' '\x04\x00\x00\x01\x00\x00\x00\x00' >"$path" ;;
        rdp) printf '%b' '\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00' >"$path" ;;
        smb) python3 - "$path" >"$path" <<'PY'
import struct
import sys

smb2 = bytearray(68)
smb2[:4] = b"\xfeSMB"
struct.pack_into("<H", smb2, 4, 64)
struct.pack_into("<Q", smb2, 24, 0x123456789ABCDEF0)
sys.stdout.buffer.write(b"\x00\x00\x00\x44" + smb2)
PY
            ;;
        redis) printf '*1\r\n$4\r\nPING\r\n' >"$path" ;;
        ldap) printf '%b' '\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00' >"$path" ;;
        socks) printf '%b' '\x05\x01\x00' >"$path" ;;
        memcached) printf 'version\r\n' >"$path" ;;
        mqtt) printf '%b' '\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00' >"$path" ;;
        tls) printf '%b' '\x16\x03\x01\x00\x04\x01\x00\x00\x00' >"$path" ;;
        upnp) printf 'GET /desc.xml HTTP/1.1\r\nHost: matrix.test\r\nConnection: close\r\n\r\n' >"$path" ;;
        nkn) printf '%s\n' '{"jsonrpc":"2.0","method":"getnodestate","id":7}' >"$path" ;;
        postgres) printf '%b' '\x00\x00\x00\x08\x00\x03\x00\x00' >"$path" ;;
        *) printf 'probe\r\n' >"$path" ;;
    esac
}

tcp_responses=0
udp_responses=0
tcp_observed_responses=()
udp_observed_responses=()
tcp_response_min=()
tcp_response_max=()
udp_response_min=()
udp_response_max=()
expected_event_listeners=("${tcp_names[@]}")
for name in "${udp_names[@]}"; do
    expected_event_listeners+=("$name-udp")
done
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
        if (( fd_count > fd_baseline + 256 )); then
            echo "TCP/UDP protocol matrix exceeded file-descriptor bound ($fd_count, baseline $fd_baseline)" >&2
            tail -40 "$log" >&2
            exit 1
        fi
    fi
    if [[ -n "$rss_baseline_kb" ]]; then
        rss_kb="$(awk '/^VmRSS:/ {print $2; exit}' "/proc/$nettrap_pid/status")"
        if [[ -n "$rss_kb" ]] && (( rss_kb > rss_baseline_kb + 131072 )); then
            echo "TCP/UDP protocol matrix exceeded RSS bound (${rss_kb}KB, baseline ${rss_baseline_kb}KB)" >&2
            tail -40 "$log" >&2
            exit 1
        fi
    fi
}

assert_event_coverage() {
    python3 - "$workdir/events.jsonl" "${expected_event_listeners[@]}" <<'PY'
import json
import sys
from pathlib import Path

event_path = Path(sys.argv[1])
expected = set(sys.argv[2:])
if not event_path.is_file():
    raise SystemExit(f"event log is missing: {event_path}")

seen = set()
for line_number, line in enumerate(event_path.read_text(encoding="utf-8").splitlines(), 1):
    try:
        event = json.loads(line)
    except json.JSONDecodeError as error:
        raise SystemExit(f"invalid event JSON on line {line_number}: {error}") from error
    listener = event.get("listener")
    event_name = event.get("event")
    handler_activity = "event_id" in event or (
        isinstance(event_name, str) and event_name not in {"connect", "policy_decision"}
    )
    if isinstance(listener, str) and handler_activity:
        seen.add(listener)

missing = sorted(expected - seen)
if missing:
    raise SystemExit(f"event log is missing handler activity: {', '.join(missing)}")
PY
}

record_response_size() {
    local transport=$1
    local name=$2
    local size=$3
    local index
    if [[ "$transport" == tcp ]]; then
        for index in "${!tcp_names[@]}"; do
            if [[ "${tcp_names[$index]}" == "$name" ]]; then
                if [[ -z "${tcp_response_min[$index]+set}" ]]; then
                    tcp_response_min[$index]=$size
                    tcp_response_max[$index]=$size
                else
                    if (( size < tcp_response_min[$index] )); then
                        tcp_response_min[$index]=$size
                    fi
                    if (( size > tcp_response_max[$index] )); then
                        tcp_response_max[$index]=$size
                    fi
                fi
                return
            fi
        done
    else
        for index in "${!udp_names[@]}"; do
            if [[ "${udp_names[$index]}" == "$name" ]]; then
                if [[ -z "${udp_response_min[$index]+set}" ]]; then
                    udp_response_min[$index]=$size
                    udp_response_max[$index]=$size
                else
                    if (( size < udp_response_min[$index] )); then
                        udp_response_min[$index]=$size
                    fi
                    if (( size > udp_response_max[$index] )); then
                        udp_response_max[$index]=$size
                    fi
                fi
                return
            fi
        done
    fi
}

assert_tcp_response() {
    local name=$1
    local response=$2
    python3 - "$name" "$response" <<'PY'
import json
import re
import sys
from pathlib import Path

name, path = sys.argv[1:]
data = Path(path).read_bytes()
if not data:
    raise SystemExit(f"{name} response is empty")
text = data.decode("ascii", errors="replace")

if name == "dns":
    length = int.from_bytes(data[:2], "big") if len(data) >= 2 else 0
    if len(data) < 14 or length < 12 or len(data) - 2 < length or not data[4] & 0x80:
        raise SystemExit("invalid DNS TCP response framing or QR bit")
elif name == "http" and not re.match(r"^HTTP/1\.[01] \d{3}", text):
    raise SystemExit("invalid HTTP response")
elif name == "upnp" and not re.match(r"^HTTP/1\.[01] 200", text):
    raise SystemExit("invalid UPnP response")
elif name == "smtp" and not re.match(r"^(220|250)", text):
    raise SystemExit("invalid SMTP response")
elif name == "ftp" and not re.match(r"^(220|215|200|221)", text):
    raise SystemExit("invalid FTP response")
elif name == "pop3" and not text.startswith("+OK"):
    raise SystemExit("invalid POP3 response")
elif name == "imap" and not re.match(r"^\* (OK|CAPABILITY)", text):
    raise SystemExit("invalid IMAP response")
elif name == "irc" and not re.search(r"\s001\s", text):
    raise SystemExit("invalid IRC response")
elif name == "finger" and "Login:" not in text:
    raise SystemExit("invalid finger response")
elif name == "ident" and "USERID" not in text:
    raise SystemExit("invalid ident response")
elif name == "daytime" and not re.search(r"\d{2}:\d{2}:\d{2}", text):
    raise SystemExit("invalid daytime response")
elif name == "time" and len(data) < 4:
    raise SystemExit("invalid RFC 868 response")
elif name == "ssh" and not text.startswith("SSH-2.0-"):
    raise SystemExit("invalid SSH response")
elif name == "redis" and not text.startswith("+PONG"):
    raise SystemExit("invalid Redis response")
elif name == "memcached" and not text.startswith("VERSION "):
    raise SystemExit("invalid Memcached response")
elif name == "socks" and (len(data) < 2 or data[0] != 5):
    raise SystemExit("invalid SOCKS response")
elif name == "ldap" and data[0] != 0x30:
    raise SystemExit("invalid LDAP response")
elif name == "mqtt" and data[0] != 0x20:
    raise SystemExit("invalid MQTT response")
elif name == "nkn":
    try:
        json.loads(text)
    except json.JSONDecodeError as error:
        raise SystemExit(f"invalid NKN JSON-RPC response: {error}") from error
elif name == "rdp":
    tpkt_length = int.from_bytes(data[2:4], "big") if len(data) >= 4 else 0
    if len(data) < 4 or data[0] != 3 or data[1] != 0 or tpkt_length < 4 or tpkt_length > len(data):
        raise SystemExit("invalid RDP response")
PY
}

assert_udp_response() {
    local name=$1
    local response=$2
    python3 - "$name" "$response" <<'PY'
import re
import sys
from pathlib import Path

name, path = sys.argv[1:]
data = Path(path).read_bytes()
if not data:
    raise SystemExit(f"{name} response is empty")
text = data.decode("ascii", errors="replace")
if name == "dns" and (len(data) < 12 or not data[2] & 0x80):
    raise SystemExit("invalid DNS response")
if name == "tftp" and (len(data) < 4 or int.from_bytes(data[:2], "big") not in {3, 5}):
    raise SystemExit("invalid TFTP response")
if name == "snmp" and (data[0] != 0x30 or 0xA2 not in data):
    raise SystemExit("invalid SNMP response")
if name == "sip" and not re.match(r"^SIP/2\.0 200", text):
    raise SystemExit("invalid SIP response")
if name == "ntp" and (len(data) < 48 or data[0] & 0x07 != 4):
    raise SystemExit("invalid NTP response")
if name == "coap" and (len(data) < 5 or data[0] >> 6 != 1 or data[1] < 0x40):
    raise SystemExit("invalid CoAP response")
if name == "daytime" and not re.search(r"\d{2}:\d{2}:\d{2}", text):
    raise SystemExit("invalid daytime response")
if name == "time" and len(data) < 4:
    raise SystemExit("invalid RFC 868 response")
if name in {"chargen", "quotd"} and len(data) < 1:
    raise SystemExit(f"invalid {name} response")
if name == "raw" and "probe" not in text:
    raise SystemExit("invalid raw UDP response")
PY
}

run_tcp_probe() {
    local mode=$1
    local port=$2
    local request=$3
    local response=${4:-}
    python3 - "$mode" "$port" "$request" "$response" <<'PY'
import socket
import sys
from pathlib import Path

mode = sys.argv[1]
port = int(sys.argv[2])
request = Path(sys.argv[3]).read_bytes()
with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
    sock.settimeout(5)
    sock.sendall(request)
    if mode == "send":
        sock.shutdown(socket.SHUT_WR)
        raise SystemExit(0)
    if mode == "dns":
        prefix = b""
        while len(prefix) < 2:
            chunk = sock.recv(2 - len(prefix))
            if not chunk:
                raise SystemExit("DNS TCP listener closed before its length prefix")
            prefix += chunk
        length = int.from_bytes(prefix, "big")
        body = b""
        while len(body) < length:
            chunk = sock.recv(length - len(body))
            if not chunk:
                raise SystemExit("DNS TCP listener closed before its complete response")
            body += chunk
        if length < 12 or not body[2] & 0x80:
            raise SystemExit("DNS TCP response has invalid framing or QR bit")
        Path(sys.argv[4]).write_bytes(prefix + body)
        raise SystemExit(0)
    sock.shutdown(socket.SHUT_WR)
    chunks = []
    total = 0
    first_chunk = True
    while True:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        total += len(chunk)
        if total > 16 * 1024 * 1024:
            raise SystemExit("TCP probe response exceeded 16 MiB")
        chunks.append(chunk)
        if first_chunk:
            sock.settimeout(0.25)
            first_chunk = False
    if not chunks:
        raise SystemExit("TCP listener returned no response")
    Path(sys.argv[4]).write_bytes(b"".join(chunks))
PY
}

run_tcp_malformed_burst() {
    python3 - "${tcp_ports[@]}" <<'PY'
import socket
import sys

payload = b"\xff" * 4096
for value in sys.argv[1:]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.25)
    try:
        sock.connect(("127.0.0.1", int(value)))
        sock.sendall(payload)
    except OSError:
        pass
    finally:
        sock.close()
PY
}

run_udp_malformed_burst() {
    python3 - "${udp_ports[@]}" <<'PY'
import socket
import sys

payload = b"\xff" * 4096
for value in sys.argv[1:]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, ("127.0.0.1", int(value)))
    except OSError:
        pass
    finally:
        sock.close()
PY
}

run_tftp_wrq() {
    local port=$1
    local filename=$2
    python3 - "$port" "$filename" <<'PY'
import socket
import sys

port = int(sys.argv[1])
filename = sys.argv[2].encode("ascii")
payload = b"matrix-tftp"
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(5)
    sock.sendto(b"\x00\x02" + filename + b"\x00octet\x00", ("127.0.0.1", port))
    response, peer = sock.recvfrom(516)
    if response != b"\x00\x04\x00\x00":
        raise SystemExit(f"invalid TFTP WRQ ACK: {response[:8].hex()}")
    sock.sendto(b"\x00\x03\x00\x01" + payload, peer)
    response, _ = sock.recvfrom(516)
    if response != b"\x00\x04\x00\x01":
        raise SystemExit(f"invalid TFTP DATA ACK: {response[:8].hex()}")
PY
}

run_socks_connect() {
    local port=$1
    python3 - "$port" <<'PY'
import socket
import sys

port = int(sys.argv[1])
host = b"example.test"
with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
    sock.sendall(b"\x05\x01\x00")
    method = sock.recv(2)
    if method != b"\x05\x00":
        raise SystemExit(f"invalid SOCKS5 method response: {method.hex()}")
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + b"\x00\x50")
    response = b""
    while len(response) < 10:
        chunk = sock.recv(10 - len(response))
        if not chunk:
            raise SystemExit("SOCKS5 CONNECT response was truncated")
        response += chunk
    if response[:4] != b"\x05\x00\x00\x01":
        raise SystemExit(f"invalid SOCKS5 CONNECT response: {response[:4].hex()}")
PY
}

run_memcached_set() {
    local port=$1
    python3 - "$port" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
    sock.sendall(b"set e2e 0 0 5\r\nhello\r\n")
    response = sock.recv(256)
    if not response.startswith(b"STORED\r\n"):
        raise SystemExit(f"invalid Memcached SET response: {response[:32]!r}")
PY
}

deadline=$((SECONDS + duration))
round=1
while (( round <= repeat || (duration > 0 && SECONDS < deadline) )); do
for index in "${!tcp_ports[@]}"; do
    name=${tcp_names[$index]}
    request="$workdir/tcp-$name.request"
    response="$workdir/tcp-$name.response"
    write_tcp_probe "$name" "$request"
    case "$name" in
        daytime|time|chargen|quotd)
            timeout "$tcp_probe_timeout_seconds" nc 127.0.0.1 "${tcp_ports[$index]}" >"$response" 2>/dev/null || true
            ;;
        dns)
            run_tcp_probe dns "${tcp_ports[$index]}" "$request" "$response" || true
            ;;
        http)
            run_tcp_probe stream "${tcp_ports[$index]}" "$request" "$response" || true
            ;;
        *)
            if contains_name "$name" "${tcp_capture_only[@]-}"; then
                run_tcp_probe send "${tcp_ports[$index]}" "$request" >/dev/null 2>&1 || true
            else
                run_tcp_probe stream "${tcp_ports[$index]}" "$request" "$response" || true
            fi
            ;;
    esac
    if ! kill -0 "$nettrap_pid" 2>/dev/null; then
        cat "$log" >&2
        echo "TCP handler crashed after $name probe" >&2
        exit 1
    fi
        if ! contains_name "$name" "${tcp_capture_only[@]}"; then
        if [[ ! -s "$response" ]]; then
            echo "TCP handler returned no response for $name (probe bytes=$(wc -c <"$request"), response bytes=$(wc -c <"$response"))" >&2
            tail -20 "$log" >&2
            exit 1
        fi
        assert_tcp_response "$name" "$response"
        tcp_responses=$((tcp_responses + 1))
        if ! contains_name "$name" "${tcp_observed_responses[@]-}"; then
            tcp_observed_responses+=("$name")
        fi
        record_response_size tcp "$name" "$(wc -c <"$response" | tr -d ' ')"
    else
        record_response_size tcp "$name" 0
    fi
    if [[ "$name" == socks ]] && ! contains_name "$name" "${tcp_capture_only[@]}"; then
        run_socks_connect "${tcp_ports[$index]}"
    fi
    if [[ "$name" == memcached ]] && ! contains_name "$name" "${tcp_capture_only[@]}"; then
        run_memcached_set "${tcp_ports[$index]}"
    fi
done

for index in "${!udp_ports[@]}"; do
    name=${udp_names[$index]}
    request="$workdir/udp-$name.request"
    case "$name" in
        dns) printf '%b' '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' >"$request" ;;
        tftp) printf '%b' '\x00\x01smoke.txt\x00octet\x00' >"$request" ;;
        snmp) printf '%b' '\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00' >"$request" ;;
        sip) printf 'OPTIONS sip:matrix.test SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-matrix\r\nFrom: <sip:matrix@matrix.test>;tag=matrix\r\nTo: <sip:matrix@matrix.test>\r\nCall-ID: matrix-call\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n' >"$request" ;;
        ntp) { printf '%b' '\x1b'; head -c 47 /dev/zero; } >"$request" ;;
        coap) printf '%b' '\x41\x01\x12\x34\xaa' >"$request" ;;
        quic) printf '%b' '\xc0\x00\x00\x00\x01\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' >"$request" ;;
        raw) printf 'probe\n' >"$request" ;;
        upnp) printf 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n' >"$request" ;;
        daytime|time|chargen|quotd|syslogrecv) printf '\n' >"$request" ;;
        *) printf 'probe\n' >"$request" ;;
    esac
    response="$workdir/udp-$name.response"
    nc -u -w 2 127.0.0.1 "${udp_ports[$index]}" <"$request" >"$response" 2>/dev/null || true
    if ! contains_name "$name" "${udp_capture_only[@]}"; then
        if [[ ! -s "$response" ]]; then
            echo "UDP handler returned no response for $name (probe bytes=$(wc -c <"$request"), response bytes=$(wc -c <"$response"))" >&2
            tail -20 "$log" >&2
            exit 1
        fi
        assert_udp_response "$name" "$response"
        udp_responses=$((udp_responses + 1))
        if ! contains_name "$name" "${udp_observed_responses[@]-}"; then
            udp_observed_responses+=("$name")
        fi
        record_response_size udp "$name" "$(wc -c <"$response" | tr -d ' ')"
    else
        record_response_size udp "$name" 0
    fi
    if [[ "$name" == tftp ]]; then
        run_tftp_wrq "${udp_ports[$index]}" "matrix-$round.bin"
    fi
done

    run_tcp_malformed_burst
    run_udp_malformed_burst

    malformed_http="$workdir/malformed-http-$round.request"
    {
        printf 'GET /'
        head -c 4096 /dev/zero | tr '\0' 'A'
        printf ' HTTP/1.1\r\nHost: matrix.test\r\n\r\n'
    } >"$malformed_http"
    timeout "$tcp_probe_timeout_seconds" nc -N 127.0.0.1 "${tcp_ports[1]}" <"$malformed_http" >/dev/null 2>&1 || true
    printf '\xff\x00\xff\x00' | timeout 2 nc -u -w 1 127.0.0.1 "${udp_ports[0]}" >/dev/null 2>&1 || true
    assert_resource_bounds
    round=$((round + 1))
done
rounds_completed=$((round - 1))

if (( duration >= 60 && rounds_completed < 2 )); then
    echo "protocol matrix duration requested at least 60s but completed only $rounds_completed round(s)" >&2
    exit 1
fi

if ! kill -0 "$nettrap_pid" 2>/dev/null; then
    cat "$log" >&2
    exit 1
fi

for _ in $(seq 1 20); do
    if assert_event_coverage 2>/dev/null; then
        break
    fi
    sleep 0.1
done
assert_event_coverage

if [[ -n "${NETTRAP_MATRIX_REPORT:-}" ]]; then
    mkdir -p "$(dirname "$NETTRAP_MATRIX_REPORT")"
    tcp_malformed_probes=$(( ${#tcp_ports[@]} * rounds_completed ))
    udp_malformed_probes=$(( ${#udp_ports[@]} * rounds_completed ))
    {
        printf 'schema=5\n'
        printf 'rounds_completed=%s\n' "$rounds_completed"
        printf 'tcp_handlers=%s\n' "${#tcp_names[@]}"
        printf 'udp_handlers=%s\n' "${#udp_names[@]}"
        printf 'tcp_responses=%s\n' "$tcp_responses"
        printf 'udp_responses=%s\n' "$udp_responses"
        printf 'tcp_observed_responses=%s\n' "$(IFS=,; echo "${tcp_observed_responses[*]}")"
        printf 'udp_observed_responses=%s\n' "$(IFS=,; echo "${udp_observed_responses[*]}")"
        tcp_sizes=()
        for index in "${!tcp_names[@]}"; do
            tcp_sizes+=("${tcp_names[$index]}:${tcp_response_min[$index]}-${tcp_response_max[$index]}")
        done
        udp_sizes=()
        for index in "${!udp_names[@]}"; do
            udp_sizes+=("${udp_names[$index]}:${udp_response_min[$index]}-${udp_response_max[$index]}")
        done
        printf 'tcp_response_sizes=%s\n' "$(IFS=,; echo "${tcp_sizes[*]}")"
        printf 'udp_response_sizes=%s\n' "$(IFS=,; echo "${udp_sizes[*]}")"
        printf 'tcp_malformed_probes=%s\n' "$tcp_malformed_probes"
        printf 'udp_malformed_probes=%s\n' "$udp_malformed_probes"
        printf 'tcp_names=%s\n' "$(IFS=,; echo "${tcp_names[*]}")"
        printf 'udp_names=%s\n' "$(IFS=,; echo "${udp_names[*]}")"
        printf 'tcp_capture_only=%s\n' "$(IFS=,; echo "${tcp_capture_only[*]}")"
        printf 'udp_capture_only=%s\n' "$(IFS=,; echo "${udp_capture_only[*]}")"
        printf 'event_listeners=%s\n' "$(IFS=,; echo "${expected_event_listeners[*]}")"
    } >"$NETTRAP_MATRIX_REPORT"
fi

echo "PASS: protocol matrix smoke exercised ${#tcp_names[@]} TCP and ${#udp_names[@]} UDP handlers for ${rounds_completed} round(s) (${tcp_responses} TCP, ${udp_responses} UDP responses)"
