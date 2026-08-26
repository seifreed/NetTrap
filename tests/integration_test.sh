#!/bin/bash
set -euo pipefail

echo "========================================"
echo "NetTrap Complete Test Suite"
echo "========================================"
echo ""

FAILED=0
PASSED=0
TEST_CONFIG="$(mktemp /tmp/nettrap-integration.XXXXXX.toml)"
ARTIFACT_DIR="$(mktemp -d /tmp/nettrap-integration-artifacts.XXXXXX)"
SMTP_DIR="/tmp/nettrap-integration-smtp"
SMTP_MESSAGE="/tmp/nettrap-integration-message.eml"
IRC_PORT=16667
FINGER_PORT=1079
IDENT_PORT=1113
DAYTIME_PORT=11013
TIME_PORT=10037
CHARGEN_PORT=11919
QUOTD_PORT=11717
MEMCACHED_PORT=11211
SOCKS_PORT=11080
TFTP_UDP_PORT=1069
SNMP_UDP_PORT=1161
SIP_UDP_PORT=15060
UPNP_UDP_PORT=11900
NTP_UDP_PORT=1123
COAP_UDP_PORT=15683
QUIC_UDP_PORT=14433
DAYTIME_UDP_PORT=11014
TIME_UDP_PORT=10038
CHARGEN_UDP_PORT=11920
QUOTD_UDP_PORT=11718
SYSLOG_UDP_PORT=1514
RAW_UDP_PORT=19099
DNS_TCP_PORT=5354
NKN_TCP_PORT=19090
RAW_TCP_PORT=19091
DUMMY_TCP_PORT=19092
UPNP_TCP_PORT=19093
RDP_TCP_PORT=13389
TLS_TCP_PORT=19444
SYSLOG_TCP_PORT=1515
INTEGRATION_TIMEOUT_SECONDS=300

cleanup() {
    if [ -n "${NETTRAP_PID:-}" ]; then
        kill "$NETTRAP_PID" 2>/dev/null || true
        wait "$NETTRAP_PID" 2>/dev/null || true
    fi
    rm -f /tmp/test_output.txt "$TEST_CONFIG" "$SMTP_MESSAGE"
    rm -rf "$SMTP_DIR" "$ARTIFACT_DIR"
}

trap cleanup EXIT

run_test() {
    local name=$1
    local cmd=$2
    
    echo -n "Testing $name... "
    if eval "$cmd" > /tmp/test_output.txt 2>&1; then
        echo "✓ PASSED"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo "✗ FAILED"
        cat /tmp/test_output.txt
        FAILED=$((FAILED + 1))
        return 1
    fi
}

run_bounded_http_burst() {
    for _ in $(seq 1 32); do
        test "$(curl --resolve example.test:8080:127.0.0.1 -s -o /dev/null \
            -w '%{http_code}' http://example.test:8080/)" = "200"
    done
}

run_concurrent_http_burst() {
    local output
    output="$(seq 1 64 | xargs -P 8 -I{} curl --resolve example.test:8080:127.0.0.1 \
        -s -o /dev/null -w '%{http_code}\n' http://example.test:8080/)"
    test "$(grep -c '^200$' <<< "$output")" -eq 64
}

run_connection_exhaustion_probe() {
    local -a pids=()
    for _ in $(seq 1 128); do
        (exec 3<>/dev/tcp/127.0.0.1/8080; sleep 2) &
        pids+=("$!")
    done
    sleep 1
    test "$(curl --resolve example.test:8080:127.0.0.1 -s -o /dev/null \
        -w '%{http_code}' http://example.test:8080/)" = "200"
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
}

run_imap_auth_probe() {
    local output status
    set +e
    output="$(curl --noproxy '*' --silent --show-error \
        --url imap://127.0.0.1:143/ --user malware:secret 2>&1)"
    status=$?
    set -e
    test "$status" -eq 67
    grep -F 'Access denied' <<< "$output"
}

run_mysql_handshake_probe() {
    local output status
    set +e
    output="$(mariadb --protocol TCP --connect-timeout=5 \
        -h 127.0.0.1 -P 3306 -u root -e 'SELECT 1' 2>&1)"
    status=$?
    set -e
    test "$status" -eq 1
    grep -Eq 'ERROR 2013|Lost connection to server during query' <<< "$output"
}

run_postgres_simple_query() {
    PGPASSWORD=secret psql --no-psqlrc \
        'postgresql://user:secret@127.0.0.1:5432/postgres?connect_timeout=5' \
        -Atqc 'SELECT 1' >/dev/null
}

run_smb_negotiate_probe() {
    local output status
    set +e
    output="$(timeout 8 smbclient -L //127.0.0.1 -N -p 445 2>&1)"
    status=$?
    set -e
    test "$status" -ne 0
    grep -Eiq 'protocol|NT_STATUS|failed|error' <<< "$output"
}

run_tls_handshake() {
    local output
    output="$(timeout 10 openssl s_client -connect 127.0.0.1:18443 \
        -servername example.test -showcerts </dev/null 2>&1 || true)"
    grep -Fq 'BEGIN CERTIFICATE' <<< "$output"
}

run_https_get() {
    test "$(curl --noproxy '*' --insecure --silent --show-error \
        --resolve example.test:18443:127.0.0.1 \
        --output /dev/null --write-out '%{http_code}' \
        https://example.test:18443/)" = "200"
}

run_smtp_delivery() {
    rm -rf "$SMTP_DIR"
    mkdir -p "$SMTP_DIR"
    printf 'Subject: NetTrap E2E\n\nclient delivery\n' >"$SMTP_MESSAGE"
    curl --noproxy '*' --silent --show-error --url smtp://127.0.0.1:12525 \
        --mail-from sender@example.test --mail-rcpt receiver@example.test \
        --upload-file "$SMTP_MESSAGE"
    find "$SMTP_DIR" -type f -name '*.eml' -print -quit | grep -q .
}

run_ftp_download() {
    test "$(curl --noproxy '*' --silent --show-error --user malware:secret \
        ftp://127.0.0.1:12121/readme.txt)" = "NetTrap default text file"
}

run_ssh_handshake() {
    local output
    output="$(ssh -vv -o BatchMode=yes -o ConnectTimeout=5 \
        -o ConnectionAttempts=1 -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -p 2222 127.0.0.1 \
        </dev/null 2>&1 || true)"
    grep -Fq 'Remote protocol version 2.0' <<< "$output"
}

run_telnet_banner() {
    local output
    output="$({ printf '\r\n'; sleep 1; } | timeout 5 nc 127.0.0.1 2323 2>/dev/null | tr -d '\r' || true)"
    grep -Fq 'login:' <<< "$output"
}

run_telnet_session() {
    python3 - <<'PY'
import socket

sock = socket.create_connection(("127.0.0.1", 2323), timeout=5)
sock.settimeout(5)

def recv_until(marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise SystemExit(f"telnet closed before {marker!r}")
        data += chunk
    return data

try:
    banner = recv_until(b" login: ")
    if b"nettrap.local login:" not in banner:
        raise SystemExit("telnet login banner missing hostname")
    sock.sendall(b"matrix\r\n")
    recv_until(b"Password: ")
    sock.sendall(b"secret\r\n")
    success = recv_until(b"# ")
    if b"Login successful." not in success:
        raise SystemExit("telnet authentication did not succeed")
    sock.sendall(b"id\r\n")
    response = recv_until(b"# ")
    if b"uid=0(root)" not in response:
        raise SystemExit("telnet shell command response was not returned")
finally:
    sock.close()
PY
}

run_irc_registration() {
    local output
    output="$({ printf 'NICK matrix\r\nUSER matrix 0 * :matrix\r\n'; sleep 1; } |
        timeout 5 nc 127.0.0.1 "$IRC_PORT" 2>/dev/null || true)"
    grep -Eq ' 001 matrix :' <<< "$output"
}

run_finger_query() {
    local output
    output="$(printf 'root\r\n' | timeout 5 nc 127.0.0.1 "$FINGER_PORT" 2>/dev/null || true)"
    grep -Fq 'Login: root' <<< "${output//$'\r'/}"
}

run_ident_query() {
    local output
    output="$(printf '40000 , 80\r\n' | timeout 5 nc 127.0.0.1 "$IDENT_PORT" 2>/dev/null || true)"
    grep -Fq 'USERID : UNIX : root' <<< "$output"
}

run_server_first_text() {
    local output
    output="$(timeout 2 nc 127.0.0.1 "$1" 2>/dev/null || true)"
    test -n "$output"
}

run_rfc868_time() {
    test "$(wc -c < <(timeout 2 nc 127.0.0.1 "$TIME_PORT" 2>/dev/null || true))" -ge 4
}

run_memcached_version() {
    local output
    output="$(printf 'version\r\n' | timeout 5 nc 127.0.0.1 "$MEMCACHED_PORT" 2>/dev/null || true)"
    grep -Fq 'VERSION 1.6.22' <<< "$output"
}

run_socks_handshake() {
    local response_path status
    response_path="$(mktemp /tmp/nettrap-socks.XXXXXX)"
    printf '\005\001\000' | timeout 5 nc 127.0.0.1 "$SOCKS_PORT" >"$response_path" 2>/dev/null || true
    if od -An -t x1 "$response_path" | tr -d ' \n' | grep -Fq '0500'; then
        status=0
    else
        status=$?
    fi
    rm -f "$response_path"
    return "$status"
}

run_udp_hex_probe() {
    local port=$1
    local payload_hex=$2
    local minimum_bytes=$3
    if [[ "$port" == "$SIP_UDP_PORT" ]]; then
        run_sip_options
        return
    fi
    python3 - "$port" "$payload_hex" "$minimum_bytes" <<'PY'
import socket
import sys

port = int(sys.argv[1])
payload = bytes.fromhex(sys.argv[2])
minimum_bytes = int(sys.argv[3])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
try:
    sock.sendto(payload, ("127.0.0.1", port))
    response, _ = sock.recvfrom(65535)
    if len(response) < minimum_bytes:
        raise SystemExit(f"UDP response too short: {len(response)} < {minimum_bytes}")
finally:
    sock.close()
PY
}

run_udp_capture_probe() {
    local port=$1
    local payload_hex=$2
    python3 - "$port" "$payload_hex" <<'PY'
import socket
import sys

port = int(sys.argv[1])
payload = bytes.fromhex(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.sendto(payload, ("127.0.0.1", port))
finally:
    sock.close()
PY
}

run_udp_empty_probe() {
    run_udp_hex_probe "$1" "" "$2"
}

run_tftp_rrq() {
    python3 - "$TFTP_UDP_PORT" <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
try:
    sock.sendto(b"\x00\x01smoke.txt\x00octet\x00", ("127.0.0.1", int(sys.argv[1])))
    response, _ = sock.recvfrom(65535)
finally:
    sock.close()

if len(response) < 4 or int.from_bytes(response[:2], "big") not in (3, 5):
    raise SystemExit(f"invalid TFTP RRQ response: {response[:8].hex()}")
PY
}

run_snmp_get() {
    python3 - "$SNMP_UDP_PORT" <<'PY'
import socket
import sys

payload = bytes.fromhex(
    "302602010004067075626c6963a019020101020100020100300e300c"
    "06082b060102010101000500"
)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
try:
    sock.sendto(payload, ("127.0.0.1", int(sys.argv[1])))
    response, _ = sock.recvfrom(65535)
finally:
    sock.close()

if len(response) < 8 or response[0] != 0x30 or 0xA2 not in response:
    raise SystemExit(f"invalid SNMP GET response: {response[:16].hex()}")
PY
}

run_sip_options() {
    python3 - "$SIP_UDP_PORT" <<'PY'
import socket
import sys

payload = (
    b"OPTIONS sip:matrix.test SIP/2.0\r\n"
    b"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-matrix\r\n"
    b"From: <sip:matrix@matrix.test>;tag=matrix\r\n"
    b"To: <sip:matrix@matrix.test>\r\n"
    b"Call-ID: matrix-call\r\n"
    b"CSeq: 1 OPTIONS\r\n"
    b"Content-Length: 0\r\n\r\n"
)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
try:
    sock.sendto(payload, ("127.0.0.1", int(sys.argv[1])))
    response, _ = sock.recvfrom(65535)
finally:
    sock.close()

if not response.startswith(b"SIP/2.0 200 OK"):
    raise SystemExit(f"invalid SIP OPTIONS response: {response[:80]!r}")
PY
}

run_ntp_semantic_probe() {
    python3 - "$NTP_UDP_PORT" <<'PY'
import socket
import sys

request = bytes([0x1B]) + bytes(47)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
try:
    sock.sendto(request, ("127.0.0.1", int(sys.argv[1])))
    response, _ = sock.recvfrom(65535)
finally:
    sock.close()

if len(response) < 48 or (response[0] & 0x07) != 4 or ((response[0] >> 3) & 0x07) != 3:
    raise SystemExit(f"invalid NTP server response: {response[:8].hex()}")
PY
}

run_coap_get() {
    python3 - "$COAP_UDP_PORT" <<'PY'
import socket
import sys

request = bytes.fromhex("41011234aa")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
try:
    sock.sendto(request, ("127.0.0.1", int(sys.argv[1])))
    response, _ = sock.recvfrom(65535)
finally:
    sock.close()

if len(response) < 4 or (response[0] >> 6) != 1 or response[1] < 0x40:
    raise SystemExit(f"invalid CoAP response: {response[:16].hex()}")
if response[2:4] != request[2:4] or response[4] != request[4]:
    raise SystemExit("CoAP response did not preserve message ID and token")
PY
}

run_nkn_jsonrpc() {
    python3 - "$NKN_TCP_PORT" <<'PY'
import json
import socket
import sys

payload = b'{"jsonrpc":"2.0","method":"getnodestate","id":7}'
sock = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=3)
sock.settimeout(3)
try:
    sock.sendall(payload)
    response = json.loads(sock.recv(4096))
finally:
    sock.close()
if response.get("jsonrpc") != "2.0" or response.get("id") != 7:
    raise SystemExit(f"unexpected NKN JSON-RPC response: {response!r}")
PY
}

run_rdp_negotiation() {
    local output
    output="$(printf '\003\000\000\023\016\340\000\000\000\000\000\001\000\010\000\003\000\000\000' |
        timeout 5 nc 127.0.0.1 "$RDP_TCP_PORT" 2>/dev/null | od -An -t x1 || true)"
    test -n "$output"
}

run_upnp_tcp_description() {
    local output
    output="$(printf 'GET /desc.xml HTTP/1.1\r\nHost: matrix.test\r\nConnection: close\r\n\r\n' |
        timeout 5 nc 127.0.0.1 "$UPNP_TCP_PORT" 2>/dev/null || true)"
    grep -Fq 'HTTP/1.1 200' <<< "$output"
}

run_raw_tcp_echo() {
    local output
    output="$(printf 'raw-e2e\n' | timeout 5 nc 127.0.0.1 "$RAW_TCP_PORT" 2>/dev/null || true)"
    grep -Fq 'raw-e2e' <<< "$output"
}

run_tcp_capture_probe() {
    local port=$1
    local payload_hex=$2
    python3 - "$port" "$payload_hex" <<'PY'
import socket
import sys

port = int(sys.argv[1])
payload = bytes.fromhex(sys.argv[2])
sock = socket.create_connection(("127.0.0.1", port), timeout=3)
try:
    sock.sendall(payload)
finally:
    sock.close()
PY
}

run_full_protocol_matrix() {
    local matrix_script
    matrix_script="$(dirname -- "$0")/protocol_matrix_smoke.sh"
    NETTRAP_MATRIX_REPEAT="${NETTRAP_E2E_MATRIX_REPEAT:-2}" \
        NETTRAP_BIN=nettrap "$matrix_script"
}

run_artifact_exports() {
    kill -TERM "$NETTRAP_PID" 2>/dev/null || true
    wait "$NETTRAP_PID" 2>/dev/null || true
    NETTRAP_PID=""

    local events="$ARTIFACT_DIR/events.jsonl"
    test -s "$events"
    test -s "$ARTIFACT_DIR/events.html"
    test -s "$ARTIFACT_DIR/events.toon"
    test -s "$ARTIFACT_DIR/events.sarif.json"
    test -s "$ARTIFACT_DIR/events.csv"
    test -s "$ARTIFACT_DIR/traffic.pcap"

    for format in json jsonl toon sarif csv; do
        nettrap report -i "$events" -o "$ARTIFACT_DIR/report.$format" --format "$format" >/dev/null
        test -s "$ARTIFACT_DIR/report.$format"
    done

    nettrap pcap -i "$ARTIFACT_DIR/traffic.pcap" -o "$ARTIFACT_DIR/replayed.jsonl" >/dev/null
    test -s "$ARTIFACT_DIR/replayed.jsonl"
}

sed 's/^output_format =.*/output_format = "toon"/; s/^pcap_enabled =.*/pcap_enabled = true/; /^output_format =/a output_path = "'"$ARTIFACT_DIR"'/events.jsonl"\npcap_path = "'"$ARTIFACT_DIR"'/traffic.pcap"\nsmtp_dir = "/tmp/nettrap-integration-smtp"' \
    /etc/nettrap/config.toml >"$TEST_CONFIG"
cat >>"$TEST_CONFIG" <<'EOF'

[[listeners]]
name = "dns-tcp"
protocol = "tcp"
port = 5354
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "https"
protocol = "tcp"
port = 18443
bind_address = "0.0.0.0"
enabled = true
emulate_response = true
use_ssl = true

[[listeners]]
name = "smtp"
protocol = "tcp"
port = 12525
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "ftp"
protocol = "tcp"
port = 12121
bind_address = "0.0.0.0"
enabled = true
emulate_response = true
pasv_ports = "30100-30105"
EOF

cat >>"$TEST_CONFIG" <<EOF

[[listeners]]
name = "irc"
protocol = "tcp"
port = $IRC_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "finger"
protocol = "tcp"
port = $FINGER_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "ident"
protocol = "tcp"
port = $IDENT_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "daytime"
protocol = "tcp"
port = $DAYTIME_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "time"
protocol = "tcp"
port = $TIME_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "chargen"
protocol = "tcp"
port = $CHARGEN_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "quotd"
protocol = "tcp"
port = $QUOTD_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "memcached"
protocol = "tcp"
port = $MEMCACHED_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "socks"
protocol = "tcp"
port = $SOCKS_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "nkn"
protocol = "tcp"
port = $NKN_TCP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "raw-tcp"
protocol = "tcp"
port = $RAW_TCP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "dummy-tcp"
protocol = "tcp"
port = $DUMMY_TCP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "upnp-tcp"
protocol = "tcp"
port = $UPNP_TCP_PORT
bind_address = "0.0.0.0"
server_name = "nettrap.local"
enabled = true
emulate_response = true

[[listeners]]
name = "rdp"
protocol = "tcp"
port = $RDP_TCP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "tls-tcp"
protocol = "tcp"
port = $TLS_TCP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "syslogrecv-tcp"
protocol = "tcp"
port = $SYSLOG_TCP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true
EOF

cat >>"$TEST_CONFIG" <<EOF

[[listeners]]
name = "tftp-udp"
protocol = "udp"
port = $TFTP_UDP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "snmp-udp"
protocol = "udp"
port = $SNMP_UDP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "sip-udp"
protocol = "udp"
port = $SIP_UDP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "upnp-udp"
protocol = "udp"
port = $UPNP_UDP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "ntp-udp"
protocol = "udp"
port = $NTP_UDP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "coap-udp"
protocol = "udp"
port = $COAP_UDP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "quic-udp"
protocol = "udp"
port = $QUIC_UDP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "daytime-udp"
protocol = "udp"
port = $DAYTIME_UDP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "time-udp"
protocol = "udp"
port = $TIME_UDP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "chargen-udp"
protocol = "udp"
port = $CHARGEN_UDP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "quotd-udp"
protocol = "udp"
port = $QUOTD_UDP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "syslogrecv-udp"
protocol = "udp"
port = $SYSLOG_UDP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "raw-udp"
protocol = "udp"
port = $RAW_UDP_PORT
bind_address = "0.0.0.0"
enabled = true
emulate_response = true
EOF

echo "Starting NetTrap engine..."
timeout "$INTEGRATION_TIMEOUT_SECONDS" nettrap run -c "$TEST_CONFIG" &
NETTRAP_PID=$!
sleep 3

echo "Waiting for services..."
for port in 445 5353 "$DNS_TCP_PORT" 8080 110 143 1389 1883 2222 2323 3306 5432 6379 12121 12525 18443 \
    "$IRC_PORT" "$FINGER_PORT" "$IDENT_PORT" "$DAYTIME_PORT" "$TIME_PORT" \
    "$CHARGEN_PORT" "$QUOTD_PORT" "$MEMCACHED_PORT" "$SOCKS_PORT" \
    "$NKN_TCP_PORT" "$RAW_TCP_PORT" "$DUMMY_TCP_PORT" "$UPNP_TCP_PORT" \
    "$RDP_TCP_PORT" "$TLS_TCP_PORT" "$SYSLOG_TCP_PORT"; do
    ready=false
    for _ in $(seq 1 40); do
        if if [ "$port" = 5353 ]; then
            dig @127.0.0.1 -p "$port" example.com A +short >/dev/null 2>&1
        else
            nc -z 127.0.0.1 "$port" 2>/dev/null
        fi; then
            ready=true
            break
        fi
        sleep 0.25
    done
    if [ "$ready" != true ]; then
        echo "Service on port $port did not become ready" >&2
        exit 1
    fi
done
echo "All services started"
echo ""

echo "--- DNS Protocol Tests ---"

run_test "DNS A query" \
    "dig @127.0.0.1 -p 5353 example.com A +short | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'"

run_test "DNS TCP A query" \
    "dig +tcp @127.0.0.1 -p $DNS_TCP_PORT example.com A +short | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'"

run_test "DNS AAAA query" \
    "dig @127.0.0.1 -p 5353 example.com AAAA +short"

run_test "DNS different domain" \
    "dig @127.0.0.1 -p 5353 test.example.org A +short | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'"

echo ""

echo "--- UDP Protocol Tests ---"

run_test "TFTP RRQ" run_tftp_rrq

run_test "SNMP GET" run_snmp_get

run_test "SIP OPTIONS" \
    "run_udp_hex_probe $SIP_UDP_PORT 4f5054494f4e53207369703a6d61747269782e74657374205349502f322e300d0a5669613a205349502f322e302f554450203132372e302e302e313a353036303b6272616e63683d7a39684734624b2d6d61747269780d0a46726f6d3a203c7369703a6d6174726978406d61747269782e746573743e3b7461673d6d61747269780d0a546f3a203c7369703a6d6174726978406d61747269782e746573743e0d0a43616c6c2d49443a206d61747269782d63616c6c0d0a435365713a2031204f5054494f4e530d0a436f6e74656e742d4c656e6774683a20300d0a0d0a 1"

run_test "NTP request" run_ntp_semantic_probe

run_test "CoAP request" run_coap_get

run_test "Daytime UDP response" "run_udp_empty_probe $DAYTIME_UDP_PORT 1"

run_test "RFC 868 UDP response" "run_udp_empty_probe $TIME_UDP_PORT 4"

run_test "Chargen UDP response" "run_udp_empty_probe $CHARGEN_UDP_PORT 0"

run_test "QOTD UDP response" "run_udp_empty_probe $QUOTD_UDP_PORT 1"

run_test "UPnP SSDP capture" \
    "run_udp_capture_probe $UPNP_UDP_PORT 4d2d534541524348202a20485454502f312e310d0a484f53543a203233392e3235352e3235352e3235303a313930300d0a4d414e3a2022737364703a646973636f766572220d0a4d583a20310d0a53543a20737364703a616c6c0d0a0d0a"

run_test "Syslog UDP capture" \
    "run_udp_capture_probe $SYSLOG_UDP_PORT 3c33343e3120323032362d30312d30315430303a30303a30305a20686f73742061707020312049443437202d20736d6f6b65"

run_test "QUIC capture" \
    "run_udp_capture_probe $QUIC_UDP_PORT c000000001080000000000000000000000000000000000000000"

run_test "Raw UDP response" \
    "run_udp_hex_probe $RAW_UDP_PORT 70726f62650a 1"

echo ""

echo "--- HTTP Protocol Tests ---"

run_test "HTTP GET" \
    "curl --resolve example.test:8080:127.0.0.1 -s -o /dev/null -w '%{http_code}' http://example.test:8080/ | grep '200'"

run_test "HTTP POST" \
    "curl --resolve example.test:8080:127.0.0.1 -s -o /dev/null -w '%{http_code}' -X POST -d 'data=test' http://example.test:8080/ | grep '200'"

run_test "HTTP HEADERS" \
    "curl --resolve example.test:8080:127.0.0.1 -s -I http://example.test:8080/ | grep -i 'content-type'"

run_test "HTTP bounded burst" run_bounded_http_burst
run_test "HTTP concurrent burst" run_concurrent_http_burst
run_test "HTTP connection exhaustion" run_connection_exhaustion_probe

echo ""

echo "--- TLS/HTTPS Protocol Tests ---"

run_test "TLS certificate handshake" run_tls_handshake

run_test "HTTPS GET" run_https_get

echo ""

echo "--- SMTP/FTP Protocol Tests ---"

run_test "SMTP client delivery" run_smtp_delivery

run_test "FTP client download" run_ftp_download

echo ""

echo "--- LDAP Protocol Tests ---"

run_test "LDAP bind and search" \
    "ldapsearch -x -LLL -H ldap://127.0.0.1:1389 -b dc=nettrap,dc=local -s base '(objectClass=*)'"

echo ""

echo "--- Mail Protocol Tests ---"

run_test "POP3 capability" \
    "curl --noproxy '*' --silent --show-error --url pop3://127.0.0.1:110/ --user malware:secret | tr -d '\\r' | grep -E '^[0-9]+ [0-9]+$'"

run_test "IMAP capability" \
    run_imap_auth_probe

echo ""

echo "--- Message Broker Tests ---"

run_test "MQTT publish" \
    "mosquitto_pub -h 127.0.0.1 -p 1883 -i nettrap-integration -t nettrap/test -m smoke"

run_test "Redis PING" \
    "redis-cli -h 127.0.0.1 -p 6379 --raw PING | grep -Fx PONG"

run_test "Memcached version" run_memcached_version

run_test "SOCKS5 handshake" run_socks_handshake

run_test "NKN JSON-RPC request" run_nkn_jsonrpc

run_test "Raw TCP echo" run_raw_tcp_echo

run_test "RDP negotiation" run_rdp_negotiation

run_test "UPnP TCP description" run_upnp_tcp_description

run_test "TLS TCP capture" \
    "run_tcp_capture_probe $TLS_TCP_PORT 160301000401000000"

run_test "Syslog TCP capture" \
    "run_tcp_capture_probe $SYSLOG_TCP_PORT 3c33343e3120323032362d30312d30315430303a30303a30305a20686f73742061707020312049443437202d20736d6f6b65"

run_test "Dummy TCP capture" \
    "run_tcp_capture_probe $DUMMY_TCP_PORT 70726f62650a"

echo ""

echo "--- Legacy TCP Service Tests ---"

run_test "IRC registration" run_irc_registration

run_test "Finger query" run_finger_query

run_test "Ident query" run_ident_query

run_test "Daytime response" "run_server_first_text $DAYTIME_PORT"

run_test "RFC 868 time response" run_rfc868_time

run_test "Chargen response" "run_server_first_text $CHARGEN_PORT"

run_test "QOTD response" "run_server_first_text $QUOTD_PORT"

echo ""

echo "--- Database Client Tests ---"

run_test "MySQL client handshake" run_mysql_handshake_probe

run_test "PostgreSQL simple query" run_postgres_simple_query

run_test "SMB client negotiation" run_smb_negotiate_probe

echo ""

echo "--- SSH/Telnet Listener Tests ---"

run_test "SSH port open" \
    "nc -z 127.0.0.1 2222"

run_test "SSH client handshake" run_ssh_handshake

run_test "Telnet port open" \
    "nc -z 127.0.0.1 2323"

run_test "Telnet login banner" run_telnet_banner

run_test "Telnet authenticated shell session" run_telnet_session

echo ""
echo "--- Complete Protocol Matrix ---"

run_test "All protocol handlers hostile matrix" run_full_protocol_matrix

echo "--- Artifact Output Tests ---"
run_test "Report and PCAP artifact exports" run_artifact_exports

echo ""

echo ""
echo "========================================"
echo "Final Results"
echo "========================================"
echo "PASSED: $PASSED"
echo "FAILED: $FAILED"
echo "TOTAL:  $((PASSED + FAILED))"
echo "========================================"

if [ $FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi
