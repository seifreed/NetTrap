#!/bin/bash
set -euo pipefail

echo "========================================"
echo "NetTrap Complete Test Suite"
echo "========================================"
echo ""

FAILED=0
PASSED=0
TEST_CONFIG="$(mktemp /tmp/nettrap-integration.XXXXXX.toml)"
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

cleanup() {
    if [ -n "${NETTRAP_PID:-}" ]; then
        kill "$NETTRAP_PID" 2>/dev/null || true
        wait "$NETTRAP_PID" 2>/dev/null || true
    fi
    rm -f /tmp/test_output.txt "$TEST_CONFIG" "$SMTP_MESSAGE"
    rm -rf "$SMTP_DIR"
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

run_ntp_udp_probe() {
    local payload_hex
    payload_hex="1b$(printf '00%.0s' $(seq 1 47))"
    run_udp_hex_probe "$NTP_UDP_PORT" "$payload_hex" 1
}

sed '/^output_format =/a smtp_dir = "/tmp/nettrap-integration-smtp"' \
    /etc/nettrap/config.toml >"$TEST_CONFIG"
cat >>"$TEST_CONFIG" <<'EOF'

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
timeout 120 nettrap run -c "$TEST_CONFIG" &
NETTRAP_PID=$!
sleep 3

echo "Waiting for services..."
for port in 445 5353 8080 110 143 1389 1883 2222 2323 3306 5432 6379 12121 12525 18443 \
    "$IRC_PORT" "$FINGER_PORT" "$IDENT_PORT" "$DAYTIME_PORT" "$TIME_PORT" \
    "$CHARGEN_PORT" "$QUOTD_PORT" "$MEMCACHED_PORT" "$SOCKS_PORT"; do
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

run_test "DNS AAAA query" \
    "dig @127.0.0.1 -p 5353 example.com AAAA +short"

run_test "DNS different domain" \
    "dig @127.0.0.1 -p 5353 test.example.org A +short | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'"

echo ""

echo "--- UDP Protocol Tests ---"

run_test "TFTP RRQ" \
    "run_udp_hex_probe $TFTP_UDP_PORT 0001736d6f6b652e747874006f6374657400 1"

run_test "SNMP GET" \
    "run_udp_hex_probe $SNMP_UDP_PORT 302602010004067075626c6963a019020101020100020100300e300c06082b060102010101000500 1"

run_test "SIP OPTIONS" \
    "run_udp_hex_probe $SIP_UDP_PORT 4f5054494f4e53207369703a6d61747269782e74657374205349502f322e300d0a5669613a205349502f322e302f554450203132372e302e302e313a353036303b6272616e63683d7a39684734624b2d6d61747269780d0a46726f6d3a203c7369703a6d6174726978406d61747269782e746573743e3b7461673d6d61747269780d0a546f3a203c7369703a6d6174726978406d61747269782e746573743e0d0a43616c6c2d49443a206d61747269782d63616c6c0d0a435365713a2031204f5054494f4e530d0a436f6e74656e742d4c656e6774683a20300d0a0d0a 1"

run_test "NTP request" run_ntp_udp_probe

run_test "CoAP request" \
    "run_udp_hex_probe $COAP_UDP_PORT 41011234aa 1"

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
