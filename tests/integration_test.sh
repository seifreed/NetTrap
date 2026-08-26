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

echo "Starting NetTrap engine..."
timeout 120 nettrap run -c "$TEST_CONFIG" &
NETTRAP_PID=$!
sleep 3

echo "Waiting for services..."
for port in 445 5353 8080 110 143 1389 1883 2222 2323 3306 5432 6379 12121 12525 18443; do
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
