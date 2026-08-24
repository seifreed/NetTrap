#!/bin/bash
set -euo pipefail

echo "========================================"
echo "NetTrap Complete Test Suite"
echo "========================================"
echo ""

FAILED=0
PASSED=0

cleanup() {
    if [ -n "${NETTRAP_PID:-}" ]; then
        kill "$NETTRAP_PID" 2>/dev/null || true
        wait "$NETTRAP_PID" 2>/dev/null || true
    fi
    rm -f /tmp/test_output.txt
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

echo "Starting NetTrap engine..."
timeout 120 nettrap run -c /etc/nettrap/config.toml &
NETTRAP_PID=$!
sleep 3

echo "Waiting for services..."
for port in 5353 8080 110 143 1389 1883 2222 2323 6379; do
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

echo "--- SSH/Telnet Listener Tests ---"

run_test "SSH port open" \
    "nc -z 127.0.0.1 2222"

run_test "Telnet port open" \
    "nc -z 127.0.0.1 2323"

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
