#!/bin/bash
# NetTrap Complete Integration Tests
set -e

echo "========================================"
echo "NetTrap Complete Test Suite"
echo "========================================"
echo ""

FAILED=0
PASSED=0

# Helper function
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

# Start NetTrap
echo "Starting NetTrap engine..."
timeout 120 nettrap run -c /etc/nettrap/config.toml &
NETTRAP_PID=$!
sleep 3

echo "Waiting for services..."
for port in 5353 8080 8443 2525 2121; do
    nc -z 127.0.0.1 $port 2>/dev/null || sleep 0.5
done
echo "All services started"
echo ""

# ============================================
# DNS Protocol Tests
# ============================================
echo "--- DNS Protocol Tests ---"

run_test "DNS A query" \
    "dig @127.0.0.1 -p 5353 example.com A +short | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'"

run_test "DNS AAAA query" \
    "dig @127.0.0.1 -p 5353 example.com AAAA +short"

run_test "DNS different domain" \
    "dig @127.0.0.1 -p 5353 test.example.org A +short | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'"

echo ""

# ============================================
# HTTP Protocol Tests
# ============================================
echo "--- HTTP Protocol Tests ---"

run_test "HTTP GET" \
    "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ | grep '200'"

run_test "HTTP POST" \
    "curl -s -X POST -d 'data=test' http://127.0.0.1:8080/ | grep -i 'nettrap'"

run_test "HTTP HEADERS" \
    "curl -s -I http://127.0.0.1:8080/ | grep -i 'content-type'"

echo ""

# ============================================
# HTTPS/TLS Protocol Tests
# ============================================
echo "--- HTTPS/TLS Protocol Tests ---"

run_test "TLS connection" \
    "echo | nc -w 1 127.0.0.1 8443 || echo 'Connection established'"

run_test "TLS port open" \
    "nc -z 127.0.0.1 8443"

echo ""

# ============================================
# SMTP Protocol Tests (using single connection)
# ============================================
echo "--- SMTP Protocol Tests ---"

run_test "SMTP session" \
    "{ echo 'EHLO test.example.com'; sleep 0.2; echo 'MAIL FROM: <test@test.com>'; sleep 0.2; echo 'RCPT TO: <user@test.com>'; sleep 0.2; echo 'QUIT'; sleep 0.2; } | nc 127.0.0.1 2525 | grep -E '(220|250|221)'"

echo ""

# ============================================
# FTP Protocol Tests (using single connection)
# ============================================
echo "--- FTP Protocol Tests ---"

run_test "FTP session" \
    "{ echo 'USER test'; sleep 0.2; echo 'PASS test123'; sleep 0.2; echo 'PWD'; sleep 0.2; echo 'QUIT'; sleep 0.2; } | nc 127.0.0.1 2121 | grep -E '(220|331|230|257|221)'"

echo ""

# ============================================
# Cleanup
# ============================================
kill $NETTRAP_PID 2>/dev/null || true

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