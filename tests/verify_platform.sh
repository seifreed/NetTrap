#!/bin/bash

set -euo pipefail

cleanup() {
    if [ -n "${NETTRAP_PID:-}" ]; then
        kill "$NETTRAP_PID" 2>/dev/null || true
        wait "$NETTRAP_PID" 2>/dev/null || true
    fi
    rm -f /tmp/nettrap_test_config.toml /tmp/dns_result.txt /tmp/tls_result.txt
}

trap cleanup EXIT

echo "========================================"
echo "NetTrap Cross-Platform Verification"
echo "========================================"
echo ""

OS="$(uname -s)"
ARCH="$(uname -m)"

echo "Platform: $OS"
echo "Architecture: $ARCH"
echo ""

echo "=== Step 1: Build Verification ==="
echo "Building NetTrap for $OS $ARCH..."

cargo build --release 2>&1 | tail -10
echo "✓ Build successful"

echo ""

echo "=== Step 2: Unit Tests ==="
cargo test --all 2>&1 | tail -30
echo "✓ Unit tests passed"

echo ""

echo "=== Step 3: Clippy Verification ==="
cargo clippy --all-targets --all-features -- -D warnings

echo ""

echo "=== Step 4: Interceptor Availability Check ==="

case "$OS" in
    Linux*)
        echo "Checking NFQUEUE availability..."
        if pkg-config --exists libnetfilter_queue 2>/dev/null; then
            echo "✓ NFQUEUE library found"
        else
            echo "⚠ NFQUEUE library not found (PCAP fallback available)"
        fi
        
        echo "Checking PCAP availability..."
        if pkg-config --exists libpcap 2>/dev/null; then
            echo "✓ PCAP library found"
        else
            echo "✗ PCAP library not found"
            exit 1
        fi
        ;;
    
    Darwin*)
        echo "Checking PCAP availability..."
        if pkg-config --exists libpcap 2>/dev/null || [ -f /usr/lib/libpcap.dylib ]; then
            echo "✓ PCAP library found"
        else
            echo "⚠ PCAP library location may vary"
        fi
        ;;
    
    MINGW*|MSYS*|CYGWIN*)
        echo "Checking WinDivert availability..."
        if [ -f "windivert/WinDivert.dll" ]; then
            echo "✓ WinDivert DLL found"
        else
            echo "⚠ WinDivert DLL not found in windivert/ directory"
        fi
        ;;
    
    *)
        echo "⚠ Unknown platform: $OS"
        ;;
esac

echo ""

echo "=== Step 5: Protocol Handler Tests ==="

echo "Testing DNS handler..."
cargo test --package nettrap-proto-dns 2>&1 | grep -E "test result:|passed|failed" | tail -5

echo ""
echo "Testing SMTP handler..."
cargo test --package nettrap-proto-smtp 2>&1 | grep -E "test result:|passed|failed" | tail -5

echo ""
echo "Testing FTP handler..."
cargo test --package nettrap-proto-ftp 2>&1 | grep -E "test result:|passed|failed" | tail -5

echo ""

echo "=== Step 6: Integration Tests ==="

cat > /tmp/nettrap_test_config.toml << 'EOF'
attribution_enabled = false
default_decision = "intercept"
pcap_enabled = false
output_format = "jsonl"

[[listeners]]
name = "dns_test"
protocol = "udp"
port = 53539
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "dns-tcp-test"
protocol = "tcp"
port = 53539
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "http"
protocol = "tcp"
port = 18088
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "https"
protocol = "tcp"
port = 18443
bind_address = "127.0.0.1"
enabled = true
emulate_response = true
use_ssl = true
EOF

echo "Starting NetTrap..."
./target/release/nettrap run -c /tmp/nettrap_test_config.toml &
NETTRAP_PID=$!

sleep 2

echo "Testing DNS..."
if command -v dig &> /dev/null; then
    if dig @127.0.0.1 -p 53539 test.example.com A +short > /tmp/dns_result.txt 2>&1 \
        && grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" /tmp/dns_result.txt; then
        echo "✓ DNS test passed"
    else
        echo "✗ DNS test failed"
        exit 1
    fi
    if dig +tcp @127.0.0.1 -p 53539 test.example.com A +short > /tmp/dns_result.txt 2>&1 \
        && grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" /tmp/dns_result.txt; then
        echo "✓ DNS TCP test passed"
    else
        echo "✗ DNS TCP test failed"
        cat /tmp/dns_result.txt
        exit 1
    fi
else
    echo "✗ dig is required for the DNS integration test"
    exit 1
fi

echo "Testing TLS handshake..."
if command -v openssl &> /dev/null; then
    if printf '' | openssl s_client -connect 127.0.0.1:18443 -servername example.test \
        > /tmp/tls_result.txt 2>&1 \
        && grep -q "BEGIN CERTIFICATE" /tmp/tls_result.txt; then
        echo "✓ TLS handshake test passed"
    else
        echo "✗ TLS handshake test failed"
        exit 1
    fi
else
    echo "✗ openssl is required for the TLS integration test"
    exit 1
fi

echo "Testing HTTPS..."
HTTPS_RESULT=$(curl --noproxy '*' --insecure --silent --show-error --output /dev/null \
    --write-out "%{http_code}" --retry 5 --retry-connrefused --retry-delay 1 \
    --resolve example.test:18443:127.0.0.1 https://example.test:18443/)
if [ "$HTTPS_RESULT" = "200" ]; then
    echo "✓ HTTPS test passed"
else
    echo "✗ HTTPS test returned: $HTTPS_RESULT"
    exit 1
fi

echo "Testing HTTP..."
if command -v curl &> /dev/null; then
    HTTP_RESULT=$(curl --noproxy '*' --silent --show-error --output /dev/null \
        --write-out "%{http_code}" --retry 5 --retry-connrefused --retry-delay 1 \
        --header "Host: example.test" http://127.0.0.1:18088/)
    if [ "$HTTP_RESULT" = "200" ]; then
        echo "✓ HTTP test passed"
    else
        echo "✗ HTTP test returned: $HTTP_RESULT"
        exit 1
    fi
else
    echo "✗ curl is required for the HTTP integration test"
    exit 1
fi

echo ""

echo "========================================"
echo "Verification Summary"
echo "========================================"
echo "Platform:      $OS"
echo "Architecture:  $ARCH"
echo "Build:         ✓"
echo "Unit Tests:    ✓"
echo "Protocol Tests: ✓"
echo ""
echo "NetTrap is ready for $OS $ARCH"
echo "========================================"
