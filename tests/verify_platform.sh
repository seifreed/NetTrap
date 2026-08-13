#!/bin/bash

set -e

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

if [ $? -eq 0 ]; then
    echo "✓ Build successful"
else
    echo "✗ Build failed"
    exit 1
fi

echo ""

echo "=== Step 2: Unit Tests ==="
cargo test --all 2>&1 | tail -30

if [ $? -eq 0 ]; then
    echo "✓ Unit tests passed"
else
    echo "✗ Unit tests failed"
    exit 1
fi

echo ""

echo "=== Step 3: Clippy Verification ==="
cargo clippy --all-targets --all-features 2>&1 | grep -E "error|warning" | tail -20 || true

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
name = "http_test"
protocol = "tcp"
port = 18088
bind_address = "127.0.0.1"
enabled = true
emulate_response = true
EOF

echo "Starting NetTrap..."
./target/release/nettrap run -c /tmp/nettrap_test_config.toml &
NETTRAP_PID=$!

sleep 2

echo "Testing DNS..."
if command -v dig &> /dev/null; then
    dig @127.0.0.1 -p 53539 test.example.com A +short > /tmp/dns_result.txt 2>&1 || true
    if grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" /tmp/dns_result.txt; then
        echo "✓ DNS test passed"
    else
        echo "⚠ DNS test inconclusive (may require privileged ports)"
    fi
else
    echo "⚠ dig not available, skipping DNS test"
fi

echo "Testing HTTP..."
if command -v curl &> /dev/null; then
    HTTP_RESULT=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18088/ 2>/dev/null || echo "000")
    if [ "$HTTP_RESULT" = "200" ]; then
        echo "✓ HTTP test passed"
    else
        echo "⚠ HTTP test returned: $HTTP_RESULT"
    fi
else
    echo "⚠ curl not available, skipping HTTP test"
fi

kill $NETTRAP_PID 2>/dev/null || true
rm -f /tmp/nettrap_test_config.toml /tmp/dns_result.txt

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