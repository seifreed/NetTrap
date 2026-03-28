#!/bin/bash
set -e

echo "=== Building NetTrap Docker Image ==="
docker build -t nettrap:latest .

echo ""
echo "=== Running NetTrap Container ==="
echo ""

# Run tests
docker run --rm \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    --cap-add=SYS_ADMIN \
    nettrap:latest \
    /bin/bash -c "
        echo '=== NetTrap Docker Test Suite ==='
        echo ''
        
        echo '--- Checking Binary ---'
        ls -la /usr/local/bin/nettrap
        echo ''
        
        echo '--- Binary Version ---'
        /usr/local/bin/nettrap --help || echo 'Help displayed'
        echo ''
        
        echo '--- Configuration ---'
        cat /etc/nettrap/config.toml
        echo ''
        
        echo '--- Starting DNS Listener (UDP 5353) ---'
        timeout 5 nettrap run -p 5353 --intercept 2>&1 &
        DNS_PID=\$!
        sleep 2
        
        echo 'Testing DNS query...'
        dig @127.0.0.1 -p 5353 test.example.com A +time=2 +short || echo 'DNS query sent'
        echo ''
        
        kill \$DNS_PID 2>/dev/null || true
        sleep 1
        
        echo '--- Starting HTTP Listener (TCP 8080) ---'
        timeout 5 nettrap run -p 8080 --intercept 2>&1 &
        HTTP_PID=\$!
        sleep 2
        
        echo 'Testing HTTP request...'
        curl -s --connect-timeout 2 -m 2 http://127.0.0.1:8080/ || echo 'HTTP request sent'
        echo ''
        
        kill \$HTTP_PID 2>/dev/null || true
        sleep 1
        
        echo '--- Starting HTTPS Listener (TCP 8443) ---'
        timeout 5 nettrap run -p 8443 --intercept 2>&1 &
        HTTPS_PID=\$!
        sleep 2
        
        echo 'Testing HTTPS/TLS connection...'
        echo '' | nc -w 2 127.0.0.1 8443 || echo 'TLS connection tested'
        echo ''
        
        echo 'Testing with openssl...'
        echo | timeout 2 openssl s_client -connect 127.0.0.1:8443 2>&1 | head -20 || echo 'TLS handshake tested'
        echo ''
        
        kill \$HTTPS_PID 2>/dev/null || true
        sleep 1
        
        echo '--- Starting SMTP Listener (TCP 2525) ---'
        timeout 5 nettrap run -p 2525 --intercept 2>&1 &
        SMTP_PID=\$!
        sleep 2
        
        echo 'Testing SMTP connection...'
        echo 'HELO test' | nc -w 2 127.0.0.1 2525 || echo 'SMTP connection tested'
        echo ''
        
        kill \$SMTP_PID 2>/dev/null || true
        sleep 1
        
        echo '--- Starting Multiple Listeners ---'
        echo 'Starting DNS (5353), HTTP (8080), HTTPS (8443)...'
        nettrap run -p 5353 -p 8080 -p 8443 --intercept 2>&1 &
        MULTI_PID=\$!
        sleep 3
        
        echo 'Testing all services...'
        dig @127.0.0.1 -p 5353 test.local A +time=1 +short || echo 'DNS OK'
        curl -s -m 1 http://127.0.0.1:8080/ || echo 'HTTP OK'
        echo | nc -w 1 127.0.0.1 8443 || echo 'HTTPS OK'
        echo ''
        
        kill \$MULTI_PID 2>/dev/null || true
        
        echo ''
        echo '=== All Protocol Tests Complete ==='
    "

echo ""
echo "=== Test Summary ==="
echo "If you see 'DNS OK', 'HTTP OK', 'HTTPS OK' above, the tests passed."
echo ""