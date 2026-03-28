# Build stage
FROM rust:1.88-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libpcap-dev \
    libnfnetlink-dev \
    libnetfilter-queue-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates

# Build release
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libnfnetlink0 \
    ca-certificates \
    curl \
    dnsutils \
    netcat-openbsd \
    procps \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /app/target/release/nettrap /usr/local/bin/

# Create config directory
RUN mkdir -p /etc/nettrap

# Create default config
COPY <<'EOF' /etc/nettrap/config.toml
attribution_enabled = true
attribution_timeout_ms = 5000
default_decision = "intercept"
pcap_enabled = false
output_format = "jsonl"

[[listeners]]
name = "dns"
protocol = "udp"
port = 5353
bind_address = "0.0.0.0"
enabled = true
emulate_response = true
response_delay_ms = 0

[[listeners]]
name = "http"
protocol = "tcp"
port = 8080
bind_address = "0.0.0.0"
enabled = true
emulate_response = true
response_delay_ms = 0

[[listeners]]
name = "https"
protocol = "tcp"
port = 8443
bind_address = "0.0.0.0"
enabled = true
emulate_response = true
response_delay_ms = 0

[[listeners]]
name = "smtp"
protocol = "tcp"
port = 2525
bind_address = "0.0.0.0"
enabled = true
emulate_response = true
response_delay_ms = 0

[[listeners]]
name = "ftp"
protocol = "tcp"
port = 2121
bind_address = "0.0.0.0"
enabled = true
emulate_response = true
response_delay_ms = 0
EOF

# Copy integration tests
COPY tests/integration_test.sh /app/integration_test.sh
RUN chmod +x /app/integration_test.sh

# Create run script
COPY <<'EOF' /app/run.sh
#!/bin/bash
set -e
echo "Starting NetTrap..."
exec nettrap run -c /etc/nettrap/config.toml
EOF
RUN chmod +x /app/run.sh

CMD ["nettrap", "--help"]