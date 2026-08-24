FROM rust:1.97.1-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libpcap-dev \
    libnfnetlink-dev \
    libnetfilter-queue-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libnfnetlink0 \
    ca-certificates \
    curl \
    dnsutils \
    ldap-utils \
    mosquitto-clients \
    netcat-openbsd \
    procps \
    redis-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 nettrap \
    && useradd --system --uid 10001 --gid nettrap --home-dir /app --shell /usr/sbin/nologin nettrap

COPY --from=builder /app/target/release/nettrap /usr/local/bin/

COPY defaultFiles /app/defaultFiles
COPY config/default.toml /etc/nettrap/config.toml
COPY tests/integration_test.sh /app/integration_test.sh

RUN mkdir -p /var/log/nettrap /var/lib/nettrap/pcap \
    && chown -R nettrap:nettrap /var/log/nettrap /var/lib/nettrap

EXPOSE 5353/udp 8080 110 143 1389 1883 2222 2323 6379 9090 9091

USER nettrap

ENTRYPOINT ["nettrap"]
CMD ["run", "-c", "/etc/nettrap/config.toml", "-o", "/var/log/nettrap/events.jsonl"]
