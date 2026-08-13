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
    netcat-openbsd \
    procps \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/nettrap /usr/local/bin/

COPY defaultFiles /app/defaultFiles
COPY config/default.toml /etc/nettrap/config.toml
COPY tests/integration_test.sh /app/integration_test.sh

RUN mkdir -p /var/log/nettrap /var/lib/nettrap/pcap

EXPOSE 5353/udp 8080 8443 2525 2121 2222 2323 3306 6379 9090

ENTRYPOINT ["nettrap"]
CMD ["run", "-c", "/etc/nettrap/config.toml"]
