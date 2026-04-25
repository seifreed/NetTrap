<p align="center">
  <img src="https://img.shields.io/badge/NetTrap-Network%20Security-orange?style=for-the-badge" alt="NetTrap">
</p>

<h1 align="center">NetTrap</h1>

<p align="center">
  <strong>Network Interception, Emulation & Deception Engine</strong>
</p>

<p align="center">
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.85%2B-orange?style=flat-square&logo=rust&logoColor=white" alt="Rust Version"></a>
  <a href="https://github.com/seifreed/nettrap/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/nettrap/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/nettrap/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <img src="https://img.shields.io/badge/protocols-26-blue?style=flat-square" alt="Protocols">
  <img src="https://img.shields.io/badge/crates-50-blue?style=flat-square" alt="Crates">
</p>

<p align="center">
  <a href="https://github.com/seifreed/nettrap/stargazers"><img src="https://img.shields.io/github/stars/seifreed/nettrap?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/nettrap/issues"><img src="https://img.shields.io/github/issues/seifreed/nettrap?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**NetTrap** is a high-performance network interception and deception engine written in Rust. It emulates 26 network protocols to detect malicious activity, capture malware C2 communications, and create honeypots. Designed as a modern replacement for [FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng) with TLS MITM, distributed deployment, and multi-platform support.

### Why NetTrap?

- **26 protocol handlers** — from DNS/HTTP to Telnet/SSH/SMB/RDP/Redis/MQTT and more
- **TLS MITM with JA3/JA4** — decrypt HTTPS traffic and fingerprint malware TLS stacks
- **mkcert integration** — one command to install trusted CA for full SSL inspection
- **Distributed mode** — multi-node fleet with event shipping to Elasticsearch, Kafka, Splunk, Syslog
- **Database storage** — SQLite (standalone) or MariaDB/MySQL (distributed, Galera multi-master)
- **5 output formats** — JSONL, JSON, SARIF v2.1.0, TOON, CSV
- **Cross-platform** — Linux, macOS, Windows (x64, ARM64)
- **Async Rust** — built on Tokio, 50 modular crates

---

## Supported Protocols

### Tier 1 — Core Protocols

| Protocol | Port | Use Case |
|----------|------|----------|
| DNS | 53 | Domain resolution honeypot (A/AAAA/MX/TXT/NS/CNAME/SOA, NXDomains, NCSI) |
| HTTP/HTTPS | 80/443 | Web honeypot with TLS MITM, custom responses, webroot serving |
| SMTP | 25 | Email server (EHLO, MAIL, DATA, Exchange commands) |
| FTP | 21 | File server (30+ FTP commands, 90+ banner presets, PASV, file serving) |
| SSH | 22 | SSH brute-force capture (banner exchange, KEX emulation) |
| Telnet | 23 | IoT malware capture (Mirai-style shell, command logging) |
| POP3 | 110 | Email client honeypot (USER, PASS, STAT, LIST, RETR) |
| IRC | 6667 | Bot C2 capture (NICK, JOIN, PRIVMSG, MOTD) |
| TFTP | 69 | Firmware/payload capture (RRQ/WRQ, block transfer) |

### Tier 2 — Enterprise & Cloud

| Protocol | Port | Use Case |
|----------|------|----------|
| SMB | 445 | Ransomware lateral movement detection (SMB1/2/3, NTLM capture) |
| RDP | 3389 | Ransomware initial access (X.224, cookie/username extraction) |
| Redis | 6379 | Cloud exploitation (RESP protocol, CONFIG SET/SLAVEOF/MODULE detection) |
| MySQL | 3306 | Database honeypot (handshake, login capture, query logging) |
| LDAP | 389 | AD attacks & Log4Shell capture (Bind, Search, JNDI) |
| PostgreSQL | 5432 | Database exploitation (startup, query logging) |
| MQTT | 1883 | IoT C2 detection (CONNECT, PUBLISH, SUBSCRIBE) |
| SOCKS | 1080 | Proxy malware detection (SOCKS4/5 handshake, CONNECT logging) |
| Memcached | 11211 | DDoS amplification & data theft (text + binary protocol) |

### Tier 3 — Specialized

| Protocol | Port | Use Case |
|----------|------|----------|
| SNMP | 161 | Network recon (community string capture, GetRequest/SetRequest) |
| SIP | 5060 | VoIP fraud detection (REGISTER, INVITE) |
| UPnP/SSDP | 1900 | IoT discovery & port mapping (M-SEARCH, AddPortMapping) |
| NTP | 123 | Amplification detection (server response) |
| CoAP | 5683 | IoT constrained devices (ACK response) |
| NKN | 30001 | NKAbuse malware (JSON-RPC, P2P detection) |
| QUIC | 443 | HTTP/3 detection (long header, version detection) |
| Raw | any | Catch-all (echo, static, base64, file, silent modes) |

> Any protocol can run on any port. The taste-based protocol router auto-detects by content, not just port number.

---

## TLS MITM & SSL Inspection

NetTrap performs full TLS man-in-the-middle to decrypt HTTPS malware traffic:

- **Dynamic certificate generation** per SNI hostname
- **JA3 fingerprinting** — identify malware by TLS client fingerprint
- **JA4 fingerprinting** — next-gen TLS fingerprint (FoxIO spec)
- **mkcert integration** — trusted CA for system-wide SSL inspection

```bash
# Install mkcert (one time)
nettrap tls install-mkcert
nettrap tls install          # Install CA in system trust store

# Run — HTTPS traffic is now fully decrypted
nettrap run -c config.toml
```

**What you see in decrypted HTTPS:**
```
TLS FINGERPRINT:  JA3=a0a70c27edcfbed9c5dd17b4cc10d6c0  JA4=t13d4907_h2_...
DECRYPTED HTTPS:  POST /exfil/upload  Host: exfil.malware.io  Body: 163 bytes
DECRYPTED HTTPS:  GET /payload.exe    Host: cdn.malware.net
```

---

## Quick Start

### Standalone (No Dependencies)

```bash
# Build
cargo build --release

# Generate config
./target/release/nettrap config --defaults > config.toml

# Run
./target/release/nettrap run -c config.toml

# Run on specific ports
./target/release/nettrap run -p 22 -p 23 -p 80 -p 443 -p 3389

# Run with PCAP capture + attribution
./target/release/nettrap run -c config.toml --pcap --attribution
```

### Docker

```bash
docker build -t nettrap:latest .
docker run -d --name nettrap \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -p 53:5353/udp -p 80:8080 -p 443:8443 \
  -p 22:2222 -p 23:2323 -p 25:2525 \
  nettrap:latest
```

---

## Output Formats

NetTrap generates reports in 5 formats simultaneously:

| Format | Extension | Use Case |
|--------|-----------|----------|
| **JSONL** | `.jsonl` | Real-time streaming (default) |
| **JSON** | `.json` | Full event array |
| **SARIF v2.1.0** | `.sarif.json` | GitHub Code Scanning, SIEM integration |
| **TOON** | `.toon` | LLM-optimized (40% fewer tokens than JSON) |
| **CSV** | `.csv` | Spreadsheet analysis |

```bash
nettrap run -c config.toml --report-format sarif
```

---

## Database Storage

### SQLite (Standalone)

Zero dependencies, single portable file:

```toml
[database]
backend = "sqlite"
sqlite_path = "nettrap.db"
```

### MariaDB/MySQL (Distributed)

Shared storage for multi-node fleets:

```toml
[database]
backend = "mariadb"
mysql_url = "mysql://nettrap:password@mariadb:3306/nettrap"
pool_size = 5
```

Supports **Galera multi-master** for synchronous replication across nodes. See [examples/](examples/) for Docker Compose stacks.

---

## Distributed Deployment

NetTrap scales from a single process to a global fleet. All distributed features are **optional** — standalone mode works with zero extra config.

```
┌─────────────────────────────────────────┐
│            Control Plane                 │
│  Config Server · Fleet Manager · Alerts  │
└──────────────────┬──────────────────────┘
                   │
       ┌───────────┼───────────┐
       │           │           │
  ┌────▼───┐  ┌───▼────┐  ┌───▼────┐
  │ Node 1 │  │ Node 2 │  │ Node N │
  │ (AWS)  │  │(Azure) │  │(OnPrem)│
  └────┬───┘  └───┬────┘  └───┬────┘
       └──────────┼────────────┘
                  ▼
  Elasticsearch · Kafka · Splunk · Syslog · MariaDB
```

### Event Sinks

Ship events in real-time to any combination of backends:

```toml
[distributed]
enabled = true
health_bind = "0.0.0.0:9090"

# Elasticsearch
[[distributed.event_sinks]]
type = "http"
target = "http://elasticsearch:9200/nettrap-events/_doc"

# Kafka (via TCP bridge)
[[distributed.event_sinks]]
type = "tcp"
target = "kafka-bridge:5044"

# Syslog (RFC 5424)
[[distributed.event_sinks]]
type = "syslog"
target = "syslog-server:514"

# Splunk HEC
[[distributed.event_sinks]]
type = "http"
target = "https://splunk:8088/services/collector/event"
auth = "Splunk your-hec-token"
```

### Health & Metrics

```bash
curl http://nettrap-node:9090/health    # Liveness
curl http://nettrap-node:9090/ready     # Readiness
curl http://nettrap-node:9090/metrics   # Prometheus
```

### Ready-to-Run Examples

```bash
# 3-node fleet with TCP collector
docker compose -f docker-compose.test.yml up -d

# Elasticsearch + Kibana
docker compose -f examples/docker-compose.elasticsearch.yml up -d

# Kafka (Redpanda) + Console
docker compose -f examples/docker-compose.kafka.yml up -d

# MariaDB Galera multi-master (3 DB nodes + 4 NetTrap nodes)
docker compose -f examples/docker-compose.mariadb-galera.yml up -d

# SQLite standalone
docker compose -f examples/docker-compose.sqlite.yml up -d
```

---

## Configuration

### Listener Options

```toml
[[listeners]]
name = "ssh"              # Protocol handler name
port = 22                 # Listen port (any protocol on any port)
protocol = "tcp"          # tcp or udp
bind_address = "0.0.0.0"
enabled = true
use_ssl = true            # TLS wrapping
banner = "!vsftpd"        # Banner preset (90+ FTP presets, !random, !hostname)
webroot = "/var/www"      # HTTP file serving directory
ftproot = "/var/ftp"      # FTP file serving directory
response_delay_ms = 100   # Artificial latency
execute_cmd = "echo {src_addr}:{src_port} >> /tmp/connections.log"
process_whitelist = ["malware.exe"]       # Literal substring by default; use "re:<pattern>" for regex
process_blacklist = ["svchost.exe"]
host_whitelist = ["10.0.0.0/8"]  # Exact IPs, CIDR ranges, and exact hostnames resolved at startup are supported
host_blacklist = ["192.168.1.1"]
dump_http_posts = true    # Save POST bodies
port_range = "8000-8010"  # Expand to 11 listeners
dns_response_ip = "192.168.100.1"
dns_nxdomains = 3         # Ignore first 3 queries (C2 failover testing)
```

### Custom Responses

```toml
# Match host + URI, return custom content
custom_response = "host=evil.com;uri=/gate;type=static;body=OK||host=*;uri=.exe;type=file;path=/path/to/payload.bin||host=*;uri=*;type=base64;data=SGVsbG8="
```

Supports `<RAW-DATE>` substitution and `{{variable}}` templates.

---

## Platform Support

| Platform | Architecture | Interceptor | Status |
|----------|-------------|-------------|--------|
| **Linux** | x86_64, i686, ARM64, ARM | NFQUEUE + iptables, PCAP | ✅ Full |
| **macOS** | x86_64 (Intel), ARM64 (Apple Silicon) | PCAP | ✅ Full |
| **Windows** | x86_64, i686 | WinDivert | ✅ Full |
| **Windows** | ARM64 | Npcap | ✅ Full |

---

## CLI Reference

```bash
nettrap run [OPTIONS]           # Start the engine
nettrap config --defaults       # Generate default config
nettrap config --check          # Validate config file
nettrap tls status              # Show mkcert/TLS status
nettrap tls install-mkcert      # Download & install mkcert
nettrap tls install             # Install CA in system trust store
nettrap tls generate <hosts>    # Generate certificate for hostnames
nettrap pcap -i <file>          # Process PCAP file
nettrap report -i <file>        # Generate report
nettrap status [--json]         # Show engine status
```

### Global Flags

```
-c, --config <PATH>     Configuration file
-v, --verbose           Debug logging
-q, --quiet             Error-only logging
-l, --log-file <PATH>   Log to file
-s, --log-syslog        Log to syslog
-f, --stop-flag <PATH>  Graceful shutdown via file creation
-n, --no-console        Suppress console output
```

---

## Build Dependencies

```bash
# Ubuntu/Debian
sudo apt install -y libpcap-dev libnetfilter-queue-dev

# Fedora
sudo dnf install -y libpcap-devel libnetfilter_queue-devel

# macOS
brew install libpcap

# Windows — Install Npcap from https://nmap.org/npcap/
```

---

## Architecture

50 modular Rust crates:

```
nettrap-cli             # Binary entry point + engine orchestration
├── nettrap-core        # Shared types (Packet, FiveTuple, Error)
├── nettrap-proxy       # Protocol taste router (26 detectors)
├── nettrap-tls-mitm    # TLS MITM, CA management, JA3/JA4
├── nettrap-interceptor # PCAP, NFQUEUE, WinDivert
├── nettrap-attribution # Process-to-connection mapping
├── nettrap-pcap        # Binary PCAP recording
├── nettrap-proto-*     # 26 protocol handler crates
├── nettrap-flow        # Connection flow tracking
├── nettrap-events      # Event bus
├── nettrap-policy      # Rule matching engine
├── nettrap-ioc         # IOC extraction
├── nettrap-fingerprint # TLS fingerprinting
├── nettrap-storage     # Storage backends
├── nettrap-api         # REST API server
└── nettrap-tui         # Terminal UI
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](docs/quickstart.md) | Get running in 5 minutes |
| [Standalone Mode](docs/standalone.md) | Single-machine deployment |
| [Distributed Deployment](docs/distributed.md) | Multi-node fleet management |
| [Kubernetes Deployment](docs/kubernetes.md) | K8s manifests & Helm |
| [Configuration Reference](docs/configuration.md) | All config options |
| [Protocol Handlers](docs/protocols.md) | Protocol details & customization |
| [Output Formats](docs/output-formats.md) | JSONL, JSON, SARIF, TOON, CSV |
| [Architecture](docs/architecture.md) | Internal design & crate structure |

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Rust 2024 Edition
- `cargo fmt` for formatting
- `cargo clippy` for linting
- Add tests for new functionality

---

## Support the Project

If you find NetTrap useful, consider supporting its development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Author:** **Marc Rivero** | [@seifreed](https://github.com/seifreed)

---

## Acknowledgments

- Inspired by [FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng) by Mandiant
- Built with [Tokio](https://tokio.rs/) async runtime
- TLS via [rustls](https://github.com/rustls/rustls) + [rcgen](https://github.com/est31/rcgen)
- mkcert integration via [mkcert](https://github.com/FiloSottile/mkcert)

---

<p align="center">
  <sub>Made with dedication for the security research community</sub>
</p>
