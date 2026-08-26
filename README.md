<p align="center">
  <img src="https://img.shields.io/badge/NetTrap-Network%20Security-orange?style=for-the-badge" alt="NetTrap">
</p>

<h1 align="center">NetTrap</h1>

<p align="center">
  <strong>Network Service Emulation & Behavioral Capture Engine</strong>
</p>

<p align="center">
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.97.1-orange?style=flat-square&logo=rust&logoColor=white" alt="Rust Version"></a>
  <a href="https://github.com/seifreed/NetTrap/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License: MIT"></a>
  <a href="https://github.com/seifreed/nettrap/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/nettrap/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/seifreed/NetTrap"><img src="https://api.scorecard.dev/projects/github.com/seifreed/NetTrap/badge" alt="OpenSSF Scorecard"></a>
  <img src="https://img.shields.io/badge/detectors-35-blue?style=flat-square" alt="Protocol detectors">
  <img src="https://img.shields.io/badge/crates-52-blue?style=flat-square" alt="Crates">
</p>

<p align="center">
  <a href="https://github.com/seifreed/nettrap/stargazers"><img src="https://img.shields.io/github/stars/seifreed/nettrap?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/nettrap/issues"><img src="https://img.shields.io/github/issues/seifreed/nettrap?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**NetTrap** is a late-alpha network service emulation and behavioral capture engine written in Rust. Direct listener mode is the primary supported path. Linux transparent redirection is experimental; Windows x86_64 transparent interception is disabled until packet-preserving NAT is validated, and macOS and Windows ARM64 remain listener/capture only. The 35 registered detectors have different fidelity levels and do not represent 35 complete protocol servers.

### Why NetTrap?

- **35 protocol detectors** — traffic classification plus partial service emulation; see the verified matrix
- **Local TLS termination with JA3/JA4** — inspect inbound TLS for configured listeners
- **mkcert integration** — one command to install a trusted CA for local TLS termination tests
- **Distributed mode** — multi-node fleet with event shipping to Elasticsearch, Kafka, Splunk, Syslog
- **Database storage** — SQLite (standalone) or PostgreSQL (distributed)
- **5 output formats** — JSONL, JSON, SARIF v2.1.0, TOON, CSV
- **Cross-platform listener mode** — packaged for Linux, macOS, and Windows x86_64/ARM64
- **Async Rust** — built on Tokio, 52 modular crates

---

## Protocol Coverage

NetTrap combines taste-based detection with partial service emulation. Required
real-client CI covers DNS/HTTP, LDAP, mail, MQTT, Redis, MySQL, PostgreSQL, and
SMB in the Docker smoke; the platform verification script additionally checks
TLS, SMTP, FTP, SSH, and Telnet where host clients are available. See [Protocol
Support](PROTOCOL_SUPPORT.md) before relying on a handler.

---

## Experimental TLS Termination

NetTrap can terminate inbound TLS for a configured local listener:

- **Dynamic certificate generation** per SNI hostname
- **JA3 fingerprinting** — identify malware by TLS client fingerprint
- **JA4 fingerprinting** — next-gen TLS fingerprint (FoxIO spec)
- **mkcert integration** — optional local CA installation

```bash
# Install mkcert (one time)
nettrap tls install-mkcert
nettrap tls install          # Install CA in system trust store

# Run a configured TLS listener
nettrap run -c config.toml
```

This path does not establish an upstream connection, implement selective
passthrough, or bypass certificate pinning. It is not a general transparent
TLS MITM proxy.

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
docker build -t nettrap:0.1.0-alpha.1 .
docker run -d --name nettrap \
  -p 1053:5353/udp -p 8080:8080 -p 2222:2222 -p 2323:2323 \
  -v nettrap-logs:/var/log/nettrap \
  nettrap:0.1.0-alpha.1
```

### Release packages

GitHub releases publish raw platform binaries, Linux `.deb` and `.rpm` packages,
macOS/Linux tarballs, Windows ZIP/MSI installers, and a Homebrew formula generated
from the release checksums. Verify downloaded assets with `SHA256SUMS`, the adjacent
`.sigstore.json` bundles, and the commands in
[RELEASE_VERIFICATION.md](RELEASE_VERIFICATION.md).

---

## Output Formats

NetTrap supports 5 NBI formats. JSONL is the default streaming output; shutdown also generates HTML, SARIF, and CSV when an output path is configured. JSON or TOON can be selected as the primary export:

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

### PostgreSQL (Distributed)

Shared storage for multi-node fleets:

```toml
[database]
backend = "postgres"
postgres_url = "postgres://nettrap:password@postgres:5432/nettrap"
pool_size = 5
```

See [examples/](examples/) for Docker Compose stacks and event-sink integrations.

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
  Elasticsearch · Kafka · Splunk · Syslog · PostgreSQL
```

### Event Sinks

Ship events in real-time to any combination of backends:

```toml
[distributed]
enabled = true
health_bind = "0.0.0.0:9090"    # serves /health and /ready
metrics_bind = "0.0.0.0:9091"   # serves /metrics (Prometheus)

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

The liveness/readiness probes and the Prometheus metrics endpoint run as
separate servers, bound via `health_bind` and `metrics_bind` respectively:

```bash
curl http://nettrap-node:9090/health    # Liveness  (health_bind)
curl http://nettrap-node:9090/ready     # Readiness (health_bind)
curl http://nettrap-node:9091/metrics   # Prometheus (metrics_bind)
```

### Ready-to-Run Examples

```bash
# 3-node fleet with TCP collector
docker compose -f docker-compose.test.yml up -d

# Elasticsearch + Kibana
docker compose -f examples/docker-compose.elasticsearch.yml up -d

# Kafka (Redpanda) + Console
docker compose -f examples/docker-compose.kafka.yml up -d

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
host_blacklist = ["192.168.1.1"] # Loopback (127.0.0.0/8, ::1) is always allowed and bypasses both lists
dump_http_posts = true    # Save POST bodies
port_range = "8000-8010"  # Expand to 11 listeners
dns_response_ip = "192.168.100.1"
dns_nxdomains = 3         # Ignore first 3 queries (C2 failover testing)
```

Ordered flow actions can match the listener, protocol, source/original
destination, port, and attributed process. The first matching rule wins:

```toml
[[flow_rules]]
listener = "http"
protocol = "tcp"
destination_port = 443
decision = "capture"
```

### Custom Responses

```toml
# Match host + URI, return custom content
custom_response = "host=evil.com;uri=/gate;type=static;body=OK||host=*;uri=.exe;type=file;path=/path/to/payload.bin||host=*;uri=*;type=base64;data=SGVsbG8="
```

Supports `<RAW-DATE>` substitution and `{{variable}}` templates.

---

## Platform Support

| Platform | Release targets | Listener mode | Transparent redirection |
|----------|-----------------|---------------|-------------------------|
| **Linux** | x86_64, ARM64 | Supported | Experimental |
| **macOS** | x86_64, ARM64 | Supported | Not supported |
| **Windows** | x86_64, ARM64 | Supported | x86_64 experimental; ARM64 listener/capture only |

See [Platform Support](PLATFORM_SUPPORT.md) for CI evidence, capture caveats,
and unsupported targets.

---

## CLI Reference

```bash
nettrap run [OPTIONS]           # Start the engine
nettrap config --defaults       # Generate default config
nettrap config --check          # Validate config file
nettrap config --migrate -c old.toml -o config.toml  # Upgrade a config schema
nettrap tls status              # Show mkcert/TLS status
nettrap tls install-mkcert      # Download & install mkcert
nettrap tls install             # Install CA in system trust store
nettrap tls generate <hosts>    # Generate certificate for hostnames
nettrap tls caroot              # Show the mkcert CA root directory
nettrap pcap -i <file>          # Replay a PCAP file offline and extract indicators
nettrap report -i <file>        # Export NBI report from JSON/JSONL input
nettrap status [--json]         # Show engine status
nettrap api [-b <ADDR>]         # Start REST API server (/health, /api/v1/flows, /api/v1/stats; default 127.0.0.1:9090)
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

52 modular Rust crates/packages:

```
nettrap-cli             # Binary entry point + engine orchestration
├── nettrap-core        # Shared types (Packet, FiveTuple, Error)
├── nettrap-proxy       # Protocol taste router (content detectors)
├── nettrap-tls-mitm    # Local TLS termination, CA management, JA3/JA4
├── nettrap-interceptor # PCAP and platform redirection adapters
├── nettrap-attribution # Process-to-connection mapping
├── nettrap-pcap        # Binary PCAP recording
├── nettrap-proto-*     # 33 runtime service/fallback handlers
├── nettrap-flow        # Connection flow tracking
├── nettrap-events      # Event bus
├── nettrap-ioc         # IOC extraction from captured content
├── nettrap-storage     # Storage backends
└── nettrap-api         # Runtime health/metrics surface
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](docs/quickstart.md) | Get running in 5 minutes |
| [Distributed Deployment](docs/distributed.md) | Multi-node fleet management |
| [Kubernetes Deployment](docs/kubernetes.md) | K8s manifests & Helm |
| [Configuration Reference](docs/configuration.md) | All config options |
| [Protocol Support](PROTOCOL_SUPPORT.md) | Verified fidelity and E2E coverage matrix |
| [Platform Support](PLATFORM_SUPPORT.md) | Release targets and mode boundaries |
| [Known Limitations](KNOWN_LIMITATIONS.md) | Alpha boundaries and unsupported behavior |
| [Security Policy](SECURITY.md) | Private reporting and supported versions |
| [Contributing](CONTRIBUTING.md) | Development workflow and pull request requirements |
| [Code of Conduct](CODE_OF_CONDUCT.md) | Community standards and enforcement |
| [Changelog](CHANGELOG.md) | Release history and notable changes |
| [Third-Party Notices](THIRD_PARTY_NOTICES.md) | External components and license inventory |
| [Output Formats](docs/output-formats.md) | JSONL, JSON, SARIF, TOON, CSV |
| [Architecture](docs/architecture.md) | Internal design & crate structure |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the required tests, quality gates,
and pull request checklist. Participation is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).

---

## Support the Project

If you find NetTrap useful, consider supporting its development:

<a href="https://buymeacoffee.com/seifreed" target="_blank">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50">
</a>

---

## License

This project is licensed under the [MIT License](LICENSE). See
[Third-Party Notices](THIRD_PARTY_NOTICES.md) for dependencies and optional
external components.

**Author:** **Marc Rivero** | [@seifreed](https://github.com/seifreed)

---

## Acknowledgments

- Built with [Tokio](https://tokio.rs/) async runtime
- TLS via [rustls](https://github.com/rustls/rustls) + [rcgen](https://github.com/est31/rcgen)
- mkcert integration via [mkcert](https://github.com/FiloSottile/mkcert)

---

<p align="center">
  <sub>Made with dedication for the security research community</sub>
</p>
