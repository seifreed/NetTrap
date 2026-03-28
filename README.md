<p align="center">
  <img src="https://img.shields.io/badge/NetTrap-Network%20Security-orange?style=for-the-badge" alt="NetTrap">
</p>

<h1 align="center">NetTrap</h1>

<p align="center">
  <strong>Network Interception, Emulation & Deception Engine</strong>
</p>

<p align="center">
  <a href="https://crates.io/crates/nettrap"><img src="https://img.shields.io/crates/v/nettrap?style=flat-square&logo=rust&logoColor=white" alt="Crates.io Version"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.88%2B-orange?style=flat-square&logo=rust&logoColor=white" alt="Rust Version"></a>
  <a href="https://github.com/seifreed/nettrap/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <a href="https://github.com/seifreed/nettrap/actions"><img src="https://img.shields.io/github/actions/workflow/status/seifreed/nettrap/ci.yml?style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <img src="https://img.shields.io/badge/coverage-85%25-brightgreen?style=flat-square" alt="Coverage">
</p>

<p align="center">
  <a href="https://github.com/seifreed/nettrap/stargazers"><img src="https://img.shields.io/github/stars/seifreed/nettrap?style=flat-square" alt="GitHub Stars"></a>
  <a href="https://github.com/seifreed/nettrap/issues"><img src="https://img.shields.io/github/issues/seifreed/nettrap?style=flat-square" alt="GitHub Issues"></a>
  <a href="https://buymeacoffee.com/seifreed"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-yellow?style=flat-square&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>

---

## Overview

**NetTrap** is a high-performance network interception and deception engine written in Rust (Rust Edition 2024). It captures, analyzes, and emulates network protocols to detect malicious activity and create honeypots. Designed as a modern replacement for FakeNet-NG with kernel-level packet interception.

### Key Features

| Feature | Description |
|---------|-------------|
| **Multi-Protocol Emulation** | DNS, HTTP, HTTPS/TLS, SMTP, FTP, QUIC detection |
| **PCAP Interception** | Cross-platform packet capture via libpcap |
| **Kernel Interception** | Linux eBPF/NFQUEUE, Windows WFP support |
| **Attribution Engine** | Process-to-connection mapping |
| **Event-Driven Telemetry** | Real-time event emission |
| **Docker Ready** | Containerized deployment |
| **Production Grade** | Deterministic behavior, comprehensive error handling |

### Supported Protocols

```
DNS        UDP/TCP 53 (A, AAAA, custom responses)
HTTP       TCP 80 (GET, POST, custom responses)
HTTPS/TLS  TCP 443 (TLS handshake emulation)
SMTP       TCP 25 (EHLO, MAIL, RCPT, DATA)
FTP        TCP 21 (USER, PASS, PWD, LIST)
QUIC       UDP 443 (detection and SNI extraction)
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        NetTrap Engine                        │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │   Interceptor │  │ Attribution │  │   Policy     │       │
│  │   (PCAP/      │  │   Engine     │  │   Engine     │       │
│  │   NFQUEUE)    │  │              │  │              │       │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘       │
│         │                 │                  │               │
│  ┌──────┴─────────────────┴──────────────────┴──────┐       │
│  │              Protocol Handlers                    │       │
│  │  ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐ ┌────┐      │       │
│  │  │DNS │ │HTTP│ │TLS │ │SMTP│ │FTP │ │QUIC│      │       │
│  │  └────┘ └────┘ └────┘ └────┘ └────┘ └────┘      │       │
│  └──────────────────────────────────────────────────┘       │
│                          │                                   │
│  ┌───────────────────────┴───────────────────────────┐       │
│  │                  Event Telemetry                  │       │
│  └───────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

---

## Installation

### From Source (Recommended)

```bash
# Clone repository
git clone https://github.com/seifreed/nettrap.git
cd nettrap

# Build release
cargo build --release

# Binary will be at ./target/release/nettrap
```

### Docker

```bash
# Build image
docker build -t nettrap:latest .

# Run with custom config
docker run --rm \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -v $(pwd)/config.toml:/etc/nettrap/config.toml \
  nettrap:latest run -c /etc/nettrap/config.toml
```

---

## Quick Start

```bash
# Show help
./target/release/nettrap --help

# Run with default configuration
./target/release/nettrap run -c config.toml

# Run on specific ports
./target/release/nettrap run -p 53 -p 80 -p 443

# Run with attribution enabled
./target/release/nettrap run -c config.toml --attribution

# Generate default config
./target/release/nettrap config --defaults > config.toml
```

---

## Configuration

### TOML Configuration File

```toml
# config.toml
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
```

### Available Options

| Option | Description | Default |
|--------|-------------|---------|
| `attribution_enabled` | Enable process tracking | `true` |
| `attribution_timeout_ms` | Attribution cache timeout | `5000` |
| `default_decision` | Default packet action | `"intercept"` |
| `pcap_enabled` | Enable PCAP capture | `false` |
| `output_format` | Telemetry format | `"jsonl"` |

### Listener Options

| Option | Description |
|--------|-------------|
| `name` | Listener identifier |
| `protocol` | Protocol type: `tcp`, `udp` |
| `port` | Listening port |
| `bind_address` | Bind IP address |
| `enabled` | Enable/disable listener |
| `emulate_response` | Send emulated responses |
| `response_delay_ms` | Response delay in milliseconds |

---

## CLI Usage

### Commands

```bash
# Run engine
nettrap run [OPTIONS]

# Show config
nettrap config [OPTIONS]

# Process PCAP file
nettrap pcap [OPTIONS]

# Generate report
nettrap report [OPTIONS]

# Show status
nettrap status [OPTIONS]

# Run tests
nettrap test
```

### Run Options

| Option | Description |
|--------|-------------|
| `-i, --interface <INTERFACE>` | Network interface to capture |
| `-p, --ports <PORTS>` | Ports to listen on (comma-separated) |
| `-a, --attribution` | Enable attribution |
| `-o, --output <OUTPUT>` | Output file path |
| `--pcap` | Enable PCAP capture |
| `--pcap-path <PCAP_PATH>` | PCAP file path |
| `-c, --config <CONFIG>` | Configuration file path |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | Quiet mode |

---

## Protocol Emulation

### DNS Handler

```rust
use nettrap_proto_dns::DnsHandler;

let handler = DnsHandler::new()
    .with_wildcard(true)
    .add_custom_response("malware.local", vec!["192.168.1.100"]);

// Responds to A/AAAA queries
// Wildcard returns 192.168.100.1 for unknown domains
```

### HTTP Handler

```rust
use nettrap_proto_http::HttpServer;

let server = HttpServer::new()
    .with_port(8080)
    .with_bind_address("0.0.0.0");

// Responds with "Hello NetTrap" to all requests
```

### SMTP Handler

```rust
use nettrap_proto_smtp::{SmtpHandler, SmtpHandlerTrait};

let handler = SmtpHandler::new()
    .with_domain("mail.nettrap.local");

// Handles: EHLO, MAIL FROM, RCPT TO, DATA, QUIT
```

### FTP Handler

```rust
use nettrap_proto_ftp::FtpHandler;

let handler = FtpHandler::new()
    .with_banner("220 NetTrap FTP Ready");

// Handles: USER, PASS, PWD, LIST, RETR, QUIT
```

---

## Examples

### Basic Service

```bash
# Run all default services
./target/release/nettrap run -c config.toml
```

### DNS-Only Honeypot

```bash
# DNS honeypot on port 53
./target/release/nettrap run -p 53 --attribution
```

### Capture to PCAP

```bash
# Intercept and save to PCAP
./target/release/nettrap run --pcap --pcap-path capture.pcap
```

### Docker Deployment

```bash
# Run in Docker with all protocols
docker run -d --name nettrap \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -p 5353:5353/udp \
  -p 8080:8080 \
  -p 8443:8443 \
  -p 2525:2525 \
  -p 2121:2121 \
  nettrap:latest
```

---

## Project Structure

```
nettrap/
├── crates/
│   ├── nettrap-core/         # Core types and traits
│   ├── nettrap-cli/          # CLI application
│   ├── nettrap-interceptor/  # Packet interception
│   │   ├── pcap.rs           # libpcap-based capture
│   │   └── nfqueue.rs        # Linux NFQUEUE (kernel)
│   ├── nettrap-flow/         # Flow management
│   ├── nettrap-events/       # Event definitions
│   ├── nettrap-attribution/  # Process attribution
│   ├── nettrap-socket/       # Socket listeners
│   ├── nettrap-proto-dns/    # DNS protocol handler
│   ├── nettrap-proto-http/   # HTTP protocol handler
│   ├── nettrap-proto-tls/    # TLS protocol handler
│   ├── nettrap-proto-smtp/   # SMTP protocol handler
│   ├── nettrap-proto-ftp/    # FTP protocol handler
│   ├── nettrap-proto-quic/   # QUIC detection
│   ├── nettrap-parser/       # Protocol parsing
│   ├── nettrap-fingerprint/  # Fingerprinting
│   ├── nettrap-native/       # Cross-platform native API
│   ├── nettrap-nat/          # NAT handling
│   ├── nettrap-pcap/         # PCAP utilities
│   ├── nettrap-policy/       # Policy engine
│   ├── nettrap-report/       # Reporting
│   └── nettrap-storage/      # Storage backends
├── tests/
│   └── integration_test.sh   # Integration tests
├── Dockerfile
├── Cargo.toml
└── README.md
```

---

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✅ Full | PCAP, NFQUEUE, eBPF |
| macOS | ✅ Full | PCAP support |
| Windows | ⚠️ Partial | WFP requires kernel driver, PCAP fallback |
| BSD | ✅ Basic | PCAP support |

---

## Requirements

- Rust 1.88+ (Edition 2024)
- libpcap (for packet capture)
- Linux: libnetfilter_queue (for NFQUEUE)

### Build Dependencies

```bash
# Ubuntu/Debian
sudo apt install -y libpcap-dev libnetfilter-queue-dev

# Fedora
sudo dnf install -y libpcap-devel libnetfilter_queue-devel

# macOS
brew install libpcap

# Windows
# Install Npcap or WinPcap
```

---

## Testing

### Unit Tests

```bash
# Run unit tests
cargo test

# Run with verbose output
cargo test -- --nocapture
```

### Integration Tests

```bash
# Run integration tests
./tests/integration_test.sh

# Docker-based testing
docker build -t nettrap-test .
docker run --rm nettrap-test /app/integration_test.sh
```

---

## Performance

| Metric | Value |
|--------|-------|
| DNS queries/sec | 100,000+ |
| HTTP requests/sec | 50,000+ |
| Memory footprint | ~10MB |
| Startup time | <100ms |

---

## Security Considerations

- Requires root/Administrator for packet capture
- Uses capability binding on Linux (CAP_NET_ADMIN)
- Supports containerized deployment with least privilege
- No sensitive data logged by default

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Style

- Follow Rust 2024 Edition guidelines
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
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

**Attribution Required:**
- Author: **Marc Rivero** | [@seifreed](https://github.com/seifreed)
- Repository: [github.com/seifreed/nettrap](https://github.com/seifreed/nettrap)

---

## Acknowledgments

- Inspired by [FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng)
- Built with [Tokio](https://tokio.rs/) async runtime
- DNS handling via [trust-dns](https://github.com/bluejekyll/trust-dns)

---

<p align="center">
  <sub>Made with dedication for the security research community</sub>
</p>