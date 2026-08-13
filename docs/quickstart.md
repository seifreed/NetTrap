# Quick Start

## Install from Source

```bash
# Prerequisites
# macOS: brew install libpcap
# Linux: apt install libpcap-dev libnetfilter-queue-dev
# Windows: Install Npcap from https://nmap.org/npcap/

git clone https://github.com/seifreed/nettrap.git
cd nettrap
cargo build --release
```

## Run (Standalone)

```bash
# Generate default config
./target/release/nettrap config --defaults > config.toml

# Run with all defaults
./target/release/nettrap run -c config.toml

# Run on specific ports
./target/release/nettrap run -p 22 -p 23 -p 80 -p 443

# Run with attribution (process tracking)
./target/release/nettrap run -c config.toml --attribution

# Run with PCAP capture
./target/release/nettrap run -c config.toml --pcap --pcap-path capture.pcap
```

## Docker (Standalone)

```bash
docker build -t nettrap:latest .
docker run -d --name nettrap \
  --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -p 53:5353/udp -p 80:8080 -p 443:8443 \
  -p 22:2222 -p 23:2323 -p 25:2525 \
  nettrap:latest
```

## Output

Configure an output path to persist NBI artifacts:

```bash
./target/release/nettrap run -c config.toml -o events.jsonl
```

This produces the JSONL stream plus the HTML, SARIF, and CSV shutdown exports.
Use `--report-format json` or `--report-format toon` to add that selected primary
export. Existing JSON/JSONL input can also be converted with `nettrap report`.

## Next Steps

- [Configure protocols](protocols.md)
- [Set up distributed deployment](distributed.md)
- [Deploy on Kubernetes](kubernetes.md)
