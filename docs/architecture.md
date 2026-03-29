# Architecture

## Crate Structure (50 crates)

```
nettrap/
├── nettrap-core        # Shared types (Packet, FiveTuple, Error)
├── nettrap-cli         # Binary entry point + engine
├── nettrap-proxy       # Protocol taste router
├── nettrap-tls-mitm    # TLS MITM + certificate generation
├── nettrap-interceptor # PCAP/NFQUEUE/WinDivert
├── nettrap-attribution # Process-to-connection mapping
├── nettrap-pcap        # PCAP recording
├── nettrap-flow        # Connection flow tracking
├── nettrap-events      # Event bus
├── nettrap-policy      # Rule matching engine
├── nettrap-proto-*     # 26 protocol handlers
├── nettrap-api         # REST API server
├── nettrap-tui         # Terminal UI
└── nettrap-report      # Report generation
```

## Runtime Flow

```
main.rs → Engine::run()
  ├── init TLS CA
  ├── init protocol router (26 taste detectors)
  ├── init attribution engine
  ├── init PCAP writer
  ├── init NBI collector + distributed event fanout
  ├── init session tracker
  ├── init health server (if distributed)
  ├── init heartbeat (if distributed)
  ├── for each listener:
  │     ├── TCP: spawn → accept → taste detect → handler → NBI → PCAP
  │     └── UDP: spawn → recv → taste detect → handler → NBI → PCAP
  └── await shutdown (Ctrl+C or stop-flag)
        ├── NBI console summary
        ├── NBI HTML report
        ├── SARIF/CSV/TOON export
        ├── flush event sinks
        └── close PCAP writer
```
