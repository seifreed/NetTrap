# Architecture

## Crate Structure (52 workspace packages)

```
nettrap/
├── nettrap-core        # Shared types (Packet, FiveTuple, Error)
├── nettrap-engine      # Adapter-free runtime policies and use-case entities
├── nettrap-cli         # Binary entry point, configuration, orchestration, listeners
├── nettrap-proxy       # Protocol taste router
├── nettrap-tls-mitm    # Local TLS termination + certificate generation
├── nettrap-interceptor # PCAP and platform redirection adapters
├── nettrap-attribution # Process-to-connection mapping
├── nettrap-pcap        # PCAP recording
├── nettrap-flow        # Connection flow tracking
├── nettrap-events      # Event bus
├── nettrap-proto-*     # 33 runtime service/fallback handlers; TLS and Dummy detectors also registered
└── nettrap-api         # REST API server and HTTP adapter
```

The current composition root is `nettrap-cli`. `nettrap-engine` now owns the
adapter-free runtime policy and health state used by that composition root.
`nettrap-api` exposes that state through its HTTP adapter while depending
inward. Concrete resource assembly, listener spawning, and infrastructure
wiring remain under `crates/nettrap-cli/src/engine/` as composition-root
responsibilities. The quality gate enforces that `nettrap-engine` cannot
acquire direct outer workspace dependencies.

## Runtime Flow

```
main.rs → Engine::run()
  ├── init TLS CA
  ├── init protocol router (35 detectors: 33 runtime handlers, TLS, and Dummy)
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
        ├── configured primary export plus SARIF/CSV
        ├── flush event sinks
        └── close PCAP writer
```
