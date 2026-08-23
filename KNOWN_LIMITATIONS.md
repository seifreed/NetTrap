# Known Limitations

NetTrap `0.1.0-alpha.1` is a technical preview for controlled malware-analysis
labs. It is not a production firewall, transparent proxy, or complete honeypot
suite.

## Networking

- Direct listener mode is the primary supported path.
- Linux transparent redirection is experimental. It modifies host firewall
  state and does not yet use dedicated NetTrap chains, nftables, crash recovery,
  or network-namespace E2E.
- Windows rejects `--intercept`; WinDivert redirection is incomplete and no
  WinDivert driver is shipped.
- macOS has no transparent redirection implementation.
- Live capture and process attribution depend on OS facilities, privileges, and
  external packet-capture runtimes.

## Policy and Protocols

- There is no per-flow policy engine for pass, capture, emulate, sinkhole, and
  block decisions. `default_decision` and `emulate_response` are reserved alpha
  fields and do not provide those controls.
- Protocol handlers have uneven fidelity. Only DNS and HTTP have required
  external-client E2E in the baseline CI contract.
- SSH does not complete a normal OpenSSH authentication session; SMB is not a
  full SMB2/SMB3 server; QUIC does not decrypt traffic or implement HTTP/3.
- Local TLS termination does not connect upstream, provide selective
  passthrough, or bypass certificate pinning.

See [PROTOCOL_SUPPORT.md](PROTOCOL_SUPPORT.md) for the handler-by-handler matrix.

## API, Data, and Compatibility

- The REST API has no authentication. Its default loopback bind is the only
  supported alpha deployment; do not expose it on an untrusted interface.
- Event, report, API, and configuration schemas do not yet have migration or
  compatibility guarantees.
- Release binaries are not platform code-signed. GitHub release artifacts do
  include checksums, SBOMs, and provenance attestations.
- Long-running soak, hostile load, and connection-exhaustion coverage is not yet
  a release gate.
- Real malware samples and private captures are not part of default regression
  tests; runtime behavior is sample-agnostic.

Platform details are maintained in [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md).
