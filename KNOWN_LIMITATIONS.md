# Known Limitations

NetTrap `0.1.0-alpha.1` is a technical preview for controlled malware-analysis
labs. It is not a production firewall, transparent proxy, or complete honeypot
suite.

## Networking

- Direct listener mode is the primary supported path.
- Linux transparent redirection is experimental. It uses dedicated NetTrap
  chains and removes stale managed chains on the next startup. Abrupt shutdown
  can leave its jump rules and multi-host forwarding enabled until that restart
  or manual cleanup. Direct `nft` support and network-namespace E2E are pending.
- Windows rejects `--intercept`; WinDivert redirection is incomplete and no
  WinDivert driver is shipped.
- macOS has no transparent redirection implementation.
- Live capture and process attribution depend on OS facilities, privileges, and
  external packet-capture runtimes.

## Policy and Protocols

- TCP and UDP apply `pass`, `capture`, `emulate`, `sinkhole`, and `block`
  decisions and audit the selected rule. Policy matching is currently based on
  listener configuration plus host/process filters; richer ordered per-flow
  rules are still pending.
- Protocol handlers have uneven fidelity. DNS, HTTP(S), TLS, SMTP, and FTP have
  required external-client E2E in the baseline CI contract.
- SSH does not complete a normal OpenSSH authentication session; SMB is not a
  full SMB2/SMB3 server; QUIC does not decrypt traffic or implement HTTP/3.
- Local TLS termination does not connect upstream, provide selective
  passthrough, or bypass certificate pinning.

See [PROTOCOL_SUPPORT.md](PROTOCOL_SUPPORT.md) for the handler-by-handler matrix.

## API, Data, and Compatibility

- The REST API has no authentication and rejects non-loopback bind addresses.
  It is not a remote administration surface.
- Event, report, API, and configuration schemas do not yet have migration or
  compatibility guarantees.
- Release binaries are not platform code-signed. GitHub release artifacts do
  include checksums, SBOMs, and provenance attestations.
- Long-running soak, hostile load, and connection-exhaustion coverage is not yet
  a release gate.
- Real malware samples and private captures are not part of default regression
  tests; runtime behavior is sample-agnostic.

Platform details are maintained in [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md).
