# Known Limitations

NetTrap `0.1.0-alpha.1` is a technical preview for controlled malware-analysis
labs. It is not a production firewall, transparent proxy, or complete honeypot
suite.

## Networking

- Direct listener mode is the primary supported path.
- Linux transparent redirection is experimental. It uses dedicated NetTrap
  chains (or a per-process `nettrap_<pid>` table when the iptables tools are unavailable)
  and removes stale managed state on the next startup. Abrupt shutdown can
  leave redirect rules and multi-host forwarding enabled until that restart or
  manual cleanup. The opt-in Linux network-namespace E2E covers redirection,
  crash recovery, and graceful cleanup.
- Windows x86_64 transparent redirection uses bounded packet-preserving NAT and
  fails closed when no redirectable listener is configured. It remains
  experimental until a real Windows host validates connectivity, checksums,
  cleanup, and crash recovery. Release ZIP/MSI artifacts bundle the pinned
  WinDivert runtime and license. Windows ARM64 stays in listener/capture mode.
- macOS has no transparent redirection implementation.
- Live capture and process attribution depend on OS facilities, privileges, and
  external packet-capture runtimes.

## Policy and Protocols

- TCP and UDP apply `pass`, `capture`, `emulate`, `sinkhole`, and `block`
  decisions and audit the selected rule. Ordered first-match `flow_rules` can
  match listener, protocol, source/original destination, destination port, and
  attributed process; a rule requiring unavailable attribution metadata cannot
  match.
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
- Event, report, API, and configuration schemas carry explicit version fields,
  and `config --migrate` handles older configuration versions; long-term
  compatibility guarantees are not yet provided.
- All release binaries, packages, checksums, SBOMs, formulas, and deployment
  metadata are keylessly signed with Sigstore bundles and include checksums,
  SBOMs, and provenance attestations. Windows
  Authenticode and macOS Developer ID signing is available in the release
  workflow only when `NETTRAP_NATIVE_SIGNING=1` is configured with external
  identities; the repository does not contain those private keys.
- The multi-architecture OCI image digest is signed and verified keylessly by
  the release workflow; consumers should verify that signature before pulling
  the image.
- Tagged releases are blocked when the repository security-evidence bundle
  reports an open high or critical Code Scanning alert. This gate is not a
  substitute for an independent third-party security audit.
- Release gates include a bounded hostile HTTP/DNS soak with malformed frames,
  64-connection churn, bounded file-descriptor/RSS growth checks, a
  128-socket connection-exhaustion smoke, and a complete TCP/UDP protocol
  matrix sustained for at least 60 seconds. The scheduled weekly gate extends
  that matrix and soak to a bounded 30-minute window (and at least 32 rounds),
  injecting 4 KiB malformed payloads into every handler plus truncated HTTP/DNS
  frames; unbounded
  production-scale hostile load is not a release gate. The scheduled gate
  runs the equivalent Windows HTTP/DNS hostile soak with concurrent sockets,
  malformed payloads, and working-set/handle bounds. It also runs every
  libFuzzer target for 60 seconds each; ordinary runs use 10 seconds per
  target. It does not prove privileged WinDivert routing or production-scale
  hostile load.
- Real malware samples and private captures are not part of default regression
  tests; runtime behavior is sample-agnostic.

Platform details are maintained in [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md).
