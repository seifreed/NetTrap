# Changelog

All notable changes to NetTrap are documented here. The project follows
Semantic Versioning, with alpha releases allowed to change configuration and
event contracts before `1.0.0`.

## [Unreleased]

### Added

- Six-target release workflow for Linux, macOS, and Windows x86_64/ARM64.
- SHA-256 checksums, SPDX SBOM generation, and GitHub artifact attestations.
- Linux release jobs now package `.deb` and `.rpm` artifacts and generate a
  Homebrew formula for the macOS/Linux tarballs.
- Windows release jobs now package attested ZIP and MSI assets;
  MSI verification extracts the installer into a clean directory before smoke tests.
- Explicit platform and protocol support matrices.
- Non-root Docker image and persistent listener-mode Compose/Kubernetes examples.
- Configuration migration command with future-schema rejection and validation.
- Ordered first-match flow policy rules for listener, protocol, destination,
  source, and attributed-process decisions.
- Docker and platform smoke tests now exercise LDAP bind/search with
  `ldapsearch` when available.
- Kubernetes manifests and distributed fixtures now expose LDAP on port 1389
  and use canonical decision values.
- Docker integration coverage now exercises POP3, IMAP, MQTT, and Redis with
  their real command-line clients.
- The same smoke image now exercises MariaDB and PostgreSQL clients against the
  emulated database listeners, covering MySQL handshake/query rejection and
  PostgreSQL simple-query completion.
- The Docker smoke now includes an `smbclient` negotiation probe against the
  synthetic SMB listener and records that file-sharing sessions remain out of scope.
- Scheduled heavy quality gates now run a 10-minute HTTP/DNS runtime soak and
  exercise every registered fuzz target; release calls retain a bounded
  60-second soak.
- Docker smoke now holds 128 concurrent HTTP sockets and verifies that a normal
  request remains available after the listener limit is reached.

### Changed

- Direct listener mode is documented as the primary alpha execution mode.
- TLS behavior is described as local termination rather than general upstream MITM.
- Platform integration tests now fail closed on DNS/HTTP errors.
- Release publication now waits for the explicit security audit and heavy
  reusable quality gates, and creates the checksum workspace before attestation.

### Security

- Windows x86_64 `--intercept` now uses the bounded experimental WinDivert
  TCP/UDP NAT path; full outbound routing remains a privileged-runner check.
- DNS query summaries reject non-EDNS additional records before invoking the
  third-party parser, avoiding malformed TSIG panic paths.
- Kubernetes and Docker examples no longer grant packet/network capabilities.

## [0.1.0-alpha.1] - Unreleased

Initial technical-preview release. See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md)
and the support matrices before deployment.
