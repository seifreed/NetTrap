# Changelog

All notable changes to NetTrap are documented here. The project follows
Semantic Versioning, with alpha releases allowed to change configuration and
event contracts before `1.0.0`.

## [Unreleased]

### Added

- Six-target release workflow for Linux, macOS, and Windows x86_64/ARM64.
- SHA-256 checksums, SPDX SBOM generation, and GitHub artifact attestations.
- Explicit platform and protocol support matrices.
- Non-root Docker image and persistent listener-mode Compose/Kubernetes examples.
- Configuration migration command with future-schema rejection and validation.
- Ordered first-match flow policy rules for listener, protocol, destination,
  source, and attributed-process decisions.
- Docker and platform smoke tests now exercise LDAP bind/search with
  `ldapsearch` when available.
- Kubernetes manifests and distributed fixtures now expose LDAP on port 1389
  and use canonical decision values.

### Changed

- Direct listener mode is documented as the primary alpha execution mode.
- TLS behavior is described as local termination rather than general upstream MITM.
- Platform integration tests now fail closed on DNS/HTTP errors.

### Security

- Windows `--intercept` now fails closed instead of opening the incomplete
  WinDivert path.
- Kubernetes and Docker examples no longer grant packet/network capabilities.

## [0.1.0-alpha.1] - Unreleased

Initial technical-preview release. See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md)
and the support matrices before deployment.
