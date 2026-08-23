# Security Policy

## Supported Versions

NetTrap is an alpha project. Security fixes are applied to `main` and the most
recent `0.1.x` pre-release only. Older snapshots and release assets are not
maintained.

| Version | Security updates |
|---|---|
| `main` | Yes, development branch |
| Latest `0.1.x` pre-release | Best effort |
| Older versions | No |

## Reporting a Vulnerability

Do not open a public issue for an undisclosed vulnerability. Use GitHub's
[private vulnerability reporting](https://github.com/seifreed/NetTrap/security/advisories/new)
form and include:

- affected commit, version, platform, and configuration;
- a minimal reproduction or packet/config fixture without real malware;
- impact and required privileges;
- whether the issue can disrupt host networking or expose captured data;
- any proposed embargo constraints.

Maintainers aim to acknowledge a report within seven days and provide an
initial triage decision within fourteen days. These are response targets, not
service-level guarantees.

## Scope

High-priority reports include unsafe packet interception, privilege escalation,
arbitrary file access, unbounded resource consumption from network input,
credential/data disclosure, TLS key exposure, and unauthenticated remote API
exposure. Protocol-fidelity gaps already listed in
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) are not vulnerabilities by
themselves unless they create a security boundary failure.

## Operational Safety

Run NetTrap only in an isolated analysis lab. The REST API rejects non-loopback
binds while it is unauthenticated. Do not use Linux transparent redirection on
a production host or install the generated CA into a production trust store. See
[PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md) for platform-specific boundaries.
