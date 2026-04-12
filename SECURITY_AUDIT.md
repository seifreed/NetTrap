# Security Audit Report - NetTrap

## Summary (2026-03-30 - Final)

**✅ Cero vulnerabilidades de dependencias.**

## Fixed Vulnerabilities

| ID | Status | Fix |
|----|--------|-----|
| RUSTSEC-2024-0421 | ✅ | Migrated to hickory-proto 0.25 |
| RUSTSEC-2025-0134 | ✅ | Replaced with rustls-pki-types 1.14 |
| RUSTSEC-2025-0017 | ✅ | Migrated to hickory-proto 0.25 |
| RUSTSEC-2026-0002 | ✅ | Updated ratatui to 0.30 |
| RUSTSEC-2024-0436 | ✅ | Removed unused rtnetlink dependency |
| RUSTSEC-2023-0071 | ✅ | Removed MySQL dependency, use PostgreSQL/SQLite |

## Code Bug Fixes

| Severity | Issue | Fix |
|----------|-------|-----|
| 🔴 Critical | WinDivert unsafe pointer dereference | Validate IHL (20-60) before unsafe cast |
| 🔴 Critical | Passwords logged in plaintext | Added `log_credentials` flag to SMTP handler |
| 🟠 High | No default connection limit | Changed `max_connections: None` to `Some(100)` |
| 🟠 High | TCP counter race condition | RAII `ConnectionGuard` with Drop for cleanup |
| 🟠 High | UDP sequential processing | Spawn tokio task per packet for parallelism |
| 🟡 Medium | Attribution cache race | Use `DashMap::remove_if` for atomic removal |
| 🟡 Medium | CA TLS save errors ignored | Log errors with `tracing::warn!` |
| 🟢 Low | Regex recompiled every call | Use `once_cell::Lazy` for static compilation |

## Remaining Known Issues

| Severity | Issue | Status |
|----------|-------|--------|
| 🟡 Medium | NBI file opened per event | Deferred - requires channel-based writer |
| 🟡 Medium | Hard abort on shutdown | Deferred - requires CancellationToken refactor |

## Dependencies Updated

| Package | Old | New |
|---------|-----|-----|
| hickory-proto | - | 0.25 |
| hickory-client | - | 0.25 |
| rustls-pki-types | - | 1.14 |
| ratatui | 0.29 | 0.30 |
| rusqlite | 0.34 | 0.39 |
| nix | 0.29 | 0.31 |
| procfs | 0.17 | 0.18 |
| windows | 0.60 | 0.62 |
| once_cell | - | Added for regex caching |

## Dependencies Removed

| Package | Reason |
|---------|--------|
| trust-dns-proto | Vulnerable idna |
| trust-dns-client | Vulnerable idna |
| rustls-pemfile | Unmaintained |
| rtnetlink | Unused |
| netlink-packet-core | Unused |
| netlink-packet-route | Unused |
| sqlx/mysql | Vulnerable rsa (Marvin attack) |

## Security Recommendations

1. **Use PostgreSQL or SQLite for database** - Avoid MySQL/MariaDB due to rsa vulnerability
2. **Set log_credentials=false in production** if credential logging is not needed
3. **Monitor max_connections** - Default limit of 100 can be adjusted in config
4. **Run `cargo audit` regularly** - Check for new vulnerabilities