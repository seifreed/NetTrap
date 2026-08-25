# Security Audit Scope

This document is the handoff package for an independent security review. It
does not claim that a third-party audit has already been completed.

## Scope

The review should cover:

- Untrusted TCP/UDP parsing, protocol dispatch, framing, and resource limits.
- Linux firewall redirection, nftables/iptables cleanup, privilege boundaries,
  and crash recovery.
- Windows listener/capture adapters and the experimental WinDivert TCP/UDP
  NAT path used by `--intercept` on x86_64.
- TLS certificate generation, key storage, and local termination boundaries.
- REST/API exposure, configuration migration, filesystem writes, and reports.
- Docker/Kubernetes manifests, release workflows, Sigstore signing, SBOMs, and
  provenance attestations.

## Threat Model

The attacker controls network bytes, connection timing, protocol claims,
hostnames, paths, headers, credentials, and malformed configuration supplied to
the analysis environment. The host may be resource constrained. Firewall and
packet-capture paths may run with elevated privileges. Release consumers must
be able to verify artifact integrity before execution.

## Reproducible Evidence

Run from the repository root:

```bash
cargo audit
cargo deny check
./scripts/quality-gates.sh quick
actionlint .github/workflows/*.yml
bash tests/verify_platform.sh
# On a privileged Windows x86_64 runner with WinDivert files installed:
pwsh -File tests/windows_interception_smoke.ps1 -BinaryPath .\nettrap.exe
```

The scheduled security workflow repeats OpenSSF Scorecard, CodeQL for Rust,
and dependency audits.
The release workflow verifies Sigstore bundles, GitHub artifact attestations,
SBOMs, and checksums before publishing.

## Acceptance Criteria

An independent review is complete only when the auditor provides a dated report
covering the scope above, severity-ranked findings, reproduction steps, and a
retest statement for every High or Critical finding. The report and remediation
commits must be linked from the release notes; automated green checks are not a
substitute for that review.
