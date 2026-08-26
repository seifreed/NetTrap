# Security Audit Scope

This document is the handoff package for an independent security review. It
does not claim that a third-party audit has already been completed.

## Scope

The review should cover:

- Untrusted TCP/UDP parsing, protocol dispatch, framing, and resource limits.
- Linux firewall redirection, nftables/iptables cleanup, privilege boundaries,
  and crash recovery.
- Windows listener/capture adapters and the disabled WinDivert bindings/parser;
  any future TCP/UDP NAT path must preserve packets and fail closed until
  independently validated.
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
# On Windows x86_64, verify transparent interception and fail-closed startup:
pwsh -File tests/windows_interception_smoke.ps1 -BinaryPath .\nettrap.exe
# Requires authenticated gh CLI; writes only to target/.
bash scripts/security-evidence.sh
```

The scheduled security workflow repeats OpenSSF Scorecard, CodeQL for Rust,
dependency audits, and pinned-action checks. `security-evidence.sh` also
captures the repository branch-protection contract and current Code Scanning
alert set for an auditor handoff; generated files are intentionally kept under
`target/security-audit/`.
The release workflow verifies Sigstore bundles, GitHub artifact attestations,
SBOMs, and checksums before publishing.

The security evidence keeps the complete Code Scanning alert count. Release
admission blocks open high or critical technical findings; Scorecard's
`CodeReviewID` and `CIIBestPracticesID` process checks remain visible in the
evidence but are not exploitable-code findings.

Tagged releases also require `SECURITY_AUDIT_REPORT.md` (or the path supplied by
`NETTRAP_EXTERNAL_AUDIT_REPORT`). `scripts/verify-external-audit.sh` rejects a
missing, undated, placeholder, or incomplete report before publication. This
gate deliberately fails until an independent auditor supplies the report; the
repository does not claim that audit has been performed.

## Acceptance Criteria

An independent review is complete only when the auditor provides a dated report
covering the scope above, severity-ranked findings, reproduction steps, and a
retest statement for every High or Critical finding. The report and remediation
commits must be linked from the release notes; automated green checks are not a
substitute for that review.
