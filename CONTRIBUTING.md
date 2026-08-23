# Contributing to NetTrap

## Before Opening Work

- Use GitHub Issues for bugs and scoped feature proposals.
- Report vulnerabilities through the private process in [SECURITY.md](SECURITY.md).
- Keep production behavior sample-agnostic. Real malware and private captures must
  not be committed or required by the default test suite.

## Development

NetTrap requires Rust 1.85 or newer. From the workspace root:

```bash
cargo build
./scripts/quality-gates.sh quick
```

Add a focused regression test for behavior changes and bug fixes. Use the full
gate for dependency upgrades, parser or interception changes, large refactors,
release work, and performance-sensitive changes:

```bash
./scripts/quality-gates.sh full
```

Platform interception changes also require:

```bash
bash tests/verify_platform.sh
```

If a gate cannot run because the host lacks a driver or tool, state the exact
missing dependency and the nearest validation that did run in the pull request.

## Pull Requests

- Keep each pull request focused and avoid unrelated refactors.
- Preserve the Clean Architecture boundaries described in `AGENTS.md`.
- Update fixtures, support matrices, and public documentation when behavior changes.
- Use a short imperative commit subject, such as `Fix DNS response truncation`.
- Complete the pull request checklist and confirm that no sensitive captures,
  credentials, generated archives, or local driver binaries are included.

By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
