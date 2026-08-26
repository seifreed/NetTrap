# Release Verification

Every NetTrap release archive, raw platform binary, Linux package, Windows MSI,
checksum, SBOM, formula, and deployment metadata has a keyless Sigstore bundle.
Release binaries and packages also have a GitHub artifact attestation and an SBOM attestation. The
draft release is not published unless the workflow verifies every raw `.binary`,
Linux/macOS `.tar.gz`, Linux `.deb`/`.rpm`, and Windows `.zip`/`.msi` against this
repository. A Homebrew formula is generated from the checksums for the four
macOS/Linux tarballs.

Verify a downloaded archive or `.binary` executable with:

```bash
gh attestation verify nettrap-linux-x86_64.tar.gz --repo seifreed/NetTrap
sha256sum --check SHA256SUMS
cosign verify-blob \
  --bundle nettrap-linux-x86_64.tar.gz.sigstore.json \
  --certificate-identity \
  "https://github.com/seifreed/NetTrap/.github/workflows/release.yml@refs/tags/v0.1.0-alpha.1" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  nettrap-linux-x86_64.tar.gz
```

To verify every downloaded release asset and metadata file in one pass, set the
workflow identity and run the repository verifier from the release directory:

```bash
COSIGN_CERTIFICATE_IDENTITY="https://github.com/seifreed/NetTrap/.github/workflows/release.yml@refs/tags/v0.1.0-alpha.1" \
  scripts/verify-release-signatures.sh releases
```

Use the corresponding archive or raw `.binary` name on macOS or Windows. The attestation binds
the archive digest to the GitHub Actions release workflow and commit; the
checksum detects local corruption and is also published as a release asset.

The bundle signature covers the downloaded release artifact. Individual
executables inside the published packages are hash-checked against the
corresponding signed raw `.binary` before release publication. Releases with
the repository variable `NETTRAP_NATIVE_SIGNING=1` additionally sign Windows
executables with Authenticode and macOS executables with Developer ID; the
required PFX/P12 identities stay in GitHub Actions secrets. Without that
variable, platform-native signatures are intentionally omitted and must not be
inferred from the artifact signature.
