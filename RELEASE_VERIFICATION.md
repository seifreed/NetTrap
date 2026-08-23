# Release Verification

Every NetTrap release archive is covered by a GitHub artifact attestation and
an SBOM attestation. The draft release is not published unless GitHub CLI can
verify every Linux/macOS `.tar.gz` and Windows `.zip` against this repository.

Verify a downloaded archive with:

```bash
gh attestation verify nettrap-linux-x64.tar.gz --repo seifreed/NetTrap
sha256sum --check SHA256SUMS
```

Use the corresponding archive name on macOS or Windows. The attestation binds
the archive digest to the GitHub Actions release workflow and commit; the
checksum detects local corruption and is also published as a release asset.

The archives are keylessly signed through GitHub's Sigstore-backed attestation
service. Individual executables are not currently Authenticode-signed or Apple
Developer ID-signed. Those platform signatures require externally managed
signing identities and must not be inferred from the archive attestation.
