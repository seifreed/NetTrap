# Third-Party Notices

NetTrap is licensed under the MIT License. It also uses third-party software
under its respective licenses.

## Rust Dependencies

The exact dependency set is locked in `Cargo.lock`. `cargo deny check` enforces
the repository license policy. Every release publishes an SPDX SBOM containing
the package versions and declared license identifiers; that SBOM is the
authoritative dependency inventory for the corresponding artifact.

## Optional External Components Not Bundled

These components are not bundled in NetTrap release archives:

- **mkcert** is optionally downloaded or invoked by the TLS setup command. It is
  distributed under the BSD 3-Clause License. Source and license:
  <https://github.com/FiloSottile/mkcert>.
- **Npcap** is an external Windows packet-capture prerequisite. The free/demo
  installer is not redistributable with NetTrap; redistribution requires the
  appropriate Npcap OEM rights. Terms: <https://npcap.com/oem/>.
## Bundled Windows x86_64 Component

- **WinDivert** DLL and `WinDivert64.sys` are bundled only in Windows x86_64
  release ZIP/MSI artifacts for the experimental NAT interception path. The
  matching `WinDivert-LICENSE.txt` file is included in those artifacts. WinDivert
  is available under the GNU LGPL. Project and terms:
  <https://reqrypt.org/windivert.html>.

## System Libraries

Linux and macOS builds may dynamically use system-provided `libpcap` and Linux
netfilter libraries. They are installed and licensed by the host operating
system or container base image and are not included in NetTrap binary archives.

No Npcap installer or mkcert binary is included in a NetTrap release. Windows
ARM64 releases do not include WinDivert because that architecture uses the
Npcap capture-only path.
