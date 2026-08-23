# Third-Party Notices

NetTrap is licensed under the MIT License. It also uses third-party software
under its respective licenses.

## Rust Dependencies

The exact dependency set is locked in `Cargo.lock`. `cargo deny check` enforces
the repository license policy. Every release publishes an SPDX SBOM containing
the package versions and declared license identifiers; that SBOM is the
authoritative dependency inventory for the corresponding artifact.

## Optional External Components

These components are not bundled in NetTrap release archives:

- **mkcert** is optionally downloaded or invoked by the TLS setup command. It is
  distributed under the BSD 3-Clause License. Source and license:
  <https://github.com/FiloSottile/mkcert>.
- **Npcap** is an external Windows packet-capture prerequisite. The free/demo
  installer is not redistributable with NetTrap; redistribution requires the
  appropriate Npcap OEM rights. Terms: <https://npcap.com/oem/>.
- **WinDivert** adapter source remains in the workspace for future development,
  but NetTrap releases do not ship its DLL or driver and Windows interception is
  disabled. WinDivert is available under the GNU LGPL. Project and terms:
  <https://reqrypt.org/windivert.html>.

## System Libraries

Linux and macOS builds may dynamically use system-provided `libpcap` and Linux
netfilter libraries. They are installed and licensed by the host operating
system or container base image and are not included in NetTrap binary archives.

No Npcap installer, WinDivert binary/driver, or mkcert binary is included in a
NetTrap release unless a future release notice explicitly says otherwise.
