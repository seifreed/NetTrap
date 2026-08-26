# Platform Support

This matrix applies to the `0.1.0-alpha.1` scope. Direct listener mode is the
primary supported execution mode. A release asset means the target is built by
the release workflow; it does not imply transparent interception support.

| Platform target | Release asset | Listener mode | Transparent redirection | Current CI contract |
|---|---|---|---|---|
| Linux x86_64 | Yes | Supported | Experimental `iptables`/`ip6tables` or direct `nft` redirection | Native Rust gates, Docker protocol E2E, and namespace interception E2E |
| Linux ARM64 | Yes | Supported | Experimental `iptables`/`ip6tables` or direct `nft` redirection | Native Rust build and tests |
| macOS x86_64 | Yes | Supported | Not supported | Native Rust gates plus `dig` and `curl` E2E |
| macOS ARM64 | Yes | Supported | Not supported | Native Rust gates plus `dig` and `curl` E2E |
| Windows x86_64 | Yes | Supported | Experimental bounded WinDivert NAT redirection | Native Rust gates, binary/config smoke, protocol matrix parity, listener parity, and interception smoke |
| Windows ARM64 | Yes | Supported | Not supported; Npcap capture is experimental | Native Rust gates, binary/config smoke, protocol matrix parity, and TCP/UDP listener parity smoke |
| Linux x86/ARM32 | No | Not supported | Not supported | No CI target or release asset |
| Windows x86 | No | Not supported | Not supported | No CI target or release asset |

## Mode Boundaries

- Listener mode binds configured TCP/UDP ports and emulates the selected
  service directly.
- Linux transparent redirection changes host firewall rules and requires
  privileges. It isolates redirects in dedicated NetTrap chains or the
  `nettrap` nftables table and removes stale managed state on the next startup.
  `iptables-nft` compatibility is supported through the system wrapper; direct
  nftables uses the same port and interface restrictions. The opt-in namespace
  contract runs as `NETTRAP_NAMESPACE_E2E=1` with root privileges on Linux.
- macOS has no transparent redirection implementation.
- Windows x86_64 `--intercept` uses a bounded packet-preserving NAT adapter and
  fails before opening the driver when no redirectable listener exists. It is
  experimental until a real Windows host validates connectivity, checksums,
  cleanup, and crash recovery. Release ZIP/MSI artifacts bundle the pinned
  WinDivert binaries and license text.
- Npcap is an external prerequisite for experimental live capture on Windows;
  it is not bundled.
- Process attribution, TLS termination, and live packet capture remain
  experimental on every platform.

Only targets listed with a release asset are packaged by `release.yml`.

## Tested Operating Systems

These are tested environments, not broader minimum-version claims. Platforms
outside this table may work but are unsupported until added to CI.

| Target | Required CI environment |
|---|---|
| Linux x86_64 | Current `ubuntu-latest` GitHub-hosted runner |
| Linux ARM64 | Ubuntu 24.04 ARM GitHub-hosted runner |
| macOS x86_64 | macOS 15 Intel GitHub-hosted runner |
| macOS ARM64 | macOS 14 ARM GitHub-hosted runner |
| Windows x86_64 | Current `windows-latest` GitHub-hosted runner; full redirect assertion requires a Windows host with WinDivert driver |
| Windows ARM64 | Windows 11 ARM GitHub-hosted runner |

## macOS Decision

macOS is listener and experimental capture only for the 1.0 scope. Transparent
redirection is not on the 1.0 roadmap. That decision changes only if a native
adapter is contributed with fail-open cleanup and privileged E2E coverage on
both Intel and ARM runners.
