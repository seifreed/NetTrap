# Platform Support

This matrix applies to the `0.1.0-alpha.1` scope. Direct listener mode is the
primary supported execution mode. A release asset means the target is built by
the release workflow; it does not imply transparent interception support.

| Platform target | Release asset | Listener mode | Transparent redirection | Current CI contract |
|---|---|---|---|---|
| Linux x86_64 | Yes | Supported | Experimental `iptables`/`ip6tables` redirection | Native Rust gates and Docker DNS/HTTP E2E |
| Linux ARM64 | Yes | Supported | Experimental `iptables`/`ip6tables` redirection | Native Rust build and tests |
| macOS x86_64 | Yes | Supported | Not supported | Native Rust gates plus `dig` and `curl` E2E |
| macOS ARM64 | Yes | Supported | Not supported | Native Rust gates plus `dig` and `curl` E2E |
| Windows x86_64 | Yes | Supported | Disabled; `--intercept` fails closed | Native Rust gates and binary/config smoke tests |
| Windows ARM64 | Yes | Supported | Not supported; Npcap capture is experimental | Native Rust gates and binary/config smoke tests |
| Linux x86/ARM32 | No | Not supported | Not supported | No CI target or release asset |
| Windows x86 | No | Not supported | Not supported | No CI target or release asset |

## Mode Boundaries

- Listener mode binds configured TCP/UDP ports and emulates the selected
  service directly.
- Linux transparent redirection changes host firewall rules and requires
  privileges. It remains experimental until dedicated chains, crash recovery,
  and network-namespace E2E are in place.
- macOS has no transparent redirection implementation.
- Windows rejects `--intercept`. Release archives do not include WinDivert
  binaries or drivers.
- Npcap is an external prerequisite for experimental live capture on Windows;
  it is not bundled.
- Process attribution, TLS termination, and live packet capture remain
  experimental on every platform.

Only targets listed with a release asset are packaged by `release.yml`.
