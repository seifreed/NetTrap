# Cross-Platform Builds

This document explains how to build NetTrap for different platforms and architectures.

## Supported Targets

### Linux
| Target | Architecture | Status |
|--------|-------------|--------|
| `x86_64-unknown-linux-gnu` | x64 | ✅ Production |
| `i686-unknown-linux-gnu` | x86 | ✅ Production |
| `aarch64-unknown-linux-gnu` | ARM64 | ✅ Production |
| `arm-unknown-linux-gnueabihf` | ARM | ✅ Production |

### macOS
| Target | Architecture | Status |
|--------|-------------|--------|
| `x86_64-apple-darwin` | Intel Mac | ✅ Production |
| `aarch64-apple-darwin` | Apple Silicon | ✅ Production |

### Windows
| Target | Architecture | Status |
|--------|-------------|--------|
| `x86_64-pc-windows-msvc` | x64 | ✅ Production |
| `i686-pc-windows-msvc` | x86 | ✅ Production |
| `aarch64-pc-windows-msvc` | ARM64 | ⚠️ Experimental (x64 emulation) |

## Building

### Linux x86_64 (Native)
```bash
# Install dependencies
sudo apt-get install -y libpcap-dev libnetfilter-queue-dev libnfnetlink-dev

# Build
cargo build --release --target x86_64-unknown-linux-gnu
```

### Linux ARM64 (Cross-compilation)
```bash
# Install cross-compilation toolchain
sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

# Add Rust target
rustup target add aarch64-unknown-linux-gnu

# Build
cargo build --release --target aarch64-unknown-linux-gnu
```

### Linux ARM (Cross-compilation)
```bash
# Install cross-compilation toolchain
sudo apt-get install -y gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf

# Add Rust target
rustup target add arm-unknown-linux-gnueabihf

# Build
cargo build --release --target arm-unknown-linux-gnueabihf
```

### macOS x86_64 (Intel)
```bash
# Install dependencies
brew install libpcap

# Build
cargo build --release --target x86_64-apple-darwin
```

### macOS ARM64 (Apple Silicon)
```bash
# Install dependencies
brew install libpcap

# Build
cargo build --release --target aarch64-apple-darwin
```

### Windows x86_64
```powershell
# Download WinDivert from https://reqrypt.org/windivert.html
# Extract and copy to windivert/ directory:
#   - WinDivert-2.2.2-A/x64/WinDivert.dll
#   - WinDivert-2.2.2-A/x64/WinDivert64.sys

# Build
cargo build --release --target x86_64-pc-windows-msvc
```

### Windows i686
```powershell
# Download WinDivert (x86 version)
# Extract and copy to windivert/ directory:
#   - WinDivert-2.2.2-A/x86/WinDivert.dll
#   - WinDivert-2.2.2-A/x86/WinDivert32.sys

# Add Rust target
rustup target add i686-pc-windows-msvc

# Build
cargo build --release --target i686-pc-windows-msvc
```

### Windows ARM64
```powershell
# Note: WinDivert doesn't have native ARM64 binaries
# Uses x64 binaries with emulation

# Add Rust target
rustup target add aarch64-pc-windows-msvc

# Build
cargo build --release --target aarch64-pc-windows-msvc
```

## Cross-Compilation with cross

For easier cross-compilation, you can use [cross](https://github.com/cross-rs/cross):

```bash
# Install cross
cargo install cross

# Build for ARM64 Linux
cross build --release --target aarch64-unknown-linux-gnu

# Build for ARM Linux
cross build --release --target arm-unknown-linux-gnueabihf

# Build for Windows x64
cross build --release --target x86_64-pc-windows-gnu
```

## Interceptor Support by Platform

| Platform | Interceptor | Packet Capture | Packet Modification | PID Tracking |
|----------|------------|----------------|---------------------|--------------|
| Linux x64/ARM | NFQUEUE | ✅ | ✅ | ✅ |
| Linux x64/ARM | PCAP | ✅ | ❌ | ❌ |
| macOS | PCAP | ✅ | ❌ | ❌ |
| Windows x64/x86 | WinDivert | ✅ | ✅ | ✅ |

## Dependencies by Platform

### Linux
- `libpcap-dev` - Packet capture
- `libnetfilter-queue-dev` - Kernel-level packet interception
- `libnfnetlink-dev` - Netlink communication

### macOS
- `libpcap` (via Homebrew) - Packet capture

### Windows
- `WinDivert.dll` - Kernel-level packet interception
- `WinDivert64.sys` or `WinDivert32.sys` - Kernel driver (must be signed)

## Distribution

Each release includes binary archives for all supported platforms:

```
nettrap-linux-x86_64.tar.gz      # Linux x64
nettrap-linux-i686.tar.gz       # Linux x86
nettrap-linux-aarch64.tar.gz     # Linux ARM64
nettrap-linux-arm.tar.gz         # Linux ARM
nettrap-macos-x86_64.tar.gz      # macOS Intel
nettrap-macos-aarch64.tar.gz     # macOS Apple Silicon
nettrap-windows-x86_64.zip       # Windows x64
nettrap-windows-i686.zip         # Windows x86
nettrap-windows-aarch64.zip      # Windows ARM64
```

Windows releases include `WinDivert.dll` in the archive.