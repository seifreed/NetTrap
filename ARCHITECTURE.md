# Architecture Support

This document details architecture-specific considerations for NetTrap.

## Supported Architectures

### Linux

| Architecture | Rust Target | NFQUEUE | PCAP | Notes |
|-------------|-------------|---------|------|-------|
| x86_64 | `x86_64-unknown-linux-gnu` | ✅ | ✅ | Primary target |
| i686 | `i686-unknown-linux-gnu` | ✅ | ✅ | 32-bit Intel/AMD |
| ARM64 | `aarch64-unknown-linux-gnu` | ✅ | ✅ | Raspberry Pi 4, servers |
| ARM | `arm-unknown-linux-gnueabihf` | ✅ | ✅ | Raspberry Pi, IoT |

#### Building on Linux

```bash
# Install dependencies
sudo apt-get install -y \
    libpcap-dev \
    libnetfilter-queue-dev \
    libnfnetlink-dev \
    build-essential

# For ARM cross-compilation
sudo apt-get install -y \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    gcc-arm-linux-gnueabihf \
    g++-arm-linux-gnueabihf

# Build native
cargo build --release

# Build for ARM64
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu

# Build for ARM
rustup target add arm-unknown-linux-gnueabihf
cargo build --release --target arm-unknown-linux-gnueabihf
```

#### Kernel Requirements for NFQUEUE

NFQUEUE requires kernel support:

```bash
# Check NFQUEUE kernel module
lsmod | grep nfnetlink_queue

# Load module if not present (requires root)
sudo modprobe nfnetlink_queue

# Kernel config options needed
CONFIG_NETFILTER=y
CONFIG_NETFILTER_NETLINK=y
CONFIG_NETFILTER_NETLINK_QUEUE=y
CONFIG_NF_CONNTRACK=y
```

### macOS

| Architecture | Rust Target | PCAP | Notes |
|-------------|-------------|------|-------|
| x86_64 | `x86_64-apple-darwin` | ✅ | Intel Macs |
| ARM64 | `aarch64-apple-darwin` | ✅ | M1/M2/M3 Macs |

#### Building on macOS

```bash
# Install dependencies
brew install libpcap

# Build native
cargo build --release

# Cross-compile to other macOS arch
rustup target add x86_64-apple-darwin  # On M1/M2/M3
rustup target add aarch64-apple-darwin  # On Intel Mac

cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin
```

#### macOS Permissions

macOS requires permissions for packet capture:

```bash
# Run with privileges
sudo ./target/release/nettrap run -c config.toml

# Or grant permissions in System Preferences
# Security & Privacy -> Privacy -> Full Disk Access
```

### Windows

| Architecture | Rust Target | WinDivert | Notes |
|-------------|-------------|-----------|-------|
| x86_64 | `x86_64-pc-windows-msvc` | ✅ | 64-bit Intel/AMD |
| i686 | `i686-pc-windows-msvc` | ✅ | 32-bit Intel/AMD |
| ARM64 | `aarch64-pc-windows-msvc` | ⚠️ | x64 emulation |

#### WinDivert Notes

**Windows x86_64 and i686:**
- Full support with native WinDivert driver
- Driver is signed with WHQL certificate
- No special permissions needed beyond Administrator

**Windows ARM64:**
- WinDivert doesn't have native ARM64 binaries
- Uses x64 binaries with emulation
- Performance is reduced due to emulation
- Some features may not work correctly

#### Building on Windows

```powershell
# Download WinDivert
Invoke-WebRequest -Uri "https://reqrypt.org/download/WinDivert-2.2.2-A.zip" -OutFile "WinDivert.zip"
Expand-Archive -Path "WinDivert.zip" -DestinationPath "WinDivert"

# Copy DLLs
Copy-Item "WinDivert/WinDivert-2.2.2-A/x64/WinDivert.dll" -Destination "target/release/"
Copy-Item "WinDivert/WinDivert-2.2.2-A/x64/WinDivert64.sys" -Destination "target/release/"

# Build
cargo build --release

# Run as Administrator
.\target\release\nettrap.exe run -c config.toml
```

#### ARM64 Considerations

For Windows on ARM:

```powershell
# Use x64 binaries (emulated)
Copy-Item "WinDivert/WinDivert-2.2.2-A/x64/WinDivert.dll" -Destination "target/release/"
Copy-Item "WinDivert/WinDivert-2.2.2-A/x64/WinDivert64.sys" -Destination "target/release/"

# Build with ARM64 target
rustup target add aarch64-pc-windows-msvc
cargo build --release --target aarch64-pc-windows-msvc
```

## Architecture-Specific Behavior

### Endianness

All code uses explicit endianness conversions:

```rust
// Correct - explicit endianness
let port = u16::from_be_bytes([data[0], data[1]]);

// Incorrect - architecture dependent
let port = u16::from_ne_bytes([data[0], data[1]]);
```

### Pointer Size

The code does not assume any particular pointer size:

```rust
// Correct - works on 32-bit and 64-bit
let len = data.len(); // usize

// Avoid - architecture specific
let len = data.len() as u64; // May truncate on 32-bit
```

### Atomic Operations

All atomic operations use portable types:

```rust
use std::sync::atomic::{AtomicUsize, Ordering};
// or
use parking_lot::RwLock;
```

## Performance Considerations

### Linux ARM (32-bit)

- Limited memory (2-4GB addressable)
- Use `opt-level = 2` instead of `3` to reduce binary size
- Consider disabling some protocol handlers

### Windows ARM64 (Emulation)

- 20-30% performance penalty due to emulation
- Packet capture may have higher latency
- Consider using PCAP mode for lower overhead

### macOS Apple Silicon

- Native performance is excellent
- PCAP capture works at near-wire speed
- No special considerations needed

## Testing on Different Architectures

### Using QEMU for ARM Testing

```bash
# Install QEMU
sudo apt-get install -y qemu-user qemu-user-static

# Test ARM binary
qemu-arm -L /usr/arm-linux-gnueabihf ./target/arm-unknown-linux-gnueabihf/release/nettrap --version

# Test ARM64 binary
qemu-aarch64 -L /usr/aarch64-linux-gnu ./target/aarch64-unknown-linux-gnu/release/nettrap --version
```

### Using Docker for Cross-Architecture Testing

```bash
# Build for different architectures
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t nettrap-multiarch .

# Run specific architecture
docker run --rm --platform linux/arm64 nettrap-multiarch ./nettrap --version
```

## CI/CD Pipeline

The GitHub Actions workflow tests on:

1. **Linux x86_64** - Full test suite including NFQUEUE and PCAP
2. **Linux i686** - Build verification
3. **Linux ARM64** - Build verification (cross-compiled)
4. **Linux ARM** - Build verification (cross-compiled)
5. **macOS Intel** - Full test suite with PCAP
6. **macOS Apple Silicon** - Full test suite with PCAP
7. **Windows x86_64** - Full test suite with WinDivert
8. **Windows i686** - Build verification with WinDivert
9. **Windows ARM64** - Build verification (x64 emulation)

Each platform/architecture combination builds and tests independently.

## Known Limitations

| Platform | Architecture | Limitation |
|----------|-------------|------------|
| Linux | ARM | May need swap file for large captures |
| macOS | Any | Requires root for promiscuous mode |
| Windows | ARM64 | WinDivert uses x64 emulation, reduced performance |
| Windows | Any | Requires Administrator privileges |
| All | 32-bit | Limited addressable memory |