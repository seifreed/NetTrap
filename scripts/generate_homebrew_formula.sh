#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <release-tag> <checksums-file> <output>" >&2
    exit 2
fi

tag=$1
checksums=$2
output=$3
version=${tag#v}
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.]+)?$ ]] || {
    echo "invalid release tag: $tag" >&2
    exit 1
}

checksum_for() {
    awk -v asset="$1" '$2 ~ ("/" asset "$|^" asset "$") { print $1; exit }' "$checksums"
}

for asset in nettrap-macos-x86_64.tar.gz nettrap-macos-aarch64.tar.gz \
    nettrap-linux-x86_64.tar.gz nettrap-linux-aarch64.tar.gz; do
    [[ "$(checksum_for "$asset")" =~ ^[0-9a-f]{64}$ ]] || {
        echo "missing checksum for Homebrew asset: $asset" >&2
        exit 1
    }
done

macos_intel=$(checksum_for nettrap-macos-x86_64.tar.gz)
macos_arm=$(checksum_for nettrap-macos-aarch64.tar.gz)
linux_intel=$(checksum_for nettrap-linux-x86_64.tar.gz)
linux_arm=$(checksum_for nettrap-linux-aarch64.tar.gz)

cat > "$output" <<EOF
class Nettrap < Formula
  desc "Network interception, emulation, and deception engine"
  homepage "https://github.com/seifreed/NetTrap"
  version "$version"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/seifreed/NetTrap/releases/download/$tag/nettrap-macos-x86_64.tar.gz"
      sha256 "$macos_intel"
    else
      url "https://github.com/seifreed/NetTrap/releases/download/$tag/nettrap-macos-aarch64.tar.gz"
      sha256 "$macos_arm"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/seifreed/NetTrap/releases/download/$tag/nettrap-linux-x86_64.tar.gz"
      sha256 "$linux_intel"
    else
      url "https://github.com/seifreed/NetTrap/releases/download/$tag/nettrap-linux-aarch64.tar.gz"
      sha256 "$linux_arm"
    end
  end

  def install
    bin.install "nettrap"
    (etc/"nettrap").install "config.toml"
  end

  test do
    assert_match "nettrap", shell_output("#{bin}/nettrap --version")
  end
end
EOF
