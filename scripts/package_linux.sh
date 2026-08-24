#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
    echo "usage: $0 <binary> <release-name> <version> <deb-arch> <rpm-arch>" >&2
    exit 2
fi

binary=$1
release_name=$2
raw_version=$3
deb_arch=$4
rpm_arch=$5

[[ -x "$binary" ]] || {
    echo "release binary is not executable: $binary" >&2
    exit 1
}
[[ "$release_name" =~ ^[a-z0-9._-]+$ ]] || {
    echo "invalid release name: $release_name" >&2
    exit 1
}
[[ "$deb_arch" =~ ^[a-z0-9]+$ && "$rpm_arch" =~ ^[a-z0-9_]+$ ]] || {
    echo "invalid package architecture" >&2
    exit 1
}

version=${raw_version#v}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.]+)?$ ]] || {
    echo "invalid release version: $raw_version" >&2
    exit 1
}

deb_version=$(printf '%s' "$version" | sed 's/-/~/')
rpm_version=${version%%-*}
rpm_release=1
if [[ "$version" == *-* ]]; then
    rpm_release="1.${version#*-}"
fi
rpm_release=${rpm_release//[^0-9A-Za-z.]/.}

output_dir=$PWD
root_dir=$(mktemp -d)
trap 'rm -rf "$root_dir"' EXIT
stage="$root_dir/stage"
doc_dir="$stage/usr/share/doc/nettrap"
created=0

install -Dm755 "$binary" "$stage/usr/bin/nettrap"
mkdir -p "$stage/etc/nettrap" "$doc_dir"
"$binary" config --defaults > "$stage/etc/nettrap/config.toml"
chmod 0644 "$stage/etc/nettrap/config.toml"

for document in LICENSE README.md CHANGELOG.md SECURITY.md KNOWN_LIMITATIONS.md \
    THIRD_PARTY_NOTICES.md PLATFORM_SUPPORT.md PROTOCOL_SUPPORT.md; do
    install -Dm644 "$document" "$doc_dir/$document"
done

if command -v dpkg-deb >/dev/null 2>&1; then
    deb_root="$root_dir/deb"
    cp -a "$stage" "$deb_root"
    mkdir -p "$deb_root/DEBIAN"
    cat > "$deb_root/DEBIAN/control" <<EOF
Package: nettrap
Version: $deb_version
Section: net
Priority: optional
Architecture: $deb_arch
Maintainer: NetTrap contributors <nettrap@seifreed.dev>
Description: Network interception, emulation, and deception engine
 NetTrap provides direct listener-mode service emulation and behavioral capture.
EOF
    dpkg-deb --build --root-owner-group "$deb_root" \
        "$output_dir/nettrap-${release_name}.deb" >/dev/null
    created=$((created + 1))
fi

if command -v rpmbuild >/dev/null 2>&1; then
    rpm_top="$root_dir/rpm"
    mkdir -p "$rpm_top"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    tar -C "$root_dir" -czf "$rpm_top/SOURCES/nettrap-stage.tar.gz" stage
    cat > "$rpm_top/SPECS/nettrap.spec" <<EOF
Name: nettrap
Version: $rpm_version
Release: $rpm_release
Summary: Network interception, emulation, and deception engine
License: MIT
URL: https://github.com/seifreed/NetTrap
Source0: nettrap-stage.tar.gz
BuildArch: $rpm_arch

%description
NetTrap provides direct listener-mode service emulation and behavioral capture.

%prep
%setup -q -n stage

%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/etc/nettrap %{buildroot}/usr/share/doc/nettrap
install -m 0755 usr/bin/nettrap %{buildroot}/usr/bin/nettrap
install -m 0644 etc/nettrap/config.toml %{buildroot}/etc/nettrap/config.toml
cp -a usr/share/doc/nettrap/. %{buildroot}/usr/share/doc/nettrap/

%files
/usr/bin/nettrap
%config(noreplace) /etc/nettrap/config.toml
%doc /usr/share/doc/nettrap/*
EOF
    rpmbuild --define "_topdir $rpm_top" --define "_rpmdir $output_dir" \
        -bb "$rpm_top/SPECS/nettrap.spec" >/dev/null
    rpm_file=$(find "$output_dir/$rpm_arch" -type f -name '*.rpm' -print -quit)
    [[ -n "$rpm_file" ]] || {
        echo "rpmbuild did not produce an RPM" >&2
        exit 1
    }
    mv "$rpm_file" "$output_dir/nettrap-${release_name}.rpm"
    rm -rf "${output_dir:?}/$rpm_arch"
    created=$((created + 1))
fi

((created > 0)) || {
    echo "neither dpkg-deb nor rpmbuild is installed" >&2
    exit 1
}

for archive in "$output_dir/nettrap-${release_name}.deb" "$output_dir/nettrap-${release_name}.rpm"; do
    if [[ -e "$archive" ]]; then
        printf 'Created %s\n' "$archive"
    fi
done
