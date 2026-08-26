#!/bin/sh
set -eu

project_root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
version=${VERSION:-0.1.0}
architecture=${ARCHITECTURE:-amd64}
sane_commit=${SANE_COMMIT:-6e4aebaa5ed77d47deaaf85067a8680252659df2}

case "$version" in
    *[!0-9A-Za-z.+:~-]*|'')
        echo "Invalid Debian version: $version" >&2
        exit 2
        ;;
esac

if [ "$architecture" != amd64 ]; then
    echo "Only amd64 is currently supported" >&2
    exit 2
fi

for required in \
    patches/0001-fujitsu-sv600-prepare-scan.patch \
    packaging/65-scansnap-sv600.rules \
    packaging/preinst packaging/postinst packaging/postrm
do
    if [ ! -f "$project_root/$required" ]; then
        echo "Missing project file: $required" >&2
        exit 2
    fi
done

build_root=$(mktemp -d)
trap 'rm -rf "$build_root"' EXIT INT TERM
source_dir="$build_root/sane-backends"
stage="$build_root/scansnap-sv600-sane"
output_dir="$project_root/dist"
package_file="$output_dir/scansnap-sv600-sane_${version}_${architecture}.deb"

git clone --filter=blob:none --no-checkout \
    https://gitlab.com/sane-project/backends.git "$source_dir"
git -C "$source_dir" checkout --detach "$sane_commit"
git -C "$source_dir" apply --unidiff-zero \
    "$project_root/patches/0001-fujitsu-sv600-prepare-scan.patch"
git -C "$source_dir" diff --check

(
    cd "$source_dir"
    ./autogen.sh
    ./configure \
        --prefix=/usr \
        --libdir=/usr/lib/x86_64-linux-gnu \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --without-usb-record-replay \
        --without-libjpeg \
        --without-libtiff \
        --without-libpng \
        --without-snmp \
        --without-avahi \
        --without-libcurl \
        BACKENDS=fujitsu
    make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
)

backend=$(find "$source_dir/backend/.libs" -maxdepth 1 -type f \
    -name 'libsane-fujitsu.so.*' | sort -V | tail -n 1)
if [ -z "$backend" ] || [ ! -s "$backend" ]; then
    echo "Built Fujitsu backend was not found" >&2
    exit 1
fi

install -d \
    "$stage/DEBIAN" \
    "$stage/etc/udev/rules.d" \
    "$stage/usr/lib/x86_64-linux-gnu/sane" \
    "$stage/usr/share/doc/scansnap-sv600-sane"

install -m 0755 "$project_root/packaging/preinst" "$stage/DEBIAN/preinst"
install -m 0755 "$project_root/packaging/postinst" "$stage/DEBIAN/postinst"
install -m 0755 "$project_root/packaging/postrm" "$stage/DEBIAN/postrm"
install -m 0644 "$project_root/packaging/65-scansnap-sv600.rules" \
    "$stage/etc/udev/rules.d/65-scansnap-sv600.rules"
install -m 0644 "$backend" \
    "$stage/usr/lib/x86_64-linux-gnu/sane/libsane-sv600-fujitsu.so.1"
install -m 0644 "$project_root/README.md" \
    "$stage/usr/share/doc/scansnap-sv600-sane/README.md"

cat >"$stage/DEBIAN/control" <<EOF
Package: scansnap-sv600-sane
Version: $version
Section: graphics
Priority: optional
Architecture: $architecture
Maintainer: ScanSnap SV600 Linux project <noreply@example.invalid>
Depends: libc6 (>= 2.28), libatomic1, libudev1, libusb-1.0-0, libsane1, udev
Recommends: simple-scan
Description: SANE support for the Fujitsu ScanSnap SV600
 Installs an Astra-compatible patched Fujitsu SANE backend and USB access
 rules for the ScanSnap SV600 scanner (04c5:128e) and camera (04c5:13ba).
 The scanner remains available to standard SANE graphical applications.
EOF

mkdir -p "$output_dir"
rm -f "$package_file"
dpkg-deb --root-owner-group --build "$stage" "$package_file"
echo "$package_file"
