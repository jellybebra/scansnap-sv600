#!/bin/sh
set -eu

project_root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
version=${VERSION:-0.1.0}
architecture=${ARCHITECTURE:-amd64}
sane_commit=${SANE_COMMIT:-6e4aebaa5ed77d47deaaf85067a8680252659df2}
vendor_dir=${SV600_VENDOR_DIR:-$project_root/vendor}
bookbound_sha256=9b1a74712985f8b39c6d8d382bbee9fbca9e21f5d60295ef60dcfb40acae2427
p2i_sha256=5c734ed79b29b2fd5805b96795bb4d15d8d8874f71ed9aad6d6e6094db6369c2
p2iatres_sha256=de7787c285a8b0d5f33dd1d98d895f371d1a98f77b151fb50a0f061ecb03c15b
i3ip_share_sha256=fcf411aa7abe756a78133ea9f21c2aef122b4e3a1b9fdca9411162d4e1158c0b
i3ip_common_sha256=560277036290cd406917623cb3ae593ef773624667999377828050e86d6309fc

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
    patches/0002-fujitsu-sv600-format-travel.patch \
    data/sv600-optical-map-deltas.inc \
    data/sv600-srgb-lut.inc \
    tools/windows/run_sv600_factory_pipeline.c \
    tools/windows/run_sv600_factory_resize.c \
    packaging/65-scansnap-sv600.rules \
    packaging/preinst packaging/postinst packaging/postrm
do
    if [ ! -f "$project_root/$required" ]; then
        echo "Missing project file: $required" >&2
        exit 2
    fi
done

for vendor_file in \
    bookbound.dll P2IDIGCROP.dll P2IATRES.DLL I3ipShare.dll I3ipCommon.dll
do
    if [ ! -f "$vendor_dir/$vendor_file" ]; then
        echo "Missing vendor runtime: $vendor_dir/$vendor_file" >&2
        exit 2
    fi
done

printf '%s  %s\n' "$bookbound_sha256" "$vendor_dir/bookbound.dll" |
    sha256sum --check --status
printf '%s  %s\n' "$p2i_sha256" "$vendor_dir/P2IDIGCROP.dll" |
    sha256sum --check --status
printf '%s  %s\n' "$p2iatres_sha256" "$vendor_dir/P2IATRES.DLL" |
    sha256sum --check --status
printf '%s  %s\n' "$i3ip_share_sha256" "$vendor_dir/I3ipShare.dll" |
    sha256sum --check --status
printf '%s  %s\n' "$i3ip_common_sha256" "$vendor_dir/I3ipCommon.dll" |
    sha256sum --check --status

build_root=$(mktemp -d)
trap 'rm -rf "$build_root"' EXIT INT TERM
source_dir="$build_root/sane-backends"
stage="$build_root/scansnap-sv600-sane"
output_dir="$project_root/dist"
package_file="$output_dir/scansnap-sv600-sane_${version}_${architecture}.deb"

git clone --filter=blob:none --no-checkout \
    https://gitlab.com/sane-project/backends.git "$source_dir"
git -C "$source_dir" checkout --detach "$sane_commit"
for patch_file in \
    0001-fujitsu-sv600-prepare-scan.patch \
    0002-fujitsu-sv600-format-travel.patch
do
    (
        cd "$source_dir"
        patch --batch --forward -p1 \
            < "$project_root/patches/$patch_file"
    )
done
install -m 0644 "$project_root/data/sv600-optical-map-deltas.inc" \
    "$source_dir/backend/sv600-optical-map-deltas.inc"
install -m 0644 "$project_root/data/sv600-srgb-lut.inc" \
    "$source_dir/backend/sv600-srgb-lut.inc"
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
    "$stage/usr/lib/scansnap-sv600" \
    "$stage/usr/lib/scansnap-sv600/i3ipCore" \
    "$stage/usr/share/doc/scansnap-sv600-sane"

i686-w64-mingw32-gcc -O2 -s \
    -o "$stage/usr/lib/scansnap-sv600/sv600-factory-pipeline.exe" \
    "$project_root/tools/windows/run_sv600_factory_pipeline.c"
i686-w64-mingw32-gcc -O2 -s \
    -o "$stage/usr/lib/scansnap-sv600/sv600-factory-resize.exe" \
    "$project_root/tools/windows/run_sv600_factory_resize.c"
install -m 0644 "$vendor_dir/bookbound.dll" \
    "$stage/usr/lib/scansnap-sv600/bookbound.dll"
install -m 0644 "$vendor_dir/P2IDIGCROP.dll" \
    "$stage/usr/lib/scansnap-sv600/P2IDIGCROP.dll"
install -m 0644 "$vendor_dir/P2IATRES.DLL" \
    "$stage/usr/lib/scansnap-sv600/P2IATRES.DLL"
install -m 0644 "$vendor_dir/I3ipShare.dll" \
    "$stage/usr/lib/scansnap-sv600/i3ipCore/I3ipShare.dll"
install -m 0644 "$vendor_dir/I3ipCommon.dll" \
    "$stage/usr/lib/scansnap-sv600/i3ipCore/I3ipCommon.dll"

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
Depends: libc6 (>= 2.28), libatomic1, libudev1, libusb-1.0-0, libsane1, udev, wine
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
