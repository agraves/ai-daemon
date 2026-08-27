#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Build ai-daemon's pacman package from this checkout.
#
# makepkg wants a source tarball, and a checkout is not one, so this assembles
# the tarball the PKGBUILD names and then hands over. It is not a wrapper that
# does the build differently: everything after the tar is stock makepkg, which
# is what makes the resulting .pkg.tar.zst the same artifact a user building
# from the AUR would get.
#
#   ./packaging/arch/make-package.sh [makepkg args...]
#
# Runs as a normal user, like makepkg insists.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
pkgver="$(sed -n 's/^pkgver=//p' "$here/PKGBUILD")"
stage="$here/ai-daemon-$pkgver"

rm -rf "$stage" "$here/ai-daemon-$pkgver.tar.gz" "$here/src" "$here/pkg"
mkdir -p "$stage"

# Everything the build needs and nothing it does not. Excluding target/ matters
# more than it looks: a stale host-built target directory inside the tarball is
# how a package ends up shipping a binary nobody just compiled.
tar -C "$root" \
    --exclude='./target' \
    --exclude='./.git' \
    --exclude='./packaging/arch/ai-daemon-*' \
    --exclude='./packaging/arch/src' \
    --exclude='./packaging/arch/pkg' \
    --exclude='*.pkg.tar.zst' \
    -cf - . | tar -C "$stage" -xf -

tar -C "$here" -czf "$here/ai-daemon-$pkgver.tar.gz" "ai-daemon-$pkgver"
rm -rf "$stage"

cd "$here"
exec makepkg --force --noconfirm "$@"
