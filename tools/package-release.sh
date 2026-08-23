#!/usr/bin/env bash
# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.
#
# Package built binaries into release archives with checksums.
#
#   tools/package-release.sh <version> <linux-build-dir> <windows-build-dir> <out-dir>
#
# Both build directories are optional in the sense that a missing one is
# skipped with a warning rather than failing: a Linux-only release is still a
# release. What is not optional is the checksum file -- a download nobody can
# verify is a download nobody should run.

set -euo pipefail

VERSION=${1:?usage: package-release.sh <version> <linux-build> <win-build> <out-dir>}
LINUX_BUILD=${2:-}
WIN_BUILD=${3:-}
OUT=${4:?output directory required}

BINARIES=(latticad lattica-cli lattica-tx lattica-util lattica-wallet lattica-miner lattica-qt)
# Built only where their dependency was found, so their absence is a fact about
# the build machine and not a defect in the release: packaged when present,
# passed over in silence when not. lattica-qt is not among them -- a release
# without the GUI is a release someone should be told about.
OPTIONAL_BINARIES=(lattica-miner-gpu)
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

mkdir -p "$OUT"
rm -f "$OUT/SHA256SUMS"

stage_common() {
    local dir=$1
    install -m 644 "$REPO_ROOT/README.md" "$dir/"
    install -m 644 "$REPO_ROOT/COPYING"   "$dir/"
    install -m 644 "$REPO_ROOT/SECURITY.md" "$dir/"
}

# ---------------------------------------------------------------- Linux
if [[ -n $LINUX_BUILD && -d $LINUX_BUILD ]]; then
    NAME="lattica-$VERSION-x86_64-linux-gnu"
    WORK=$(mktemp -d)
    mkdir -p "$WORK/$NAME/bin"
    missing=()
    for b in "${BINARIES[@]}"; do
        if [[ -f "$LINUX_BUILD/$b" ]]; then
            install -m 755 "$LINUX_BUILD/$b" "$WORK/$NAME/bin/"
        else
            missing+=("$b")
        fi
    done
    for b in "${OPTIONAL_BINARIES[@]}"; do
        [[ -f "$LINUX_BUILD/$b" ]] && install -m 755 "$LINUX_BUILD/$b" "$WORK/$NAME/bin/"
    done
    [[ ${#missing[@]} -gt 0 ]] && echo "warning: linux archive is missing ${missing[*]}" >&2
    stage_common "$WORK/$NAME"
    tar -C "$WORK" --owner=0 --group=0 --numeric-owner \
        --mtime="@$(git -C "$REPO_ROOT" log -1 --format=%ct)" \
        -czf "$OUT/$NAME.tar.gz" "$NAME"
    rm -rf "$WORK"
    echo "  $NAME.tar.gz"
else
    echo "warning: no Linux build directory, skipping" >&2
fi

# -------------------------------------------------------------- Windows
if [[ -n $WIN_BUILD && -d $WIN_BUILD ]]; then
    NAME="lattica-$VERSION-win64"
    WORK=$(mktemp -d)
    mkdir -p "$WORK/$NAME"
    missing=()
    for b in "${BINARIES[@]}"; do
        if [[ -f "$WIN_BUILD/$b.exe" ]]; then
            install -m 755 "$WIN_BUILD/$b.exe" "$WORK/$NAME/"
        else
            missing+=("$b.exe")
        fi
    done
    for b in "${OPTIONAL_BINARIES[@]}"; do
        [[ -f "$WIN_BUILD/$b.exe" ]] && install -m 755 "$WIN_BUILD/$b.exe" "$WORK/$NAME/"
    done
    [[ ${#missing[@]} -gt 0 ]] && echo "warning: windows archive is missing ${missing[*]}" >&2
    stage_common "$WORK/$NAME"
    (cd "$WORK" && zip -qr9X "$OUT/$NAME.zip" "$NAME")
    rm -rf "$WORK"
    echo "  $NAME.zip"
else
    echo "warning: no Windows build directory, skipping" >&2
fi

# ------------------------------------------------------------- checksums
# nullglob, so a release with only one of the two archives still gets sums
# rather than dying on an unexpanded glob just before the step that matters.
(
    cd "$OUT"
    shopt -s nullglob
    archives=(*.tar.gz *.zip)
    if [[ ${#archives[@]} -eq 0 ]]; then
        echo "error: nothing was packaged" >&2
        exit 1
    fi
    sha256sum "${archives[@]}" > SHA256SUMS
)
echo
echo "SHA256SUMS:"
sed 's/^/  /' "$OUT/SHA256SUMS"
