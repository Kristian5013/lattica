#!/usr/bin/env bash
# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.
#
# Build the Lattica Windows installer (msys2/mingw64).
#
#   1. Stages a self-contained runtime bundle:
#        - the 5 binaries (lattica-qt, latticad, lattica-cli, lattica-tx,
#          lattica-wallet)
#        - the Qt6 runtime + plugins via windeployqt6
#        - the full mingw/3rd-party DLL closure (sqlite/zmq/icu/freetype/... and
#          the libgcc/libstdc++/libwinpthread runtime), gathered from `ldd`
#   2. Runs makensis on share/setup.nsi to produce
#        dist/lattica-<version>-win64-setup.exe
#
# Everything is staged into an ASCII WORKDIR first: makensis (like moc/lupdate)
# cannot handle non-ASCII characters in the source path, so the inputs are
# copied to a plain-ASCII working directory and the finished installer is
# copied back to dist/.
#
# The build dir must already be built (cmake --build <BUILDDIR> -DENABLE_GUI=ON).
# Env overrides: BUILDDIR, MINGW_BIN, MAKENSIS, WORKDIR.
set -euo pipefail

TOPDIR=${TOPDIR:-$(git rev-parse --show-toplevel)}
BUILDDIR=${BUILDDIR:-$TOPDIR/build-gui}
MINGW_BIN=${MINGW_BIN:-/c/msys64/mingw64/bin}
MAKENSIS=${MAKENSIS:-$MINGW_BIN/makensis.exe}
WORKDIR=${WORKDIR:-/c/Users/$(whoami)/AppData/Local/Temp/lattica-inst}

WINDEPLOYQT="$MINGW_BIN/windeployqt6.exe"
QT_EXE="$BUILDDIR/lattica-qt.exe"
DIST="$WORKDIR/dist/Lattica"

[ -x "$QT_EXE" ] || { echo "lattica-qt.exe not found at $QT_EXE — build with -DENABLE_GUI=ON first."; exit 1; }
[ -x "$WINDEPLOYQT" ] || { echo "windeployqt6 not found at $WINDEPLOYQT"; exit 1; }

echo ">> preparing ASCII workdir $WORKDIR"
rm -rf "$WORKDIR"
mkdir -p "$DIST" "$WORKDIR/share/pixmaps" "$WORKDIR/share/examples" "$WORKDIR/doc"
# installer inputs (paths inside setup.nsi are relative to share/). The .nsi is
# generated from share/setup.nsi.in by CMake's generate_setup_nsi() (name +
# version filled), so take it from the build dir.
GENERATED_NSI="$BUILDDIR/lattica-win64-setup.nsi"
[ -f "$GENERATED_NSI" ] || { echo "$GENERATED_NSI not found — configure the build first (cmake -S . -B $BUILDDIR)."; exit 1; }
cp "$GENERATED_NSI" "$WORKDIR/share/setup.nsi"
cp "$TOPDIR/share/pixmaps/lattica.ico" "$TOPDIR/share/pixmaps/nsis-header.bmp" "$TOPDIR/share/pixmaps/nsis-wizard.bmp" "$WORKDIR/share/pixmaps/"
cp "$TOPDIR/share/examples/lattica.conf" "$WORKDIR/share/examples/"
cp "$TOPDIR/doc/README_windows.txt" "$WORKDIR/doc/"

echo ">> staging binaries"
cp "$QT_EXE" "$DIST/"
for b in latticad lattica-cli lattica-tx lattica-wallet; do
    cp "$BUILDDIR/$b.exe" "$DIST/"
done

echo ">> windeployqt6 (Qt DLLs + plugins)"
"$WINDEPLOYQT" --release --compiler-runtime --no-translations \
    --no-system-d3d-compiler --no-opengl-sw "$DIST/lattica-qt.exe" >/dev/null

echo ">> gathering the full DLL closure (ldd over every binary + plugin)"
{
    for f in "$DIST"/*.exe; do ldd "$f"; done
    for d in platforms styles tls imageformats iconengines generic networkinformation; do
        for g in "$DIST/$d"/*.dll; do [ -f "$g" ] && ldd "$g"; done
    done
} 2>/dev/null | grep -oiE '/(c/msys64/)?mingw64/bin/[^ ]+\.dll' | sort -u | while read -r p; do
    bn=$(basename "$p")
    src="$MINGW_BIN/$bn"; [ -f "$src" ] || src="$p"
    [ -f "$DIST/$bn" ] || { [ -f "$src" ] && cp "$src" "$DIST/"; }
done

echo ">> bundle: $(ls "$DIST"/*.dll | wc -l) DLLs, $(du -sh "$DIST" | cut -f1) total"

if [ -x "$MAKENSIS" ] || command -v "$MAKENSIS" >/dev/null 2>&1; then
    echo ">> makensis (from $WORKDIR)"
    ( cd "$WORKDIR" && "$MAKENSIS" -V2 share/setup.nsi )
    mkdir -p "$TOPDIR/dist"
    cp "$WORKDIR"/dist/lattica-*-win64-setup.exe "$TOPDIR/dist/"
    echo ">> done: $(ls "$TOPDIR"/dist/lattica-*-win64-setup.exe)"
else
    echo ">> NSIS (makensis) not found. Install it, then re-run:"
    echo "   pacman -S mingw-w64-x86_64-nsis"
fi
