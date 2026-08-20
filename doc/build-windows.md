WINDOWS BUILD NOTES
====================

Lattica is built natively on Windows with the [MSYS2](https://www.msys2.org/)
MinGW-w64 toolchain (not MSVC, and not cross-compiled from Linux). The result is
a set of standalone `*.exe` binaries plus, optionally, an NSIS installer.

Toolchain
---------

Install [MSYS2](https://www.msys2.org/) and, from a **MSYS2 MinGW64** shell,
install the toolchain and dependencies:

```bash
pacman -S --needed \
    mingw-w64-x86_64-gcc \
    mingw-w64-x86_64-cmake \
    mingw-w64-x86_64-ninja \
    mingw-w64-x86_64-pkgconf \
    mingw-w64-x86_64-boost \
    mingw-w64-x86_64-sqlite3
```

Lattica requires a **C++20** compiler; the `mingw-w64-x86_64-gcc` package is
recent enough. The vendored libraries (LevelDB, crc32c, minisketch, univalue,
ML-DSA-44/ML-KEM-768) are built from the source tree and need not be
installed.

Optional dependencies:

```bash
# ZeroMQ notifications
pacman -S mingw-w64-x86_64-zeromq
# GUI
pacman -S mingw-w64-x86_64-qt6-base mingw-w64-x86_64-qt6-tools
# Translations
pacman -S mingw-w64-x86_64-gettext
# Windows installer
pacman -S mingw-w64-x86_64-nsis
```

> **Note:** the multiprocess (IPC) `lattica-node`/`lattica-gui` binaries are
> **not** available on Windows — `ENABLE_IPC` is forced off there.

Building
--------

From the MinGW64 shell, in the source directory:

```bash
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build
```

The binaries are produced under `build/bin/` (`latticad.exe`,
`lattica-cli.exe`, `lattica-tx.exe`, `lattica-wallet.exe`).

### GUI

```bash
cmake -S . -B build-gui -G Ninja -DENABLE_GUI=ON
cmake --build build-gui --target lattica-qt
```

This produces `build-gui/lattica-qt.exe`.

> **Non-ASCII source paths:** Qt's `moc`/`lupdate` and `makensis` cannot read or
> write through a source path that contains non-ASCII characters. If your
> checkout lives under such a path, create an ASCII directory junction to it
> (`mklink /J C:\lattica "<path>"`) and configure/build through the junction.

Building the installer
----------------------

After a GUI build, `tools/build-installer.sh` stages a self-contained runtime
bundle (the binaries + the Qt 6 DLLs/plugins via `windeployqt6` + the full DLL
closure) and runs `makensis` on the generated `lattica-win64-setup.nsi`,
producing `dist/lattica-<version>-win64-setup.exe`.

```bash
tools/build-installer.sh
```
