UNIX BUILD NOTES
====================

Some notes on how to build Lattica Core on Unix-like systems.

Lattica uses a CMake-based build system. The canonical build is:

```bash
cmake -B build
cmake --build build
ctest --test-dir build
```

The binaries are produced under `build/bin/`.

Toolchain requirements
----------------------

Lattica is written in **C++20**, so a reasonably recent compiler is required:

- GCC 14 or newer, or
- Clang 19 or newer

plus:

- CMake 3.22 or newer
- Ninja (recommended) or GNU Make
- pkg-config
- Python 3 (for some helper scripts)

Dependencies
------------

The consensus-critical and bundled libraries (LevelDB, crc32c, minisketch,
univalue, ML-DSA-44/ML-KEM-768 and, for IPC,
libmultiprocess) are **vendored** in the source tree and built automatically —
you do not need to install them.

The remaining system dependencies are:

| Dependency | Purpose | Package (Debian/Ubuntu) |
|------------|---------|-------------------------|
| Boost (headers only) | multi_index, etc. | `libboost-dev` |
| SQLite 3 | wallet database | `libsqlite3-dev` |
| ZeroMQ *(optional)* | `-zmqpub*` notifications | `libzmq3-dev` |
| Qt 6 *(GUI only)* | the `lattica-qt` GUI | `qt6-base-dev qt6-tools-dev qt6-tools-dev-tools` |
| gettext *(translations)* | regenerating `lattica_en.ts` | `gettext` |
| Cap'n Proto *(IPC only)* | multiprocess `lattica-node`/`lattica-gui` | `capnproto libcapnp-dev` |

ML-DSA-44 signature verification requires no external library — the FIPS 204
implementation is vendored.

To install the build prerequisites and the required dependencies on
Debian/Ubuntu:

```bash
sudo apt install build-essential cmake ninja-build pkg-config python3 \
    libboost-dev libsqlite3-dev
```

Optional dependencies:

```bash
# ZeroMQ notifications
sudo apt install libzmq3-dev
# GUI
sudo apt install qt6-base-dev qt6-tools-dev qt6-tools-dev-tools
# Translations
sudo apt install gettext
# Multiprocess (IPC)
sudo apt install capnproto libcapnp-dev
```

Build options
-------------

Build behaviour is controlled with `-D<OPTION>=ON|OFF` flags passed to the
configure step. The most common are:

| Option | Default | Effect |
|--------|---------|--------|
| `ENABLE_WALLET` | ON | Build the SQLite wallet |
| `ENABLE_GUI` | OFF | Build the `lattica-qt` GUI (requires Qt 6) |
| `WITH_ZMQ` | ON | Build ZeroMQ notification support |
| `ENABLE_IPC` | ON (Unix) | Build the multiprocess `lattica-node`/`lattica-gui` binaries |

For example, to build with the GUI:

```bash
cmake -B build -DENABLE_GUI=ON
cmake --build build
```

Running the tests
-----------------

```bash
ctest --test-dir build
```

Each unit test is a standalone executable under `build/bin/` (`test_lattica`,
the per-test binaries, etc.); `ctest` runs them all.

Strip the binaries
------------------

The release binaries can be reduced in size by stripping debug symbols:

```bash
strip build/bin/latticad
```
