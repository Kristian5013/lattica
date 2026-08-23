# Dependencies

These are the dependencies used by Lattica.
You can find installation instructions in the `/doc/build-*.md` file for your platform.

The consensus-critical and bundled libraries (LevelDB, crc32c, minisketch,
univalue, mldsa44/falcon512/mlkem768 and, for IPC,
libmultiprocess) are vendored in the source tree and require no separate
installation.

## Compiler

Lattica is written in C++20 and requires one of the following compilers.

| Toolchain | Minimum required |
| --- | --- |
| [GCC](https://gcc.gnu.org) | 14 |
| [Clang](https://clang.llvm.org) | 19 |

## Required

### Build

| Dependency | Releases | Minimum required |
| --- | --- | --- |
| [Boost](https://www.boost.org/users/download/) (headers only) | [link](https://www.boost.org/users/download/) | 1.74.0 |
| CMake | [link](https://cmake.org/) | 3.22 |

### Runtime

| Dependency | Releases | Minimum required |
| --- | --- | --- |
| glibc (Linux) | [link](https://www.gnu.org/software/libc/) | 2.31 |

## Optional

### Build

| Dependency | Releases | Minimum required |
| --- | --- | --- |
| [Cap'n Proto](https://capnproto.org/) ([IPC](multiprocess.md), Unix only) | [link](https://capnproto.org/) | 0.7.1 |
| Python (scripts) | [link](https://www.python.org) | 3.10 |
| [Qt](https://download.qt.io/archive/qt/) (gui) | [link](https://download.qt.io/archive/qt/) | 6.2 |
| [SQLite](https://sqlite.org) (wallet) | [link](https://sqlite.org) | 3.7.17 |
| [ZeroMQ](https://github.com/zeromq/libzmq/releases) (notifications) | [link](https://github.com/zeromq/libzmq/releases) | 4.0.0 |
| gettext (regenerating translations) | [link](https://www.gnu.org/software/gettext/) | N/A |

### Runtime

| Dependency | Releases | Minimum required |
| --- | --- | --- |
| [Fontconfig](https://www.freedesktop.org/wiki/Software/fontconfig/) (gui) | [link](https://www.freedesktop.org/wiki/Software/fontconfig/) | 2.6 |
| [FreeType](https://freetype.org) (gui) | [link](https://freetype.org) | 2.3.0 |
