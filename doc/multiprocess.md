# Multiprocess Lattica

_This document describes usage of the multiprocess feature. For design information, see the [design/multiprocess.md](design/multiprocess.md) file._

## Build Option

The `-DENABLE_IPC=ON` build option, supported and enabled by default on Unix systems, can be passed to build the supplemental `lattica-node` and `lattica-gui` multiprocess executables. (IPC is not supported on Windows, where the option is forced off.)

## Debugging

The `-debug=ipc` command line option can be used to see requests and responses between processes.

## Installation

Specifying `-DENABLE_IPC=ON` requires [Cap'n Proto](https://capnproto.org/) to be installed. See [build-unix.md](build-unix.md) for information about installing dependencies.

### Cross-compiling

When cross-compiling, native code generation tools from [libmultiprocess](https://github.com/bitcoin-core/libmultiprocess) and [Cap'n Proto](https://capnproto.org/) are required. They can be passed to the cmake build by specifying `-DMPGEN_EXECUTABLE=/path/to/mpgen -DCAPNP_EXECUTABLE=/path/to/capnp -DCAPNPC_CXX_EXECUTABLE=/path/to/capnpc-c++` options.

### External libmultiprocess installation

By default when `-DENABLE_IPC=ON` is enabled, the libmultiprocess sources at [../src/ipc/libmultiprocess/](../src/ipc/libmultiprocess/) are built as part of the lattica cmake build, but alternately an external [libmultiprocess](https://github.com/bitcoin-core/libmultiprocess/) cmake package can be used instead by following its [installation instructions](https://github.com/bitcoin-core/libmultiprocess/blob/master/doc/install.md) and specifying `-DWITH_EXTERNAL_LIBMULTIPROCESS=ON` to the lattica build, so it will use the external package instead of the sources. This can be useful when making changes to the upstream project. If libmultiprocess is not installed in a default system location it is possible to specify the [`CMAKE_PREFIX_PATH`](https://cmake.org/cmake/help/latest/envvar/CMAKE_PREFIX_PATH.html) environment variable to point to the installation prefix where libmultiprocess is installed.

## Usage

The multiprocess binaries are invoked directly: `lattica-node` is the IPC-enabled alternative to `latticad`, and `lattica-gui` is the IPC-enabled alternative to `lattica-qt`. For example:

```
build/bin/lattica-node -regtest -printtoconsole -debug=ipc
```

(Unlike Bitcoin Core, Lattica does not ship a `lattica` umbrella wrapper, so there is no `-m`/`--multiprocess` switch — the multiprocess executables are run by name.)

The multiprocess binaries currently function the same as the monolithic binaries, except they support an `-ipcbind` option.

In the future, after [#10102](https://github.com/bitcoin/bitcoin/pull/10102) they will have other differences. Specifically `lattica-gui` will spawn a `lattica-node` process to run P2P and RPC code, communicating with it across a socket pair, and `lattica-node` will spawn `lattica-wallet` to run wallet code, also communicating over a socket pair. This will let node, wallet, and GUI code run in separate address spaces for better isolation, and allow future improvements like being able to start and stop components independently on different machines and environments. [#19460](https://github.com/bitcoin/bitcoin/pull/19460) also adds a new `lattica-wallet -ipcconnect` option to allow new wallet processes to connect to an existing node process.
And [#19461](https://github.com/bitcoin/bitcoin/pull/19461) adds a new `lattica-gui -ipcconnect` option to allow new GUI processes to connect to an existing node process.
