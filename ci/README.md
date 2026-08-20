# CI Scripts

This directory contains scripts for each build step in each build stage.

The CI mirrors the structure of Bitcoin Core's `ci/` directory, adapted for
Lattica: there is no `depends/` dependency generator (Lattica links system and
vendored libraries), there is no Python functional-test framework, and there are
no fuzz targets, so those stages are removed. The unit tests are run with
`ctest`, the benchmarks are the `bench_lattica` target, and clang-tidy uses the
`contrib/devtools/lattica-tidy` plugin.

## Running a Stage Locally

Be aware that the tests will be built and run in-place, so please run at your own risk.
If the repository is not a fresh git clone, you might have to clean files from previous builds or test runs first.

The ci needs to perform various sysadmin tasks such as installing packages or writing to the user's home directory.
While it should be fine to run
the ci system locally on your development box, the ci scripts can generally be assumed to have received less review and
testing compared to other parts of the codebase. If you want to keep the work tree clean, you might want to run the ci
system in a virtual machine with a Linux operating system of your choice.

To allow for a wide range of tested environments, but also ensure reproducibility to some extent, the test stage
requires `bash`, `docker`, and `python3` to be installed. To install all requirements on Ubuntu, run

```
sudo apt install bash docker.io python3
```

It is recommended to run the CI system in a clean environment. The `env -i`
command below ensures that *only* specified environment variables are propagated
into the local CI.
To run the test stage with a specific configuration:

```
env -i HOME="$HOME" PATH="$PATH" USER="$USER" FILE_ENV="./ci/test/00_setup_env_native.sh" ./ci/test_run_all.sh
```

## Configurations

The test files (`FILE_ENV`) are constructed to test a range of configurations,
rather than a single pass/fail. This helps to catch build failures and logic
errors that present on platforms other than the ones the author has tested.

The available environments are:

- `00_setup_env_native.sh` — Linux, GCC 14, default features (wallet + ZMQ), unit tests.
- `00_setup_env_native_multiprocess.sh` — Linux, GCC 14, multiprocess IPC enabled.
  Non-blocking in the default matrix: the vendored libmultiprocess CMake wiring
  is not yet hooked up for a clean checkout.
- `00_setup_env_native_nowallet.sh` — Linux, GCC 14, node-only. Lattica builds
  the wallet into the node (wallet is always on), so this is not part of the
  default matrix.
- `00_setup_env_mac_native.sh` — macOS native build (run with `DANGER_RUN_CI_ON_HOST=1`).
- `00_setup_env_native_tidy.sh` — Linux, clang-tidy via `contrib/devtools/lattica-tidy`.
  Requires `src/.clang-tidy` (not yet added), so it is not part of the default matrix.

It is also possible to force a specific configuration without modifying the
file. For example,

```
env -i HOME="$HOME" PATH="$PATH" USER="$USER" MAKEJOBS="-j1" FILE_ENV="./ci/test/00_setup_env_native.sh" ./ci/test_run_all.sh
```

The files starting with `0n` (`n` greater than 0) are the scripts that are run
in order.

## Cache

In order to avoid rebuilding all objects for each build, `ccache` is used and
the cache is reused when possible.

## Linting

The lint stage (`ci/lint.py`) builds a separate container and runs
`ci/lint/06_script.sh`. Lattica has not yet ported Bitcoin Core's Rust lint
runner (`test/lint/test_runner`); as a starter the script shellchecks the CI and
devtools shell scripts. It is therefore not part of the default CI matrix yet.
