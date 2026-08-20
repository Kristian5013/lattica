#!/usr/bin/env bash

export LC_ALL=C.UTF-8

export CONTAINER_NAME="ci_mac_native"  # macos does not use a container, but the env var is needed for logging
export GOAL="all"
export CMAKE_GENERATOR="Ninja"
export CI_OS_NAME="macos"
export NO_DEPENDS=1

# The runner's AppleClang does not support the C++26 (CXX26) dialect, and brew's
# LLVM libc++ is strict about not leaking C names (e.g. global ::size_t) that the
# code relies on. Build with brew gcc@14 instead — the same compiler/stdlib
# family (GCC + libstdc++) as the Linux job, which the codebase compiles on.
GCC_PREFIX="$(brew --prefix gcc@14)"
export CC="${GCC_PREFIX}/bin/gcc-14"
export CXX="${GCC_PREFIX}/bin/g++-14"

# Homebrew installs the libraries (sqlite, zeromq, boost) under the
# brew prefix, which is not on GCC's default search path. Expose the headers and
# libraries to every compile/link via CPATH/LIBRARY_PATH (the standard way to
# build a non-brew-aware project against brew packages).
BREW_PREFIX="$(brew --prefix)"
export CPATH="${BREW_PREFIX}/include"
export LIBRARY_PATH="${BREW_PREFIX}/lib"

export LATTICA_CONFIG="-DCMAKE_EXE_LINKER_FLAGS='-Wl,-stack_size -Wl,0x80000'"
