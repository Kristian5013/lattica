#!/usr/bin/env bash

export LC_ALL=C.UTF-8

set -o errexit -o nounset -o pipefail -o xtrace

# The source root dir, usually from git, usually read-only.
# The ci system copies this folder.
BASE_READ_ONLY_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )"/../../ >/dev/null 2>&1 && pwd )
export BASE_READ_ONLY_DIR
# The destination root dir inside the container.
# This folder will also hold any SDKs.
# This folder only exists on the ci guest and will be a copy of BASE_READ_ONLY_DIR
export BASE_ROOT_DIR="${BASE_ROOT_DIR:-/ci_container_base}"
# The depends dir.
# Lattica does not use the depends dependency generator (it links system and
# vendored libraries), so NO_DEPENDS is set in the env files. The variable is
# kept because the container runner mounts a (then unused) volume for it.
export DEPENDS_DIR=${DEPENDS_DIR:-$BASE_ROOT_DIR/depends}
# A folder for the ci system to put temporary files (build result, datadirs for tests, ...)
# This folder only exists on the ci guest.
export BASE_SCRATCH_DIR=${BASE_SCRATCH_DIR:-$BASE_ROOT_DIR/ci/scratch}

echo "Setting specific values in env"
# shellcheck disable=SC1090
source "${FILE_ENV}"

echo "Fallback to default values in env (if not yet set)"
# The number of parallel jobs to pass down to make and ctest
export MAKEJOBS=${MAKEJOBS:--j$(if command -v nproc > /dev/null 2>&1; then nproc; else sysctl -n hw.logicalcpu; fi)}

export RUN_UNIT_TESTS=${RUN_UNIT_TESTS:-true}
# Lattica has no python functional test framework, so functional tests are off
# by default. The variable is kept for parity with the upstream env contract.
export RUN_FUNCTIONAL_TESTS=${RUN_FUNCTIONAL_TESTS:-false}
export RUN_TIDY=${RUN_TIDY:-false}
# By how much to scale the ctest timeouts (option --timeout).
# This is needed because some ci machines have slow CPU or disk, so mining or a
# reindex might be waiting on disk IO.
export TEST_RUNNER_TIMEOUT_FACTOR=${TEST_RUNNER_TIMEOUT_FACTOR:-40}
export RUN_FUZZ_TESTS=${RUN_FUZZ_TESTS:-false}
export RUN_CHECK_DEPS=${RUN_CHECK_DEPS:-false}

# Use the Ninja generator: it handles the scratch path robustly and is faster
# than Make. ninja-build is part of CI_BASE_PACKAGES. Variant files may override.
export CMAKE_GENERATOR=${CMAKE_GENERATOR:-Ninja}

# See man 7 debconf
export DEBIAN_FRONTEND=noninteractive
export CCACHE_MAXSIZE=${CCACHE_MAXSIZE:-2G}
export CCACHE_TEMPDIR=${CCACHE_TEMPDIR:-/tmp/.ccache-temp}
export CCACHE_COMPRESS=${CCACHE_COMPRESS:-1}
# The cache dir.
# This folder exists only on the ci guest, and on the ci host as a volume.
export CCACHE_DIR="${CCACHE_DIR:-$BASE_SCRATCH_DIR/ccache}"
# Folder where the build result is put (bin and lib).
export BASE_OUTDIR=${BASE_OUTDIR:-$BASE_SCRATCH_DIR/out}
# The folder for previous release binaries.
# Lattica is pre-release, so this is never populated, but the container runner
# still mounts a volume for it.
export PREVIOUS_RELEASES_DIR=${PREVIOUS_RELEASES_DIR:-$BASE_ROOT_DIR/prev_releases}
export CI_BASE_PACKAGES=${CI_BASE_PACKAGES:-build-essential pkgconf curl ca-certificates ccache python3 python3-pip rsync git procps cmake ninja-build}
export GOAL=${GOAL:-all}
export CI_RETRY_EXE=${CI_RETRY_EXE:-"retry"}

# The --platform argument used with `docker build` and `docker run`.
export CI_IMAGE_PLATFORM=${CI_IMAGE_PLATFORM:-"linux"} # Force linux, but use native arch by default
