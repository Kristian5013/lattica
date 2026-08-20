#!/usr/bin/env bash

export LC_ALL=C.UTF-8

set -o errexit -o xtrace -o pipefail

if [ "${DANGER_RUN_CI_ON_HOST}" != "1" ]; then
  echo "This script will make unsafe local and global modifications, so it can only be run inside a container and requires DANGER_RUN_CI_ON_HOST=1"
  exit 1
fi

cd "${BASE_ROOT_DIR}"

export PATH="/path_with space:${PATH}"
export ASAN_OPTIONS="detect_leaks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:report_error_type=1"

echo "Number of available processing units: $(nproc)"
if [ "$CI_OS_NAME" == "macos" ]; then
  top -l 1 -s 0 | awk ' /PhysMem/ {print}'
else
  free -m -h
  echo "System info: $(uname --kernel-name --kernel-release)"
  lscpu
fi
echo "Free disk space:"
df -h

# What host to compile for. Lattica does not use the depends system, so guess a
# native host triple; cross-compiling variants export HOST explicitly.
export HOST=${HOST:-$(uname -m)-pc-linux-gnu}

echo "=== BEGIN env ==="
env
echo "=== END env ==="

# Make sure default datadir does not exist and is never read by creating a dummy file
if [ "$CI_OS_NAME" == "macos" ]; then
  echo > "${HOME}/Library/Application Support/Lattica"
else
  echo > "${HOME}/.lattica"
fi

LATTICA_CONFIG_ALL="-DCMAKE_INSTALL_PREFIX=$BASE_OUTDIR"

ccache --zero-stats

# Folder where the build is done.
BASE_BUILD_DIR=${BASE_BUILD_DIR:-$BASE_SCRATCH_DIR/build-$HOST}

if [[ "${RUN_TIDY}" == true ]]; then
  LATTICA_CONFIG_ALL="$LATTICA_CONFIG_ALL -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
fi

eval "CMAKE_ARGS=($LATTICA_CONFIG_ALL $LATTICA_CONFIG)"
cmake -S "$BASE_ROOT_DIR" -B "$BASE_BUILD_DIR" "${CMAKE_ARGS[@]}" || (
  cd "${BASE_BUILD_DIR}"
  # shellcheck disable=SC2046
  cat $(cmake -P "${BASE_ROOT_DIR}/ci/test/GetCMakeLogFiles.cmake")
  false
)

if [[ "${GOAL}" != all && "${GOAL}" != codegen ]]; then
  GOAL="all ${GOAL}"
fi

# shellcheck disable=SC2086
cmake --build "${BASE_BUILD_DIR}" "$MAKEJOBS" --target $GOAL || (
  echo "Build failure. Verbose build follows."
  # shellcheck disable=SC2086
  cmake --build "${BASE_BUILD_DIR}" -j1 --target $GOAL --verbose
  false
)

ccache --version | head -n 1 && ccache --show-stats --verbose
ccache --print-stats | python3 -c '
import os
import sys

for line in sys.stdin:
    key, value = line.split("\t", 1)
    # "primary storage" fallback only needed for ccache version 4.5.1
    if key in ("local_storage_hit", "primary_storage_hit"):
        hits = int(value)
    elif key in ("local_storage_miss", "primary_storage_miss"):
        miss = int(value)

calls = hits + miss
# codegen has no calls, so skip that here
if calls:
    rate = (hits / calls * 100)
    print(f"{rate:.2f}")
    if rate < 75:
        container = os.environ["CONTAINER_NAME"]
        print(
            "::notice title=low ccache hitrate::"
            f"Ccache hit-rate in {container} was {rate:.2f}%"
        )
'

if [ -n "${CI_LIMIT_STACK_SIZE}" ]; then
  ulimit -s 512
fi

if [ "$RUN_CHECK_DEPS" = "true" ]; then
  "${BASE_ROOT_DIR}/contrib/devtools/check-deps.sh" "${BASE_BUILD_DIR}"
fi

if [ "$RUN_UNIT_TESTS" = "true" ]; then
  CTEST_OUTPUT_ON_FAILURE=ON \
  ctest --test-dir "${BASE_BUILD_DIR}" \
    --stop-on-failure \
    "${MAKEJOBS}" \
    --timeout $(( TEST_RUNNER_TIMEOUT_FACTOR * 60 ))
fi

if [ "${RUN_TIDY}" = "true" ]; then
  cmake -B /tidy-build -DLLVM_DIR=/usr/lib/llvm-"${TIDY_LLVM_V}"/cmake -DCMAKE_BUILD_TYPE=Release -S "${BASE_ROOT_DIR}"/contrib/devtools/lattica-tidy
  cmake --build /tidy-build "$MAKEJOBS"
  cmake --build /tidy-build --target lattica-tidy-tests "$MAKEJOBS"

  set -eo pipefail
  # Filter out:
  # * qt qrc and moc generated files
  jq 'map(select(.file | test("src/qt/.*_autogen/.*\\.cpp$") | not))' "${BASE_BUILD_DIR}/compile_commands.json" > tmp.json
  mv tmp.json "${BASE_BUILD_DIR}/compile_commands.json"

  cd "${BASE_BUILD_DIR}/src/"
  if ! ( run-clang-tidy-"${TIDY_LLVM_V}" -config-file="${BASE_ROOT_DIR}/src/.clang-tidy" -quiet -load="/tidy-build/liblattica-tidy.so" "${MAKEJOBS}" | tee tmp.tidy-out.txt ); then
    grep -C5 "error: " tmp.tidy-out.txt
    echo "^^^ ⚠️ Failure generated from clang-tidy"
    false
  fi
fi
