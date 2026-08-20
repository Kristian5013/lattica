#!/usr/bin/env bash

export LC_ALL=C.UTF-8

set -o errexit -o pipefail -o xtrace

if [ "${DANGER_RUN_CI_ON_HOST}" != "1" ]; then
  echo "This script will make unsafe local and global modifications, so it can only be run inside a container and requires DANGER_RUN_CI_ON_HOST=1"
  exit 1
fi

CFG_DONE="${BASE_ROOT_DIR}/ci.base-install-done"  # Use a global setting to remember whether this script ran to avoid running it twice

if [ "$( cat "${CFG_DONE}" || true )" == "done" ]; then
  echo "Skip base install"
  exit 0
fi

MAKEJOBS="-j$( nproc )"  # Use nproc, because MAKEJOBS is the default in docker image builds.

if [ -n "$DPKG_ADD_ARCH" ]; then
  dpkg --add-architecture "$DPKG_ADD_ARCH"
fi

if [ -n "${APT_LLVM_V}" ]; then
  ${CI_RETRY_EXE} apt-get update
  ${CI_RETRY_EXE} apt-get install curl -y
  curl "https://apt.llvm.org/llvm-snapshot.gpg.key" | tee "/etc/apt/trusted.gpg.d/apt.llvm.org.asc"
  (
    # shellcheck disable=SC2034
    source /etc/os-release
    echo "deb http://apt.llvm.org/${VERSION_CODENAME}/ llvm-toolchain-${VERSION_CODENAME}-${APT_LLVM_V} main" > "/etc/apt/sources.list.d/llvm-toolchain-${VERSION_CODENAME}-${APT_LLVM_V}.list"
  )
fi

if command -v apk >/dev/null 2>&1; then
  ${CI_RETRY_EXE} apk update
  # shellcheck disable=SC2086
  ${CI_RETRY_EXE} apk add --no-cache $CI_BASE_PACKAGES $PACKAGES
elif [ "$CI_OS_NAME" != "macos" ]; then
  if [[ -n "${APPEND_APT_SOURCES_LIST}" ]]; then
    echo "${APPEND_APT_SOURCES_LIST}" >> /etc/apt/sources.list
  fi
  ${CI_RETRY_EXE} apt-get update
  # shellcheck disable=SC2086
  ${CI_RETRY_EXE} apt-get install --no-install-recommends --no-upgrade -y $PACKAGES $CI_BASE_PACKAGES
fi

if [ -n "${APT_LLVM_V}" ]; then
  update-alternatives --install /usr/bin/clang++ clang++ "/usr/bin/clang++-${APT_LLVM_V}" 100
  update-alternatives --install /usr/bin/clang clang "/usr/bin/clang-${APT_LLVM_V}" 100
  update-alternatives --install /usr/bin/llvm-symbolizer llvm-symbolizer "/usr/bin/llvm-symbolizer-${APT_LLVM_V}" 100
fi

if [ -n "$PIP_PACKAGES" ]; then
  # shellcheck disable=SC2086
  ${CI_RETRY_EXE} pip3 install --user $PIP_PACKAGES
fi

# Lattica requires the C++26 (CXX26) compiler dialect. Distribution CMake
# (e.g. Ubuntu 24.04 ships 3.28) does not know the C++26 flags for GCC, which
# breaks every try_compile. Install a recent CMake into /usr/local (ahead of the
# distro one on PATH).
if [ "$CI_OS_NAME" != "macos" ] && command -v pip3 >/dev/null 2>&1; then
  ${CI_RETRY_EXE} pip3 install --break-system-packages --upgrade cmake
fi

echo -n "done" > "${CFG_DONE}"
