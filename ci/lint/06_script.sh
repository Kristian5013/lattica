#!/usr/bin/env bash

export LC_ALL=C

set -o errexit -o pipefail -o xtrace

# Fixes permission issues when there is a container UID/GID mismatch with the owner
# of the mounted lattica src dir.
git config --global --add safe.directory /lattica

export PATH="/python_env/bin:${PATH}"

if [ -n "${LINT_CI_IS_PR}" ]; then
  export COMMIT_RANGE="HEAD~..HEAD"
fi

# NOTE: Lattica has not yet ported Bitcoin Core's Rust lint runner
# (test/lint/test_runner) and its lint-*.py checks. As a starter, shellcheck the
# CI and devtools shell scripts. Extend this once test/lint/ is ported.
shellcheck ci/test/*.sh ci/test/00_setup_env*.sh ci/lint/*.sh contrib/devtools/*.sh
