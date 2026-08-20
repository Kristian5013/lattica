#!/usr/bin/env bash

export LC_ALL=C.UTF-8

set -o errexit; source ./ci/test/00_setup_env.sh
set -o errexit
"./ci/test/02_run_container.py"
