#!/usr/bin/env bash
# Copyright (c) 2026 Kristian Pilatovich
# See COPYING for license.
#
# Run every fuzz target for a bounded time and report.
#
#   test/fuzz/run.sh <fuzz-binary> [seconds-per-target] [corpus-dir]
#
# The bound is the point. An unbounded fuzzer is a thing someone runs once; a
# fuzzer that finishes in a known number of minutes is a thing that runs on
# every change, and finding a fault on the day it is written is worth more than
# finding it thoroughly a year later. The corpus persists between runs, so each
# run starts from what every previous run learned rather than from nothing.
#
# A crash leaves its input in the corpus directory as crash-<sha1>; reproduce it
# with:  FUZZ=<target> <fuzz-binary> <that file>

set -uo pipefail

FUZZ_BIN=${1:?usage: run.sh <fuzz-binary> [seconds-per-target] [corpus-dir]}
SECONDS_PER=${2:-60}
CORPUS_ROOT=${3:-"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/corpus"}

if [[ ! -x $FUZZ_BIN ]]; then
    echo "error: $FUZZ_BIN is not an executable" >&2
    exit 1
fi

# The binary lists its targets when FUZZ is unset, on stderr, one indented per
# line. Asking it beats keeping a second list in step with the first.
mapfile -t TARGETS < <(FUZZ= "$FUZZ_BIN" 2>&1 >/dev/null | sed -n 's/^  \([a-z_][a-z0-9_]*\)$/\1/p')

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "error: $FUZZ_BIN reported no targets" >&2
    exit 1
fi

echo "${#TARGETS[@]} targets, ${SECONDS_PER}s each, corpus in $CORPUS_ROOT"
echo

failed=()
for t in "${TARGETS[@]}"; do
    corpus="$CORPUS_ROOT/$t"
    mkdir -p "$corpus"
    log=$(mktemp)

    # -print_final_stats gives the coverage reached, which is the number worth
    # watching over time: a target whose coverage stops growing is a target
    # whose corpus has gone stale or whose reachable code is exhausted.
    FUZZ="$t" "$FUZZ_BIN" "$corpus" \
        -max_total_time="$SECONDS_PER" \
        -print_final_stats=1 \
        -timeout=30 \
        -rss_limit_mb=4096 \
        > "$log" 2>&1
    rc=$?

    cov=$(sed -n 's/.*cov: \([0-9]*\).*/\1/p' "$log" | tail -1)
    execs=$(sed -n 's/^stat::number_of_executed_units: *\([0-9]*\).*/\1/p' "$log" | tail -1)

    if [[ $rc -ne 0 ]]; then
        printf '[FAIL] %-22s rc=%d\n' "$t" "$rc"
        sed -n '/ERROR\|SUMMARY\|Test unit written/p' "$log" | head -6 | sed 's/^/       /'
        failed+=("$t")
    else
        printf '[ ok ] %-22s cov=%-7s execs=%s\n' "$t" "${cov:-?}" "${execs:-?}"
    fi
    rm -f "$log"
done

echo
if [[ ${#failed[@]} -gt 0 ]]; then
    echo "FAILURES: ${failed[*]}"
    exit 1
fi
echo "ALL PASS"
