#!/bin/bash

set -xeu

TIMEOUT=${TIMEOUT:=10}
RUN_TIME=${RUN_TIME:=600}
VERBOSITY=${VERBOSITY:=}

SRCDIR=/libocispec
# The build happens on a private copy: the fuzzing build is not one to leave
# behind in the tree the caller mounted, and the tree may well be a checkout
# that is being worked on.
WORKDIR=/tmp/libocispec

N_TESTS=7

SINGLE_RUN_TIME=$(( RUN_TIME / N_TESTS ))

rm -rf "$WORKDIR"
cp -a "$SRCDIR" "$WORKDIR"
cd "$WORKDIR"
git config --global --add safe.directory "$WORKDIR"
git clean -fdx
./autogen.sh
# hfuzz-clang looks these up with getenv(2) as it compiles, so they have to be
# in the environment of make, not just of configure.
export HFUZZ_CC_UBSAN=1 HFUZZ_CC_ASAN=1
./configure CC=hfuzz-clang CPPFLAGS="-D FUZZER" CFLAGS="-ggdb3 -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-div,indirect-calls"
make -j "$(nproc)"

function run_test {
    export FUZZING_MODE=$1

    # shellcheck disable=SC2086
    result=$(honggfuzz --exit_upon_crash $VERBOSITY --run_time "$SINGLE_RUN_TIME" --timeout "$TIMEOUT" -T -i tests/data -- src/ocispec/validate 2>&1 | tail -n 2)
    echo "$result"
    echo "$result" | grep -q crashes_count:0
}

run_test 0
run_test 1
run_test 2
run_test 3
run_test 4
run_test 5
run_test 6
