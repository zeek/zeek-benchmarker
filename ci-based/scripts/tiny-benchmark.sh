#!/bin/bash
#
# Tiny perf-benchmark.sh version that runs $ZEEKBIN with $*
# prefixed with nice and taskset under timeout and that's it.
#
set -eux
NICE_ADJUSTMENT=${NICE_ADJUSTMENT:--19}
KILL_TIMEOUT=${KILL_TIMEOUT:-300}

# Add path where tiny-benchmark.sh is located to ZEEKPATH
# so that microbenchmark is in the path.
orig_zeekpath=$(${ZEEKCONFIG} --zeekpath)
export ZEEKPATH="${orig_zeekpath}:$(dirname $0)"

exec timeout --signal=SIGKILL ${KILL_TIMEOUT} \
    nice -n ${NICE_ADJUSTMENT} \
    /usr/bin/taskset --cpu-list ${ZEEKCPUS} \
    /usr/bin/time -o /dev/stdout -f 'BENCHMARK_TIMING=%e;%M;%U;%S' \
    ${ZEEKBIN} $*
