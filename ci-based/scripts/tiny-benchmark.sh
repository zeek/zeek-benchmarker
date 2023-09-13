#!/bin/bash
#
# Tiny perf-benchmark.sh version that runs $ZEEKBIN with $*
# prefixed with nice and taskset under timeout and that's it.
#
set -eux
echo ${ZEEKBIN}
echo ${ZEEKCPUS}
NICE_ADJUSTMENT=${NICE_ADJUSTMENT:--19}
KILL_TIMEOUT=${KILL_TIMEOUT:-300}

# Add path where tiny-benchmark.sh is located to ZEEKPATH
# XXX: Maybe move this upwards for less magic.
export ZEEKPATH="${ZEEKPATH}:$(dirname $0)"

exec timeout --signal=SIGKILL ${KILL_TIMEOUT} \
    nice -n ${NICE_ADJUSTMENT} \
    /usr/bin/taskset --cpu-list ${ZEEKCPUS} \
    /usr/bin/time -o /dev/stdout -f 'BENCHMARK_TIMING=%e;%M;%U;%S' \
    ${ZEEKBIN} $*
