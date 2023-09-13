#!/usr/bin/env bash
set -ex

export LD_LIBRARY_PATH="/benchmarker/zeek/install/lib:/benchmarker/zeek/install/lib64:${LD_LIBRARY_PATH}"

if [ "$IS_LOCAL" = "0" ]; then
    tar -xzf /benchmarker/binaries/${BUILD_FILE_NAME} -C /benchmarker
fi

# If BENCH_COMMAND and BENCH_ARGS is set, dispatch to tiny-benchmark.sh.
if [ -n "${BENCH_COMMAND}" ] && [ -n "${BENCH_ARGS}" ]; then
    exec $BENCH_COMMAND $BENCH_ARGS

    # not reached
    exit 1
fi

cp /test_data/${DATA_FILE_NAME} ${TMPFS_PATH}/${DATA_FILE_NAME}
timeout --signal=SIGKILL 5m /benchmarker/scripts/perf-benchmark.sh --quiet --parseable --mode file \
    --seed ${ZEEKSEED} --build ${ZEEKBIN} --data-file ${TMPFS_PATH}/${DATA_FILE_NAME} \
    --cpus ${ZEEKCPUS}
