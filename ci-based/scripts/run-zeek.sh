#!/usr/bin/env bash
set -ex

export LD_LIBRARY_PATH="/zeek/install/lib:/zeek/install/lib64:${LD_LIBRARY_PATH}"

# If BENCH_COMMAND and BENCH_ARGS is set, dispatch to tiny-benchmark.sh.
if [ -n "${BENCH_COMMAND}" ] && [ -n "${BENCH_ARGS}" ]; then
    exec $BENCH_COMMAND $BENCH_ARGS

    # not reached
    exit 1
fi

if [ -z "${DATA_FILE_NAME}" ] || [ -z "${TMPFS_PATH}" ]; then
    echo "DATA_FILE_NAME or TMPFS_PATH not set" >&2
    exit 1
fi

cp /test_data/${DATA_FILE_NAME} ${TMPFS_PATH}/${DATA_FILE_NAME}
timeout --signal=SIGKILL 5m /benchmarker/scripts/perf-benchmark.sh --quiet --parseable --mode file \
    --seed ${ZEEKSEED} --build ${ZEEKBIN} --data-file ${TMPFS_PATH}/${DATA_FILE_NAME} \
    --cpus ${ZEEKCPUS} \
    --zeek-extra-args "${PCAP_ARGS}"
