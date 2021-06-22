#!/usr/bin/env bash

export LD_LIBRARY_PATH="/benchmarker/broker/install/lib:/benchmarker/broker/install/lib64:${LD_LIBRARY_PATH}"
export PATH="/benchmarker/broker/install/bin:${PATH}"

if [ "$IS_LOCAL" = "0" ]; then
    tar -xzf /benchmarker/binaries/${BUILD_FILE_NAME} -C /benchmarker
fi

cp -r /test_data ${TMPFS_PATH}
cd ${TMPFS_PATH}/test_data
timeout --signal=SIGKILL 30s broker-cluster-benchmark -c ${DATA_FILE_NAME}
