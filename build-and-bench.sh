#!/bin/sh

BASE_DIR=$1

git clone --recursive --depth=1 --branch topic/timw/finals https://github.com/zeek/zeek.git src
mkdir install
cd src
./configure --prefix=${BASE_DIR}/install --generator=Ninja --build-type=release
cd build
ninja
ninja install

cd $BASE_DIR
mkdir logs
cd logs
${BASE_DIR}/perf-benchmark -m file -s ${BASE_DIR}/src/testing/btest/random.seed -b ${BASE_DIR}/install/bin/zeek -d /mnt/data/test_data/ixia_data_2m_500Mbps.pcap | tee ${BASE_DIR}/benchmark.log

cd ${BASE_DIR}
rm -rf src
rm -rf install
rm -rf logs
