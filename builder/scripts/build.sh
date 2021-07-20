#!/usr/bin/env bash

SCRIPT_PATH=/benchmark
INSTALL_PATH=${SCRIPT_PATH}/install
SOURCE_PATH=${SCRIPT_PATH}/zeek
AF_PACKET_PATH=${SCRIPT_PATH}/zeek-af_packet-plugin

# Save this off at the start of the run because we're going to need it for storing
# logs at the end of the run
CURRENT_DATE=$(date +%Y-%m-%d)

# We need postfix for a few things to send error messages externally, so start it
# up before getting started.
echo
echo "=== Starting postfix ==="
postfix start

# clone master
echo
echo "=== Cloning Zeek master branch ==="
git clone --recursive https://github.com/zeek/zeek ${SOURCE_PATH} || exit

# clone af_packet if it doesn't exist
if [ ! -d ${AF_PACKET_PATH} ]; then
    echo
    echo "=== Cloning AF_Packet plugin ==="
    git clone --recursive https://github.com/j-gras/zeek-af_packet-plugin ${AF_PACKET_PATH} || exit
fi

# configure master with af_packet plugin
echo
echo "=== Configuring build ==="
cd ${SOURCE_PATH}
./configure --generator=Ninja --build-type=relwithdebinfo --disable-python --disable-broker-tests --disable-zkg --disable-btest --disable-btest-pcaps --include-plugins=${AF_PACKET_PATH} --prefix=${INSTALL_PATH} || exit

# build/install
echo
echo "=== Building and installing ==="
cd build
ninja install || exit
export PATH=${INSTALL_PATH}/bin:${PATH}

if [ ${SKIP_ZEEK_DEPLOY:-0} -ne 1 ]; then

    # copy zeekctl config
    echo
    echo "=== Copying zeekctl configuration ==="
    cp ${SCRIPT_PATH}/configs/zeekctl/*.cfg ${INSTALL_PATH}/etc
    cp ${SCRIPT_PATH}/configs/zeekctl/broker_metrics_port.py ${INSTALL_PATH}/lib64/zeek/python/zeekctl/plugins

    # We need a couple of network interfaces to run t-rex against, but we
    # unfortunately can't do this as part of the Dockerfile due to
    # permissions during the build. Do it here instead.
    echo
    echo "=== Creating network interfaces for Zeek/T-Rex ==="
    ip link add veth0 type veth peer name veth1
    ip addr add 192.168.1.1 dev veth0
    ip addr add 192.168.2.1 dev veth1
    ip link set veth0 up
    ip link set veth1 up

    # We can't run cron from systemd inside a docker container so just start
    # it up manually
    echo "*/5 * * * * /usr/local/zeek/bin/zeekctl cron" | crontab -
    crond

    # start up zeek
    echo
    echo "=== Starting zeek ==="
    zeekctl deploy || exit

fi

if [ ${SKIP_TREX:-0} -ne 1 ]; then

    # start up t-rex
    #
    # explanation of options here:
    # --cfg: the path to the config file we copied during Docker build
    # -f: the path to traffic configuration. sfr3.yaml is a general mix of protocols.
    # -m: the number of times the data in the traffic configuration is multiplied.
    #     by default srf3.yaml is about 100Mbps. setting this value higher increases
    #     the amount of data sent.
    # -d: the duration of the test
    # --nc: shut down quickly at the end of the duration without letting the flows
    #       fully expire.
    echo
    echo "=== Starting t-rex ==="
    cd ${SCRIPT_PATH}/trex/latest
    ./t-rex-64 --cfg ${SCRIPT_PATH}/configs/trex_cfg.yaml -f cap2/sfr3.yaml -m 4 -d 416000 --nc

fi

if [ ${SKIP_ZEEK_DEPLOY:-0} -ne 1 ]; then

    echo
    echo "=== Stopping zeek ==="
    zeekctl stop

    echo
    echo "=== Storing logs ==="
    COMMIT_HASH=$(cd /benchmark/zeek && git rev-parse --short HEAD)
    LOGS_PATH="/benchmark/zeek_logs/${CURRENT_DATE}-${COMMIT_HASH}"
    mkdir ${LOGS_PATH}
    cp -r ${INSTALL_PATH}/logs/${CURRENT_DATE} ${LOGS_PATH}
    mkdir ${LOGS_PATH}/processes
    cp -r ${INSTALL_PATH}/spool/logger-1 ${LOGS_PATH}/processes
    cp -r ${INSTALL_PATH}/spool/manager ${LOGS_PATH}/processes
    cp -r ${INSTALL_PATH}/spool/proxy-1 ${LOGS_PATH}/processes
    cp -r ${INSTALL_PATH}/spool/worker-1-* ${LOGS_PATH}/processes

fi

echo
echo "=== Done ==="
