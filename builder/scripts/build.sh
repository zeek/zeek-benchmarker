#!/usr/bin/env bash

GRAFANA_DASHBOARD=https://localhost:3000
SCRIPT_PATH=/benchmark
INSTALL_PATH=${SCRIPT_PATH}/install
SOURCE_PATH=${SCRIPT_PATH}/zeek
AF_PACKET_PATH=${SCRIPT_PATH}/zeek-af_packet-plugin

# Save this off at the start of the run because we're going to need it for storing
# logs at the end of the run
CURRENT_DATE=$(date +%Y-%m-%d)

# Steal some email information from the zeekctl.cfg file so we don't have to
# duplicate it here
MAIL_FROM=$(awk '/MailFrom/ {print $3}' ${SCRIPT_PATH}/configs/zeekctl/zeekctl.cfg)
MAIL_TO=$(awk '/MailTo/ {print $3}' ${SCRIPT_PATH}/configs/zeekctl/zeekctl.cfg)

BRANCH=master
RUN_TIME=259200

function send_email() {

    sendmail "${MAIL_TO}" <<EOF
From: ${MAIL_FROM}
Subject: ${1}
${2}
EOF

}

function send_error_email() {

    sendmail "${MAIL_TO}" <<EOF
From: ${MAIL_FROM}
Subject: Builder benchmark pass failed
${2}
EOF

    postfix flush
    sleep 10
    postfix stop
    exit 1

}

# We need postfix for a few things to send error messages externally, so start it
# up before getting started.
echo
echo "=== Starting postfix ==="
postfix start

# clone master
echo
echo "=== Cloning Zeek master branch ==="
git clone --branch ${BRANCH} --recursive https://github.com/zeek/zeek ${SOURCE_PATH} || send_error_email "Git clone of zeek branch failed"

# clone af_packet if it doesn't exist
if [ ! -d ${AF_PACKET_PATH} ]; then
    echo
    echo "=== Cloning AF_Packet plugin ==="
    git clone --recursive https://github.com/j-gras/zeek-af_packet-plugin ${AF_PACKET_PATH} || send_error_email "Git clone of zeek-af_packet-plugin failed"
fi

# configure master with af_packet plugin
echo
echo "=== Configuring build ==="
cd ${SOURCE_PATH}
HEAD_COMMIT_FULL=$(git log -1 --pretty="%H %B")
HEAD_COMMIT=$(git rev-parse HEAD)
START_TIME=$(date)
./configure --generator=Ninja --build-type=relwithdebinfo --enable-jemalloc --disable-python --disable-broker-tests --disable-btest --disable-btest-pcaps --include-plugins=${AF_PACKET_PATH} --prefix=${INSTALL_PATH} || send_error_email "configure failed"

# build/install
echo
echo "=== Building and installing ==="
cd build
ninja install || send_error_email "Build failed"
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

    # disable checksums for t-rex data to process correctly
    echo "redef ignore_checksums = T;" >>${INSTALL_PATH}/share/zeek/site/local.zeek

    # start up zeek
    echo
    echo "=== Starting zeek ==="
    zeekctl deploy || send_error_email "zeekctl deploy failed"

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
    ./t-rex-64 --cfg ${SCRIPT_PATH}/configs/trex_cfg.yaml -f cap2/sfr3.yaml -m 4 -d ${RUN_TIME} --nc

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

END_TIME=$(date)
ST_EPOCH=$(($(date --date="${START_TIME}" +"%s")-1800))
ST_EPOCH=$((${ST_EPOCH}*1000))
ET_EPOCH=$(($(date --date="${END_TIME}" +"%s")+1800))
ET_EPOCH=$((${ET_EPOCH}*1000))
read -r -d '' RESULT_EMAIL <<-EOF
Builder benchmark pass was completed.

Commit:
${HEAD_COMMIT_FULL}
https://github.com/zeek/zeek/commit/${HEAD_COMMIT}

Run started: ${START_TIME}
Run finished: ${END_TIME}
Grafana: ${GRAFANA_DASHBOARD}?orgId=1&from=${ST_EPOCH}&to=${ET_EPOCH}

EOF

send_email "Builder benchmark completed" "${RESULT_EMAIL}"

# This shouldn't be necessary but flush postfix and sleep for a bit so any email
# gets out of the queue before shutting down and destroying the container.
echo "=== Flushing and shutting down postfix (10s delay) ==="
postfix flush
sleep 10
postfix stop

echo
echo "=== Done ==="
