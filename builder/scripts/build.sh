#!/usr/bin/env bash

GRAFANA_DASHBOARD=https://localhost:3000
SCRIPT_PATH=/benchmark
INSTALL_PATH=${SCRIPT_PATH}/install
SOURCE_PATH=${SCRIPT_PATH}/zeek

# Save this off at the start of the run because we're going to need it for storing
# logs at the end of the run
CURRENT_DATE=$(date +%Y-%m-%d)

# Steal some email information from the zeekctl.cfg file so we don't have to
# duplicate it here
MAIL_FROM=$(gawk '/MailFrom\s+=/ {print $3}' ${SCRIPT_PATH}/configs/zeekctl/zeekctl.cfg)
MAIL_TO=$(gawk '/MailTo\s+=/ {print $3}' ${SCRIPT_PATH}/configs/zeekctl/zeekctl.cfg)

BRANCH=${ZEEK_BRANCH:-master}
RUN_TIME=${ZEEK_RUN_LENGTH:-3600}

function send_email() {

    sendmail "${MAIL_TO}" <<EOF
From: OS-Perf-2 Benchmarker <${MAIL_FROM}>
Subject: ${1}

${2}
EOF

}

function send_error_email() {

    sendmail "${MAIL_TO}" <<EOF
From: OS-Perf-2 Benchmarker <${MAIL_FROM}>
Subject: Builder benchmark pass failed

${2}
EOF

    # Sleep for a few seconds to let the email send
    sleep 10
    exit 1
}

# clone master
echo
echo "=== Cloning Zeek ${BRANCH} branch ==="
git clone --branch ${BRANCH} --recursive https://github.com/zeek/zeek ${SOURCE_PATH} || send_error_email "Git clone of zeek branch failed"

# configure a build
echo
echo "=== Configuring build ==="
cd ${SOURCE_PATH}
HEAD_COMMIT_FULL=$(git log -1 --pretty="%H %B")
HEAD_COMMIT=$(git rev-parse HEAD)

if [ ${SKIP_BUILD:-0} -ne 1 ]; then
    ./configure --generator=Ninja --build-type=relwithdebinfo --enable-jemalloc --disable-python --disable-broker-tests --disable-btest --disable-btest-pcaps --prefix=${INSTALL_PATH} || send_error_email "configure failed"

    # build/install
    echo
    echo "=== Building and installing ==="
    cd build
    ninja install || send_error_email "Build failed"
    export PATH=${INSTALL_PATH}/bin:${PATH}
fi

START_TIME=$(date)

if [ ${SKIP_BUILD:-0} -ne 1 -a ${SKIP_ZEEK_DEPLOY:-0} -ne 1 ]; then

    # copy zeekctl config
    echo
    echo "=== Copying zeekctl configuration ==="
    cp ${SCRIPT_PATH}/configs/zeekctl/*.cfg ${INSTALL_PATH}/etc

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
    cron

    # disable checksums for t-rex data to process correctly
    echo "redef ignore_checksums = T;" >>${INSTALL_PATH}/share/zeek/site/local.zeek

    #zkg install --force zeek-jemalloc-profiling

    # start up zeek
    echo
    echo "=== Starting zeek ==="
    zeekctl deploy || send_error_email "zeekctl deploy failed"

fi

if [ ${SKIP_TREX:-0} -ne 1 ]; then

    # This symlink is required to run t-rex in ASTF mode.
    if [ ! -e /usr/lib/x86_64-linux-gnu/liblibc.a ]; then
        ln -s /usr/lib/x86_64-linux-gnu/libc.a /usr/lib/x86_64-linux-gnu/liblibc.a
    fi

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
    (source ${SCRIPT_PATH}/trex/trex-venv/bin/activate &&
        LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libstdc++.so.6 ./t-rex-64 --cfg ${SCRIPT_PATH}/configs/trex_cfg.yaml --astf -f astf/sfr.py -m 4 -d ${RUN_TIME} --nc)

fi

if [ ${SKIP_BUILD:-0} -ne 1 -a ${SKIP_ZEEK_DEPLOY:-0} -ne 1 ]; then

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
ST_EPOCH=$(($(date --date="${START_TIME}" +"%s") - 600))
ST_EPOCH=$((${ST_EPOCH} * 1000))
ET_EPOCH=$(($(date --date="${END_TIME}" +"%s") + 600))
ET_EPOCH=$((${ET_EPOCH} * 1000))

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
echo "=== Sleeping to let email send (10s delay) ==="
sleep 10

echo
echo "=== Done ==="
