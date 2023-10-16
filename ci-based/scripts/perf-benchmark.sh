#!/bin/bash

# Default options
ZEEK_BUILD=""
ZEEK_EXTRA_ARGS=""
DATA_FILE=""
MODE="intf"
INTERFACE=""
SEED_FILE=""
QUIET=0
ZEEK_CPU=20
TCPREPLAY_CPU=21
PARSEABLE=0

# Path where flamegraph is installed
FLAMEGRAPH_PATH=""
FLAMEGRAPH_PREFIX="benchmark"

# Path to perf
PERF_BINARY=/bin/perf

usage() {
    usage="\
Usage: $0 -b [zeek binary path] -d [data file path]

  Options:
    -b, --build PATH        The path to a Zeek binary to benchmark
    -d, --data-file PATH    The path to a data file to read from for replay
    -m, --mode MODE         This can be one of three possible values:
                            intf, read, or flamegraph. This controls what
                            mode is used for the benchmark run, and defaults
                            to intf if not passed. The modes are described
                            below.
    -i, --interface INTF    The network interface to use for capturing data.
                            This interface should be completely idle, since
                            tcpreplay will be using it to replay the data.
                            This argument is ignored if the mode is 'file'.
    -f, --flamegraph PATH   The path to the directory where Flamegraph is
                            installed. This argument is required if the mode
                            is 'flamegraph', but is ignored otherwise.
    -o, --output FILE       The file prefix to use as output for Flamegraph.
                            This defaults to 'benchmark'. This argument is ignored
                            if the mode is not 'flamegraph'.
    -s, --seed FILE         (optional) A path to a Zeek random seed file.
                            This is used control the generation of connection
                            IDs and other data so it is consistent between
                            benchmarking runs.
    -q, --quiet             Only log the output of tests.
    -c, --cpus              A comma-separated list of two CPUs to pin the Zeek
                            and tcpreplay processes to, respectively. This
                            defaults to CPUs 20 and 21. See the note below
                            about running on lower-power systems. For example
                            to use CPUs 3 and 4, pass this argument as 3,4.
    -p, --parseable         Modifies the output for the read mode to be more
                            easily parsed. This is used by the automated
			    benchmarker to calculate averages between
			    multiple runs. It has no effect in any other
			    modes.

    By default or when 'intf' is passed for the mode argument, the output will
    include CPU, memory, etc statistics from Zeek processing all of the data
    in the data file as if it was reading it live from the network. This mode
    requires an interface to be passed using the -i argument.

    When 'file' is passed for the mode (-m) argument, the output will include
    the runtime and maximum memory usage of Zeek when reading the data file
    directly from disk.

    When 'flamegraph' is passed for the mode (-m) argument, this script will
    output two flamegraphs for the process runtime in svg format. The first
    flamegraph is a standard graph showing the time spent in functions,
    stacked in the normal manner. The second graph is 'stack-reversed'.

    Symbols in Flamegraph outputs may not correctly stack unless the various
    libraries linked into Zeek are built with frame pointers. This includes
    glibc, libpcap, and openssl. Rebuilding those libraries with the
    -fno-omit-frame-pointer compiler flag may provide more accurate output.
    You can set libraries that get preloaded by setting the PRELOAD_LIBS
    varaible in the script.

    This script assumes that it is being run on a system with a large number
    of CPU cores. If being used on a smaller system, modify this script and
    set the ZEEK_CPU and TCPREPLAY_CPU variables to smaller values or pass
    the --cpus argument.
"

    echo "${usage}"
    exit 1
}

while (("$#")); do
    case "$1" in
        -d | --data-file)
            DATA_FILE=$2
            shift 2
            ;;
        -b | --build)
            ZEEK_BUILD=$2
            shift 2
            ;;
        -m | --mode)
            MODE=$2
            shift 2
            ;;
        -i | --interface)
            INTERFACE=$2
            shift 2
            ;;
        -f | --flamegraph)
            FLAMEGRAPH_PATH=$2
            shift 2
            ;;
        -o | --output)
            FLAMEGRAPH_PREFIX=$2
            shift 2
            ;;
        -s | --seed)
            SEED_FILE=$2
            shift 2
            ;;
        -q | --quiet)
            QUIET=1
            shift 1
            ;;
        -c | --cpus)
            CPU_ARRAY=($(echo $2 | tr ',' "\n"))
            ZEEK_CPU=${CPU_ARRAY[0]}
            if [ ${#CPU_ARRAY[@]} -gt 1 ]; then
                TCPREPLAY_CPU=${CPU_ARRAY[1]}
            fi
            shift 2
            ;;
        -p | --parseable)
            PARSEABLE=1
            shift 1
            ;;
        --zeek-extra-args)
            ZEEK_EXTRA_ARGS="${2}"
            shift 2
            ;;
        -h | --help)
            usage
            ;;
        *)
            echo "Invalid option '$1'.  Try $0 --help to see available options."
            exit 1
            ;;
    esac
done

if [ "${MODE}" != "intf" -a "${MODE}" != "file" -a "${MODE}" != "flamegraph" ]; then
    echo "Error: -m argument should be one of 'intf', 'file', or 'flamegraph'"
    echo
    usage
fi

if [ -z "${ZEEK_BUILD}" ]; then
    echo "Error: -b argument is required and should point at a Zeek binary"
    echo
    usage
fi

if [ -z "${DATA_FILE}" ]; then
    echo "Error: -d argument is required and should point at a pcap file to replay"
    echo
    usage
fi

if [ "${MODE}" != "file" -a -z "${INTERFACE}" ]; then
    echo "Error: -i argument is required for the ${MODE} mode and should point to an idle network interface"
    echo
    usage
fi

PRELOAD_LIBS=""

ZEEK_ARGS=""
if [ "${MODE}" != "file" ]; then
    ZEEK_ARGS="-i af_packet::${INTERFACE}"
fi

if [ -n "${SEED_FILE}" ]; then
    ZEEK_ARGS="${ZEEK_ARGS} -G ${SEED_FILE}"
fi

if [ -n "${ZEEK_EXTRA_ARGS}" ]; then
    ZEEK_ARGS="${ZEEK_ARGS} ${ZEEK_EXTRA_ARGS}"
fi

if [ "${MODE}" = "intf" ]; then

    TIME_FILE=$(mktemp)

    if [ ${QUIET} -eq 0 ]; then
        echo "####### Testing reading data file from a network interface #######"
        echo "Using CPU ${ZEEK_CPU} for zeek and CPU ${TCPREPLAY_CPU} for tcpreplay"
        echo "Running '${ZEEK_BUILD} ${ZEEK_ARGS}' against ${DATA_FILE}"
    fi

    # Start zeek, find it's PID, then wait 10s to let it reach a steady state
    taskset --all-tasks --cpu-list $ZEEK_CPU /usr/bin/time -f "%M" -o $TIME_FILE $ZEEK_BUILD $ZEEK_ARGS &
    TIME_PID=$!

    sleep 5
    ZEEK_PID=$(ps -ef | awk -v timepid="${TIME_PID}" '{ if ($3 == timepid) { print $2 } }')
    renice -20 -p $ZEEK_PID >/dev/null
    sleep 5

    if [ ${QUIET} -eq 0 ]; then
        echo "Zeek running on PID ${ZEEK_PID}"
    fi

    # Start perf stat on the zeek process
    ${PERF_BINARY} stat -p $ZEEK_PID &
    PERF_PID=$!

    # Start replaying the data
    if [ ${QUIET} -eq 0 ]; then
        echo "Starting replay"
    fi
    taskset --all-tasks --cpu-list $TCPREPLAY_CPU tcpreplay --preload-pcap -i $INTERFACE -q $DATA_FILE

    # Capture the average CPU usage of the process
    CPU_USAGE=$(ps -p $ZEEK_PID -o %cpu=)

    # Kill everything
    echo
    kill -2 $ZEEK_PID
    wait $TIME_PID
    wait $PERF_PID

    echo "Maximum memory usage (max_rss): $(head -n 1 ${TIME_FILE}) KB"
    echo "Average CPU usage: ${CPU_USAGE}%"

    rm $TIME_FILE

elif [ "${MODE}" = "file" ]; then

    TIME_FILE=$(mktemp)

    if [ ${QUIET} -eq 0 ]; then
        echo "####### Testing reading the file directly from disk #######"
        echo "Using CPU ${ZEEK_CPU} for zeek"
    fi
    taskset --all-tasks --cpu-list $ZEEK_CPU /usr/bin/time -f "BENCHMARK_TIMING=%e;%M;%U;%S" -o $TIME_FILE $ZEEK_BUILD $ZEEK_ARGS -r $DATA_FILE
    TIME_PID=$!
    ZEEK_PID=$(ps -ef | awk -v timepid="${TIME_PID}" '{ if ($3 == timepid) { print $2 } }')
    renice -20 -p $ZEEK_PID >/dev/null

    if [ ${PARSEABLE} -eq 0 ]; then
        awk '{print "Time spent: " $1 " seconds\nMax memory usage: " $2 " KB"}' $TIME_FILE
    else
        cat $TIME_FILE
    fi

    rm $TIME_FILE

elif [ "${MODE}" = "flamegraph" ]; then

    if [ ${QUIET} -eq 0 ]; then
        echo "####### Generating flamegraph data #######"
        echo "Using CPU ${ZEEK_CPU} for zeek and CPU ${TCPREPLAY_CPU} for tcpreplay"
    fi

    PERF_RECORD_FILE=$(mktemp)
    PERF_COLLAPSED_FILE=$(mktemp)

    # Start zeek under perf record, then sleep for a few seconds to let it actually start up. For runs with
    # shorter amounts of data or with slower traffic, you can add '-c 499' here to get finer-grained results.
    # With big data sets, it just results in the graph getting blown out by waits in the IO loop.
    LD_PRELOAD=${PRELOAD_LIBS} ${PERF_BINARY} record -g -o $PERF_RECORD_FILE -- $ZEEK_BUILD $ZEEK_ARGS &
    PERF_PID=$!

    sleep 5

    ZEEK_PID=$(ps -ef | awk -v perfpid="${PERF_PID}" '{ if ($3 == perfpid) { print $2 } }')
    if [ ${QUIET} -eq 0 ]; then
        echo "Zeek running on PID ${ZEEK_PID}"
    fi

    # Start replaying the data
    if [ ${QUIET} -eq 0 ]; then
        echo "Starting replay"
    fi
    taskset --all-tasks --cpu-list $TCPREPLAY_CPU tcpreplay --preload-pcap -i $INTERFACE -q $DATA_FILE

    # Kill everything
    echo
    kill -2 $ZEEK_PID
    wait $PERF_PID

    echo
    if [ ${QUIET} -eq 0 ]; then
        echo "####### Collapsing perf stack data #######"
    fi
    ${PERF_BINARY} script -i $PERF_RECORD_FILE | c++filt | ${FLAMEGRAPH_PATH}/stackcollapse-perf.pl >$PERF_COLLAPSED_FILE

    if [ ${QUIET} -eq 0 ]; then
        echo "####### Building normal flamegraph, writing to ${FLAMEGRAPH_PREFIX}.svg #######"
    fi
    cat $PERF_COLLAPSED_FILE | ${FLAMEGRAPH_PATH}/flamegraph.pl >"${FLAMEGRAPH_PREFIX}.svg"

    if [ ${QUIET} -eq 0 ]; then
        echo "####### Building reverse flamegraph, writing to ${FLAMEGRAPH_PREFIX}-reversed.svg #######"
    fi
    cat $PERF_COLLAPSED_FILE | ${FLAMEGRAPH_PATH}/flamegraph.pl --reverse >"${FLAMEGRAPH_PREFIX}-reversed.svg"

    rm $PERF_RECORD_FILE
    rm $PERF_COLLAPSED_FILE

fi
