#!/usr/bin/env bash

# Script for running the benchmarking system from cron. This checks for the date
# to be a multiple of five so that the builder can run for three days and then
# pause for two. This script needs to be run as root or as a user with access to
# manage docker containers.

if [ $(($(date +\%s) / 86400 % 5)) != 0 ]; then
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
echo $SCRIPT_DIR

cd $SCRIPT_DIR
cd ..

/usr/local/bin/docker-compose stop builder
/usr/local/bin/docker-compose up --force-recreate -d builder
