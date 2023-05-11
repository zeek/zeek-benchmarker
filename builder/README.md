# Zeek Builder Benchmark

This directory contains Docker configuration and set of scripts/config files to
run builds of Zeek for benchmarking. The purpose of this is to repeatedly run
builds of Zeek from the master branch and to benchmark their performance over
long periods of time, allowing us to find performance issues that do not present
themselves in normal testing.

## Requirements

- Docker

## Configuration Setup

- config/ssmtp/revaliases:
  - Set the various fields as described in the sample line
- config/ssmtp/ssmtp.conf:
  - Set the various fields as described in the sample lines
- configs/zeekctl/zeekctl.cfg:
  - Set the `MailTo` option to a destination address for reports from Zeek.
- scripts/build.sh
  - If a longer or shorter runtime for the benchmark is desired, modify the `-d`
    argument in the call to `t-rex-64`. This value is in seconds.

## Setup

Build the base builder Docker image by running: `docker-compose build builder`

The builder can now be run by calling `docker-compose up builder`. By default
this will build from master and run a t-rex simulation for 3 days. You can
modify the runtime in `scripts/build.sh`.

Ports are exposed from the builder container to provide metrics to Prometheus on
ports 4040-4042 and ports 4051-4058 by default. These can be fed into Grafana to
display as graphs.

### Automating

If you want builds to run automatically you can add the following to following
to cron:

```
docker-compose rm -f builder && docker-compose up -d builder
```

The `scripts/cron.sh` script exists as well to automate running a build every 5
days from `cron`. It takes into account that cron doesn't handle the end of
months very well, and can be called directly from a crontab instead.

## TODO

- Default graph configurations for Grafana
