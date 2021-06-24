# Zeek Builder Benchmark

This directory contains Docker configuration and set of scripts/config files to run builds of Zeek for benchmarking. The purpose of this is to repeatedly run builds of Zeek from the master branch and to benchmark their performance over long periods of time, allowing us to find performance issues that do not present themselves in normal testing.

## Requirements

- Docker

## Configuration Setup

- docker-compose.yml:
  - Modify the IP addresses if desired. The default IPs used here should fall within the typical blocks of IPs used by Docker and should be ok for most setups.
  - Note that if you change the IP addresses here you must modify `config/prometheus/prometheus.yml` to match.
- config/postfix/main.cf:
  - Set the `myorigin` option to the FQDN for the Docker host.
- config/postfix/sasl_passwd:
  - This uses gmail as the upstream SMTP server by default. This requires setting the email address and an app password for a gmail account used for authentication.
- configs/zeekctl/zeekctl.cfg:
  - Set the `MailTo` option to a destination address for reports from Zeek.
- scripts/build.sh
  - If a longer or shorter runtime for the benchmark is desired, modify the `-d` argument in the call to `t-rex-64`. This value is in seconds.

## Setup

1. Create three docker volumes named prometheus_data, grafana_data, and zeek_logs. See a comment in `docker-compose.yml` for how to do this.
2. Build the base builder Docker image by running: `docker-compose build builder`
3. Start the prometheus and grafana containers in the background by running: `docker-compose up -d grafana` and `docker-compose up -d prometheus`

The builder can now be run by calling `docker-compose up builder`. By default this will build from master and run a t-rex simulation for 3 days. Prometheus will store data for 26 weeks. You can modify the runtime in `scripts/build.sh`.

Grafana graphs are not configured out of the box. You will need to manually enable the Prometheus data source and configure the graphs.

### Automating

If you want builds to run automatically you can add the following to following to cron:

```
docker-compose rm -f builder && docker-compose up -d builder
```

## TODO

- Default graph configurations for Grafana
