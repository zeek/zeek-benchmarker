# Zeek Builder Benchmark

This directory contains Docker configuration and set of scripts/config files to run builds of Zeek for benchmarking. The purpose of this is to repeatedly run builds of Zeek from the master branch and to benchmark their performance over long periods of time, allowing us to find performance issues that do not present themselves in normal testing.

## Requirements

- Docker

## Setup

1. Create three docker volumes named prometheus_data, grafana_data, and zeek_logs
2. Modify the docker-compose.yml file to set the paths to the config and scripts directories, and to set the IPs used by the containers if desired.
  - Note that if you change the IPs here, you also need to modify `config/prometheus/prometheus.yml` to match.
3. Build the base builder Docker image by running: `docker-compose build builder`
4. Start the prometheus and grafana containers in the background by running: `docker-compose up -d grafana` and `docker-compose up -d prometheus`

The builder can now be run by calling `docker-compose up builder`. By default this will build from master and run a t-rex simulation for 3 days. Prometheus will store data for 26 weeks. You can modify the runtime in `scripts/build.sh`.

Grafana graphs are not configured out of the box. You will need to manually enable the Prometheus data source and configure the graphs.

### Automating

If you want builds to run automatically you can add the following to following to cron:

```
docker compose rm -f builder && docker compose up -d builder
```

## TODO

- Alerting via email, including Zeek failures and notices
- Replace hard coded paths in docker-compose.yml with something more configurable
- Default graph configurations for Grafana
- Autoprune dead builder containers after the benchmark passes run
