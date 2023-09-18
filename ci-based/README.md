# Zeek Benchmarker

This repo contains a set of python and bash scripts for running a remote benchmarking service for Zeek and Broker builds. It is intended for use with the Cirrus CI continuous integration service that Zeek uses for automated build and test, but could be adapted to run against other hosts as well.

It uses Docker for privilege separation when running the benchmark scripts.

## Requirements
- Python 3
- Docker
- Docker-compose

## Setup

0. Copy `config.yml.template` to `config.yml`

1. Create external docker volumes as described at the top of the docker-compose file:
   - test_data (bind): A path containing pcaps for zeek benchmarks
   - broker_test_data (bind): A path containing a cluster configuration data file for broker benchmarks
   - zeek_install_data (volume): A volume holding the Zeek installation
   - app_spool_data (volume): Volume holding data while working on jobs.

2. Create the necessary container images by running the following.

   sudo docker-compose build
   sudo docker build -f Dockerfile . -t zeek-benchmarker-zeek-runner

3. Edit the config.yml and set the values as described in that file.
4. Run `docker-compose up`. You may want to configure systemd such
   that the `docker-compose up` runs at boot time.


## Supported Endpoints

### `/zeek`:

This endpoint is used to benchmark builds of the primary Zeek repo based on PRs and marges from the Cirrus CI system.

#### Required header values and arguments:

- Header value `Zeek-HMAC`: This is the HMAC value computed from the combination of the endpoint and a request timestamp, in the form of `zeek-<timestamp>`, using the key provided in the HMAC_KEY variable in the script.
- Header value `Zeek-HMAC-Timestamp`: This is the timestamp used in the above computation.
- Argument `branch`: The full branch name being tested. This will be checked by `git` to ensure that it is a valid branch name.
- Argument `build`: The full URL to the build being tested. By default the script checks to ensure that the URL is coming from the Cirrus infrastructure.
- Argument `build_hash`: A sha256 hash of the build file.

#### Output

The benchmark outputs the amount of time it took to read and process the `DATA_FILE` and the maximum amount of memory used to process it, as such:

```
Time spent: 97.25 seconds
Max memory usage: 2125832 bytes
```

### `/broker`:

This endpoint is used to benchmark builds of the primary Broker repo based on PRs and marges from the Cirrus CI system.

#### Required header values and arguments:

- Header value `Zeek-HMAC`: This is the HMAC value computed from the combination of the endpoint and a request timestamp, in the form of `zeek-<timestamp>`, using the key provided in the HMAC_KEY variable in the script.
- Header value `Zeek-HMAC-Timestamp`: This is the timestamp used in the above computation.
- Argument `branch`: The full branch name being tested. This will be checked by `git` to ensure that it is a valid branch name.
- Argument `build`: The full URL to the build being tested. By default the script checks to ensure that the URL is coming from the Cirrus infrastructure.
- Argument `build_hash`: A sha256 hash of the build file.

#### Output

The benchmark returns the output from the broker-cluster-benchmark included with Broker:

```
zeek-recording-logger (sending): 0.0098869s
zeek-recording-manager (sending): 0.584391s
zeek-recording-proxy (sending): 1.00211s
zeek-recording-worker (receiving): 1.00507s
zeek-recording-proxy (receiving): 14.334s
zeek-recording-manager (receiving): 14.3401s
zeek-recording-worker (sending): 14.7662s
zeek-recording-logger (receiving): 15.2519s
system: 15.2516s
```
