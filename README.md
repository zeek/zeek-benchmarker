# Zeek Benchmarker

This repo contains a set of python and bash scripts for running a remote benchmarking service for Zeek builds. It is intended for use with the Cirrus CI continuous integration service that Zeek uses for automated build and test, but could be adapted to run against other hosts as well.

It uses Docker for privilege separation when running the benchmark scripts.

## Requirements
- Python 3
- Docker

## Setup

1. Edit the benchmark.py script and set the HMAC_KEY variable to an HMAC key hash. This key will be used for hashing the requests based on a set of data passed as part of the request. As mentioned in the comment in the script, this needs to be a python byte-string, not a plain string.
2. Edit the benchmark.py script and set the DATA_FILE variable to a path that contains a pcap file used for benchmarking.
3. Edit the benchmark.py script and set the host, port, and SSL information at the bottom of the file. This information will be used for running flask.
4. Create a python virtualenv in the same directory as the script, and use `pip` to install the required python modules listed in `requirements.txt`
5. If systemd support is desired, edit the zeek-benchmarker.service file, update the `<path>` values to the location of the script, and copy it into the proper directory for systemd (usually `/etc/systemd/system`).
6. Create the base docker image using the command `docker build -t zeek-benchmarker -f Dockerfile.base .`. This command should be run from within the `zeek-benchmarker` directory. This creates a base image that includes all of the common files that every benchmark run will require. The base image requires the `centos-8` image to be available in order to build.
7. By default the benchmarker runs on a system with a large amount of CPUs, and we limit the CPUs used to a specific set. This is set in the `app.config['CPU_SET']` variable. If used on a system with fewer CPUs, this needs to be updated.

## Supported Endpoints

### `/zeek`:

This endpoint is used to benchmark builds of the primary Zeek repo based on PRs and marges from the Cirrus CI system.

#### Required header values and arguments:

- Header value `Zeek-HMAC`: This is the HMAC value computed from the combination of the endpoint and a request timestamp, in the form of `zeek-<timestamp>`, using the key provided in the HMAC_KEY variable in the script.
- Header value `Zeek-HMAC-Timestamp`: This is the timestamp used in the above computation.
- Argument `branch`: The full branch name being tested. This will be checked by `git` to ensure that it is a valid branch name.
- Argument `build`: The full URL to the build being tested. By default the script checks to ensure that the URL is coming from the Cirrus infrastructure.
- Argument `build_hash`: An md5 hash of the build file.

#### Output

The benchmark outputs the amount of time it took to read and process the `DATA_FILE` and the maximum amount of memory used to process it, as such:

```
Time spent: 97.25 seconds
Max memory usage: 2125832 bytes
```