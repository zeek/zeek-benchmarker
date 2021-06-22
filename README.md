# Zeek Benchmarkers

This repo contains two separate benchmarking systems for Zeek.

- ci-based: This is a system for running short benchmarks of builds of Zeek and Broker via incoming HTTP requests from Cirrus CI. It uses recorded data to generate simple CPU and memory usage data. The output is returned both to the CI request and to an SQLite database. The latter can be used to visualize results over time on Grafana or the like.

- builder: This is a system for running long-term benchmarks of builds of Zeek locally on the benchmark host and reporting the state of the process via Prometheus.
