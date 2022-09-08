FROM ubuntu:22.04

RUN apt-get update -y
RUN apt-get install -y openssl python3 iproute2 tcpreplay time linux-tools-common

RUN mkdir /benchmarker
WORKDIR /benchmarker
COPY random.seed /benchmarker
