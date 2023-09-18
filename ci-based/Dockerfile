FROM ubuntu:22.04

RUN apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
    iproute2 \
    libmaxminddb0 \
    linux-tools-common \
    openssl \
    python3 \
    tcpreplay \
    time

WORKDIR /benchmarker
COPY ./scripts ./scripts
COPY random.seed .
