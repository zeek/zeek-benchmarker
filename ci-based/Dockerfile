FROM ubuntu:22.04

RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install --no-install-recommends -y \
    iproute2 \
    libmaxminddb0 \
    linux-tools-common \
    openssl \
    python3 \
    tcpreplay \
    time \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /benchmarker
COPY ./scripts ./scripts
COPY random.seed .
