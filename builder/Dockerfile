FROM ubuntu:22.04

# Install everything needed for building Zeek from scratch
#
RUN apt update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
    bison \
    bzip2 \
    cmake \
    cron \
    curl \
    flex \
    gawk \
    gcc \
    g++ \
    gdb \
    git \
    iproute2 \
    libjemalloc2 \
    libjemalloc-dev \
    linux-headers-generic \
    libasan6 \
    libpcap-dev \
    libssl-dev \
    net-tools \
    ninja-build \
    pciutils \
    python3 \
    python3-dev \
    python3-pip \
    python3-pip-whl \
    python3-semantic-version \
    python3-yaml \
    rsync \
    ssmtp \
    swig \
    tar \
    vim \
    wget \
    zlib1g-dev

# Needed for zkg. Not normally used, but might be useful for debugging.
RUN pip3 install GitPython

# Install t-rex and copy over the configuration. If this version
# changes make sure to update build.sh to match.
#
RUN mkdir -p /benchmark/trex
RUN curl -k -o /benchmark/trex/trex-v2.99.tar.gz https://trex-tgn.cisco.com/trex/release/v2.99.tar.gz
RUN cd /benchmark/trex && tar -xzf trex-v2.99.tar.gz
RUN ln -s /benchmark/trex/v2.99 /benchmark/trex/latest

COPY configs/ssmtp/ssmtp.conf /etc/ssmtp/ssmtp.conf
COPY configs/ssmtp/revaliases /etc/ssmtp/revaliases

# Set the working dir for when the container starts up. This can
# be reset via docker-compose.yml as well.
WORKDIR /benchmark
