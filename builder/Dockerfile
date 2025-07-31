FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install everything needed for building Zeek from scratch
#
RUN apt update -y
RUN apt-get install -y \
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
    python3-git \
    python3-pip \
    python3-pip-whl \
    python3-semantic-version \
    python3-yaml \
    rsync \
    software-properties-common \
    ssmtp \
    swig \
    tar \
    vim \
    wget \
    zlib1g-dev

# Newer versions of t-rex don't work with python 3.12. Install 3.11 from
# deadsnakes so it's available.
RUN add-apt-repository -y ppa:deadsnakes/ppa
RUN apt update -y && \
    apt install -y python3.11 python3.11-venv

# Install t-rex and copy over the configuration. If this version
# changes make sure to update build.sh to match.
#
RUN mkdir -p /benchmark/trex
RUN curl -k -o /benchmark/trex/trex-v3.06.tar.gz https://trex-tgn.cisco.com/trex/release/v3.06.tar.gz
RUN cd /benchmark/trex && tar -xzf trex-v3.06.tar.gz
RUN ln -s /benchmark/trex/v3.06 /benchmark/trex/latest
RUN python3.11 -m venv /benchmark/trex/trex-venv

COPY configs/ssmtp/ssmtp.conf /etc/ssmtp/ssmtp.conf
COPY configs/ssmtp/revaliases /etc/ssmtp/revaliases

# Set the working dir for when the container starts up. This can
# be reset via docker-compose.yml as well.
WORKDIR /benchmark
