FROM centos:8

# Install everything needed for building Zeek from scratch
#
RUN dnf -y install epel-release dnf-plugins-core
RUN dnf config-manager --set-enabled powertools
RUN dnf -y update
RUN dnf -y install \
    bison \
    cmake \
    cronie \
    curl \
    elfutils-libelf-devel \
    flex \
    gcc \
    gcc-c++ \
    gdb \
    git \
    kernel-devel \
    kernel-headers \
    libpcap \
    libpcap-devel \
    net-tools \
    ninja-build \
    openssl-devel \
    python3 \
    python3-devel \
    rsync \
    sendmail \
    swig \
    tar \
    wget \
    zlib-devel
RUN dnf clean all

# Install t-rex and copy over the configuration. If this version
# changes make sure to update build.sh to match.
#
RUN mkdir -p /benchmark/trex
RUN curl -k -o /benchmark/trex/trex-v2.89.tar.gz https://trex-tgn.cisco.com/trex/release/v2.89.tar.gz
RUN cd /benchmark/trex && tar -xzf trex-v2.89.tar.gz

# Copy over the build script and set the working directory for when
# the container starts up
#
COPY ./scripts/build.sh /benchmark

ARG SKIP_ZEEK_DEPLOY
ARG SKIP_TREX

WORKDIR /benchmark
RUN /benchmark/build.sh