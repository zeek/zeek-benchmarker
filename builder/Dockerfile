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
    cyrus-sasl-plain \
    elfutils-libelf-devel \
    flex \
    gcc \
    gcc-c++ \
    gdb \
    git \
    kernel-devel \
    kernel-headers \
    libasan \
    libpcap \
    libpcap-devel \
    mailx \
    net-tools \
    ninja-build \
    openssl-devel \
    postfix \
    python3 \
    python3-devel \
    rsync \
    swig \
    tar \
    wget \
    zlib-devel
RUN dnf clean all
RUN rm -rf /var/cache/dnf

# Needed for zkg. Not normally used, but might be useful for debugging.
RUN pip3 install GitPython semantic-version

# Install t-rex and copy over the configuration. If this version
# changes make sure to update build.sh to match.
#
RUN mkdir -p /benchmark/trex
RUN curl -k -o /benchmark/trex/trex-v2.90.tar.gz https://trex-tgn.cisco.com/trex/release/v2.90.tar.gz
RUN cd /benchmark/trex && tar -xzf trex-v2.90.tar.gz
RUN ln -s /benchmark/trex/v2.90 /benchmark/trex/latest

RUN mkdir -p /etc/postfix/sasl
COPY configs/postfix/main.cf /etc/postfix/main.cf
COPY configs/postfix/sasl_passwd /etc/postfix/sasl/sasl_passwd
RUN chmod 644 /etc/postfix/main.cf
RUN postmap /etc/postfix/sasl/sasl_passwd
RUN chmod 600 /etc/postfix/sasl/*

# Set the working dir for when the container starts up. This can
# be reset via docker-compose.yml as well.
WORKDIR /benchmark
