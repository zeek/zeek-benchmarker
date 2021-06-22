FROM centos:8

RUN dnf -y install epel-release dnf-plugins-core
RUN dnf config-manager --set-enabled PowerTools
RUN dnf -y update
RUN dnf -y install \
    openssl \
    python3 \
    iproute \
    perf \
    tcpreplay \
    time
RUN dnf clean all
RUN rm -rf /var/cache/dnf

RUN mkdir /benchmarker
WORKDIR /benchmarker
COPY random.seed /benchmarker
