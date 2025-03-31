FROM ubuntu:24.04

ENV SERVICE_NAME=ada_zeek

LABEL maintainer="dev@ada"
LABEL version="2.6"
LABEL description="Docker image for ada system zeek service"

RUN useradd -rm -d /home/adadmin -s /bin/bash -g root -G sudo -u 1001 adadmin

RUN set -x \
    && mkdir -p /home/adadmin/logs \
    && mkdir -p /home/adadmin/bin

# Install dependencies
RUN set -x \
    && apt-get update \
    && apt-get -y install g++ cmake flex bison swig supervisor \
    && apt-get -y install libfl-dev libpcap-dev libssl-dev zlib1g-dev libkrb5-dev libmaxminddb-dev libhiredis-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# install redis-plus-plus
COPY redis-plus-1.3.12.tar.gz /home/adadmin/
RUN set -x \
    && cd /home/adadmin \
    && tar -zxf redis-plus-1.3.12.tar.gz \
    && cd redis-plus-plus-1.3.12 \
    && mkdir build \
    && cd build \
    && cmake .. \
    && make -j4\
    && make install \
    && rm -rf /home/adadmin/redis-plus-1.3.12.tar.gz

# Install zeek
COPY zeek.bin.7.1.0.tar.gz /home/adadmin/
COPY plugins/sedara_Redis-0.4.0.tar.gz /home/adadmin/
COPY plugins/Zeek_TrafficOverUdp-1.0.0.tar.gz /home/adadmin/

RUN set -x \
    && cd /home/adadmin \
    && tar -C /usr/local -xzf zeek.bin.7.1.0.tar.gz \
    && tar -C /usr/local/zeek/lib/zeek/plugins -xzf sedara_Redis-0.4.0.tar.gz \
    && tar -C /usr/local/zeek/lib/zeek/plugins -xzf Zeek_TrafficOverUdp-1.0.0.tar.gz \
    && rm -rf zeek.bin.7.1.0.tar.gz \
    && rm -rf sedara_Redis-0.4.0.tar.gz \
    && rm -rf Zeek_TrafficOverUdp-1.0.0.tar.gz \
    && chown -R adadmin:root /home/adadmin \
    && sed -i 's/127.0.0.1/ada_redis/g' /usr/local/zeek/lib/zeek/plugins/sedara_Redis/scripts/types.zeek

USER root
WORKDIR /usr/local/zeek

#CMD ["sleep", "3600"]
CMD ["./bin/zeek", "-i", "trafficoverudp::0.0.0.0:9093", "-B", "plugin-Zeek-TrafficOverUdp"]