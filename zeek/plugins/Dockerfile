# Build the ada_zeek based on zeek:7.1.0(local)
ARG IMAGE=zeek:7.1.0
FROM $IMAGE

RUN apt-get update && apt-get -y --no-install-recommends install \
    cmake curl \
    libpcap-dev \
    libssl-dev \
    libhiredis-dev \
    build-essential \
    && apt autoclean \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L https://github.com/sewenew/redis-plus-plus/archive/refs/tags/1.3.12.tar.gz -o /tmp/redis-plus-plus-1.3.12.tar.gz \
    && cd /tmp \
    && tar -xzf redis-plus-plus-1.3.12.tar.gz \
    && cd redis-plus-plus-1.3.12 \
    && mkdir -p build \
    && cd build \
    && cmake .. \
    && make -j4\
    && make install \
    && rm -rf /tmp/redis-plus-plus-1.3.12 \
    && rm -rf /tmp/redis-plus-plus-1.3.12.tar.gz 

WORKDIR /tmp

######### build redis plugin
COPY zeek-adaegis-redis /tmp/zeek-adaegis-redis
RUN cd /tmp/zeek-adaegis-redis && \
  rm -rf ./build && \
  chmod +x ./configure && \
  ./configure && \
  make && \
  make install && \
  rm -rf /tmp/zeek-adaegis-redis

# Smoke check the plugin loads...
RUN zeek -N Zeek::Redis

######### build receiver plugin 
COPY zeek-adaegis-receiver /tmp/zeek-adaegis-receiver
RUN cd /tmp/zeek-adaegis-receiver && \
  rm -rf ./build && \
  chmod +x ./configure && \
  ./configure && \
  make && \
  make install && \
  rm -rf /tmp/zeek-adaegis-receiver

# Smoke check the plugin loads...
RUN zeek -N Zeek::TrafficReceiver


WORKDIR /usr/local/zeek
EXPOSE 9093/udp
CMD ["zeek", "-i", "trafficreceiver::0.0.0.0:9093"]