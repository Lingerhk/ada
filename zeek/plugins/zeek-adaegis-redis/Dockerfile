# Build the plugin against the latest zeekurity/zeek-dev image
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

WORKDIR /src
COPY . .
RUN rm -rf ./build && \
  ./configure && \
  make && \
  make install && \
  cp /src/build/Zeek_Redis.tgz /usr/local/zeek/Zeek_Redis.tgz && \
  rm -rf /src

WORKDIR /usr/local/zeek

# Smoke check the plugin loads...
RUN zeek -N Zeek::Redis

CMD ["zeek", "-i", "lo"]