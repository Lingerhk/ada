# Build the plugin against the latest zeekurity/zeek-dev image
ARG IMAGE=zeek:7.1.0
FROM $IMAGE

RUN apt-get update && apt-get -y --no-install-recommends install \
    cmake \
    libpcap-dev \
    libssl-dev \
    build-essential \
  && apt autoclean \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN rm -rf ./build && \
  ./configure && \
  make && \
  make install && \
  cp /src/build/Zeek_TrafficReceiver.tgz /usr/local/zeek/Zeek_TrafficReceiver.tgz && \
  rm -rf /src

WORKDIR /usr/local/zeek

# Smoke check the plugin loads...
RUN zeek -N Zeek::TrafficReceiver

EXPOSE 9093/udp

CMD ["zeek", "-i", "trafficreceiver::0.0.0.0:9093"]