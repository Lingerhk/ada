# Build the ada_zeek based on zeek:7.1.0(local)
FROM ada_zeek:7.1.0

ENV SERVICE_NAME=ada_zeek

LABEL maintainer="dev@ada"
ARG ADA_VERSION=dev
LABEL version=${ADA_VERSION}
LABEL description="Docker image for ada system zeek service"

RUN sed -i 's/127.0.0.1/ada_redis/g' /usr/local/zeek/lib/zeek/plugins/Zeek_Redis/scripts/types.zeek

USER root
WORKDIR /usr/local/zeek

EXPOSE 9093/udp

CMD ["zeek", "-i", "trafficreceiver::0.0.0.0:9093"]