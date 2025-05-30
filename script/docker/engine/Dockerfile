FROM ubuntu:24.04

ENV SERVICE_NAME=ada_engine
ENV ENGINE_CONF_PATH=/home/adadmin/conf/engine.yaml

LABEL maintainer="dev@ada"
LABEL version="2.9.1"
LABEL description="Docker image for ada system engine service"

RUN useradd -rm -d /home/adadmin -s /bin/bash -g root -G sudo -u 1001 adadmin

RUN set -x \
    && mkdir -p /home/adadmin/logs \
    && mkdir -p /home/adadmin/bin

COPY ./engine /home/adadmin/bin/
COPY ./engine.yaml /home/adadmin/bin

USER adadmin
WORKDIR /home/adadmin

CMD ["./bin/engine"]